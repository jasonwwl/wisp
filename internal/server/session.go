package server

import (
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// ErrResumeNotFound is returned by BindResume when a session id is not
// in the registry, is TTL-expired, has fallen out of its resume window,
// or is currently bound to another handler. All four are mapped to the
// same wire-level outcome (protocol.AckResumeNotFound) so a client
// cannot distinguish them by error alone.
var ErrResumeNotFound = errors.New("session: not in resume window")

// ErrSessionInUse is returned by BindFresh when a fresh session id
// already exists in the registry. Collisions on 32 random bytes are
// astronomically unlikely; this is a paranoia check.
var ErrSessionInUse = errors.New("session: id already in registry")

// DefaultResumeWindow is design.md §5.3's "5 minutes".
const DefaultResumeWindow = 5 * time.Minute

// defaultSweepInterval is how often the sweeper scans for entries that
// have outlived either their TTL or their resume window. Sized to be
// slow relative to the resume window itself — a few minutes of slop is
// acceptable; the on-bind staleness check catches anything finer.
const defaultSweepInterval = 30 * time.Second

// sessionEntry is the per-session record. Mutable state (bound,
// resumeUntil) is protected by the owning registry's mu; port is
// accessed via atomic so handler goroutines can read it without
// taking the registry lock.
type sessionEntry struct {
	id          [32]byte
	ttlDeadline time.Time // absolute; never extended by resume

	port atomic.Int64 // 0 means "not yet known" (ephemeral mode pre-bind)

	bound       bool
	resumeUntil time.Time // valid iff !bound
}

// Port returns the entry's currently-known public TCP port (0 in
// ephemeral mode before the handler has bound).
func (e *sessionEntry) Port() int { return int(e.port.Load()) }

// ID returns the entry's session id.
func (e *sessionEntry) ID() [32]byte { return e.id }

// TTLDeadline returns the absolute wall-clock time at which this
// session's TTL elapses.
func (e *sessionEntry) TTLDeadline() time.Time { return e.ttlDeadline }

// sessionRegistry holds the live + resume-window session state. It is
// the authority over which sessions exist, which are currently bound to
// a live WS, and which are sitting in their resume window. It owns the
// lifecycle of ports lent to its entries: BindFresh acquires from the
// PortAllocator; Evict releases.
type sessionRegistry struct {
	ports        *PortAllocator
	resumeWindow time.Duration
	log          *slog.Logger

	mu      sync.Mutex
	entries map[[32]byte]*sessionEntry

	sweepStop chan struct{}
	sweepDone chan struct{}
}

// newSessionRegistry returns a registry with a running sweeper. Caller
// must Close it on shutdown.
func newSessionRegistry(ports *PortAllocator, resumeWindow time.Duration, log *slog.Logger) *sessionRegistry {
	if resumeWindow <= 0 {
		resumeWindow = DefaultResumeWindow
	}
	if log == nil {
		log = slog.Default()
	}
	r := &sessionRegistry{
		ports:        ports,
		resumeWindow: resumeWindow,
		log:          log,
		entries:      make(map[[32]byte]*sessionEntry),
		sweepStop:    make(chan struct{}),
		sweepDone:    make(chan struct{}),
	}
	go r.sweepLoop(defaultSweepInterval)
	return r
}

// BindFresh registers a brand-new session at a port the caller has
// already acquired from the PortAllocator and successfully bound to.
// The registry takes ownership of that port: subsequent Evict releases
// it back to the allocator. Returns ErrSessionInUse if id collides.
//
// Two-step Acquire+BindFresh (rather than registry-internal Acquire) is
// deliberate: it keeps the handler in charge of TIME_WAIT retries
// across adjacent ports in the fixed-range fresh path.
func (r *sessionRegistry) BindFresh(id [32]byte, port int, ttl time.Duration) (*sessionEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.entries[id]; dup {
		return nil, ErrSessionInUse
	}
	e := &sessionEntry{
		id:          id,
		ttlDeadline: time.Now().Add(ttl),
		bound:       true,
	}
	e.port.Store(int64(port))
	r.entries[id] = e
	return e, nil
}

// BindResume re-binds an entry that is currently in its resume window.
// Returns ErrResumeNotFound for any path that should look identical on
// the wire: missing id, TTL elapsed, resume window elapsed, or already
// bound to another handler.
func (r *sessionRegistry) BindResume(id [32]byte) (*sessionEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[id]
	if !ok {
		return nil, ErrResumeNotFound
	}
	now := time.Now()
	if now.After(e.ttlDeadline) || e.bound || now.After(e.resumeUntil) {
		return nil, ErrResumeNotFound
	}
	e.bound = true
	e.resumeUntil = time.Time{}
	return e, nil
}

// Unbind transitions a bound entry back to its resume window. Idempotent
// for entries already unbound, or for ids the registry no longer knows.
func (r *sessionRegistry) Unbind(id [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[id]
	if !ok || !e.bound {
		return
	}
	e.bound = false
	rd := time.Now().Add(r.resumeWindow)
	if rd.After(e.ttlDeadline) {
		rd = e.ttlDeadline
	}
	e.resumeUntil = rd
}

// Evict removes an entry and releases its port back to the allocator.
// Idempotent for unknown ids. Called by the sweeper on window/TTL
// expiry, by the handler on terminal events (BYE, TTL fire), and by
// Close on shutdown.
func (r *sessionRegistry) Evict(id [32]byte) {
	r.mu.Lock()
	e, ok := r.entries[id]
	if !ok {
		r.mu.Unlock()
		return
	}
	delete(r.entries, id)
	r.mu.Unlock()
	if p := int(e.port.Load()); p > 0 {
		r.ports.Release(p)
	}
}

// Count returns the number of live entries. Test/observability helper.
func (r *sessionRegistry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// SweepNow runs one eviction pass against the supplied wall-clock. It
// is exposed for tests; the background sweepLoop calls it on its tick.
func (r *sessionRegistry) SweepNow(now time.Time) {
	r.mu.Lock()
	var expired [][32]byte
	for id, e := range r.entries {
		switch {
		case now.After(e.ttlDeadline):
			expired = append(expired, id)
		case !e.bound && now.After(e.resumeUntil):
			expired = append(expired, id)
		}
	}
	r.mu.Unlock()
	for _, id := range expired {
		r.Evict(id)
	}
}

func (r *sessionRegistry) sweepLoop(interval time.Duration) {
	defer close(r.sweepDone)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-r.sweepStop:
			return
		case now := <-t.C:
			r.SweepNow(now)
		}
	}
}

// Close stops the sweeper and evicts every remaining entry.
func (r *sessionRegistry) Close() {
	select {
	case <-r.sweepStop:
		// already closed
	default:
		close(r.sweepStop)
	}
	<-r.sweepDone
	r.mu.Lock()
	ids := make([][32]byte, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	for _, id := range ids {
		r.Evict(id)
	}
}
