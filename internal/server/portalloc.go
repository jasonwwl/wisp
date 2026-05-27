package server

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// PortAllocator hands out free TCP ports. In "fixed-range" mode it
// picks the lowest free port from an inclusive range; in "ephemeral"
// mode (spec "0" or "auto") it always returns 0 and lets the OS pick
// a free port at bind time.
//
// It is the in-memory authority for what's currently leased — it does
// not itself bind any sockets. The caller is responsible for actually
// listening on the port returned by Acquire, and for calling Release
// once the listener is torn down.
type PortAllocator struct {
	lo, hi    int
	ephemeral bool

	mu   sync.Mutex
	used map[int]struct{}
}

// ErrExhausted is returned by Acquire when no port in the range is free.
var ErrExhausted = errors.New("portalloc: range exhausted")

// NewPortAllocator parses a range spec and returns an allocator.
//
// Accepted forms:
//   - "lo-hi"          fixed inclusive range, e.g. "22000-22099"
//   - "0" or "auto"    ephemeral mode: every Acquire returns 0, and
//     the caller is expected to bind to ":0" so the
//     kernel picks a free port. Useful for tests and
//     for deployments that don't care about port
//     determinism.
func NewPortAllocator(spec string) (*PortAllocator, error) {
	if spec == "0" || spec == "auto" {
		return &PortAllocator{ephemeral: true, used: make(map[int]struct{})}, nil
	}
	dash := strings.IndexByte(spec, '-')
	if dash < 1 || dash == len(spec)-1 {
		return nil, fmt.Errorf("portalloc: bad spec %q (want lo-hi, \"0\", or \"auto\")", spec)
	}
	lo, err := strconv.Atoi(strings.TrimSpace(spec[:dash]))
	if err != nil {
		return nil, fmt.Errorf("portalloc: bad lo: %w", err)
	}
	hi, err := strconv.Atoi(strings.TrimSpace(spec[dash+1:]))
	if err != nil {
		return nil, fmt.Errorf("portalloc: bad hi: %w", err)
	}
	if lo < 1 || hi < 1 || lo > 65535 || hi > 65535 {
		return nil, fmt.Errorf("portalloc: out of range 1-65535: %d-%d", lo, hi)
	}
	if lo > hi {
		return nil, fmt.Errorf("portalloc: lo > hi: %d > %d", lo, hi)
	}
	return &PortAllocator{lo: lo, hi: hi, used: make(map[int]struct{})}, nil
}

// Ephemeral reports whether this allocator delegates port choice to
// the OS (spec was "0" or "auto").
func (p *PortAllocator) Ephemeral() bool { return p.ephemeral }

// Acquire returns the lowest free port in the range, marking it as
// used. In ephemeral mode it returns 0 unconditionally.
func (p *PortAllocator) Acquire() (int, error) {
	if p.ephemeral {
		return 0, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for port := p.lo; port <= p.hi; port++ {
		if _, taken := p.used[port]; !taken {
			p.used[port] = struct{}{}
			return port, nil
		}
	}
	return 0, ErrExhausted
}

// Release marks a previously-acquired port as free. Releasing a port
// that was never acquired (or in ephemeral mode) is a no-op.
func (p *PortAllocator) Release(port int) {
	if p.ephemeral {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, port)
}

// InUse reports whether port is currently held. Useful for tests.
func (p *PortAllocator) InUse(port int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.used[port]
	return ok
}

// Range returns the inclusive bounds.
func (p *PortAllocator) Range() (lo, hi int) { return p.lo, p.hi }
