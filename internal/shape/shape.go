// Package shape implements wisp's traffic-shaping primitives: random
// per-frame padding (delegated to the frame package, always on), burst
// smoothing (opt-in), and chaff emission during idle periods (opt-in).
//
// See docs/design.md §7.
//
// The Shaper sits between yamux and the wsraw write side: the mux
// adapter's Write feeds bytes into Shaper.Write, which decides whether
// to forward immediately as a Yamux-typed wisp frame, coalesce within
// a short window, or — if chaff is enabled — also emit low-rate Ping-
// typed dummy frames during silent periods.
package shape

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"sync"
	"time"
)

// Default knobs. Sourced from docs/design.md §7.
const (
	DefaultBurstWindow     = 10 * time.Millisecond
	DefaultChaffInterval   = 1 * time.Second
	DefaultChaffSilenceMin = 250 * time.Millisecond
)

// Mode is the user-facing shaping selection. Both bits are independently
// opt-in; both off is the v0.1 pass-through behaviour.
type Mode struct {
	Burst bool
	Chaff bool
}

// Empty reports whether no shaping is requested. Callers can skip the
// shaper entirely in that case.
func (m Mode) Empty() bool { return !m.Burst && !m.Chaff }

// Config tunes a Shaper. Zero values fill in from package defaults.
type Config struct {
	Mode            Mode
	BurstWindow     time.Duration
	ChaffInterval   time.Duration
	ChaffSilenceMin time.Duration
	// MaxPayload is the upper bound on a single SendData payload. The
	// shaper flushes the burst buffer early when the next Write would
	// otherwise overflow.
	MaxPayload int
}

// Sender is the side-effect interface the shaper drives. mux.Adapter
// implements it: SendData emits a TypeYamux wisp frame, SendChaff a
// TypePing one. Both must be safe for concurrent use.
type Sender interface {
	SendData(p []byte) error
	SendChaff(p []byte) error
}

// ErrClosed is returned by Write after Close.
var ErrClosed = errors.New("shape: closed")

// Shaper wraps a Sender with traffic shaping. New returns a started
// Shaper; Close stops it and flushes pending data.
//
// Lock discipline: Sender calls happen with s.mu released. The buffer,
// timer, lastWrite, and closed fields are mu-protected. The chaff loop
// briefly takes mu to read state, then drops it before calling Sender.
type Shaper struct {
	cfg    Config
	sender Sender

	mu        sync.Mutex
	buffer    bytes.Buffer
	timer     *time.Timer
	closed    bool
	lastWrite time.Time

	chaffStop chan struct{}
	chaffDone chan struct{}
}

// New returns a Shaper ready to receive Writes. When cfg.Mode.Chaff is
// true a goroutine is started that emits chaff during idle periods;
// Close must be called to stop it.
func New(cfg Config, sender Sender) *Shaper {
	if cfg.BurstWindow <= 0 {
		cfg.BurstWindow = DefaultBurstWindow
	}
	if cfg.ChaffInterval <= 0 {
		cfg.ChaffInterval = DefaultChaffInterval
	}
	if cfg.ChaffSilenceMin <= 0 {
		cfg.ChaffSilenceMin = DefaultChaffSilenceMin
	}
	if cfg.MaxPayload <= 0 {
		cfg.MaxPayload = 1 << 16 // mirrors frame.MaxPayload
	}
	s := &Shaper{cfg: cfg, sender: sender}
	if cfg.Mode.Chaff {
		s.chaffStop = make(chan struct{})
		s.chaffDone = make(chan struct{})
		go s.chaffLoop()
	}
	return s
}

// Write enqueues p for emission. When burst is off, p is sent right
// away as one data frame. When burst is on, p is buffered and emitted
// at the next flush — burst window expiry, MaxPayload near-fill, or
// explicit Flush/Close.
func (s *Shaper) Write(p []byte) error {
	if !s.cfg.Mode.Burst {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return ErrClosed
		}
		s.lastWrite = time.Now()
		s.mu.Unlock()
		return s.sender.SendData(p)
	}

	var pendingFlush []byte
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if s.buffer.Len() > 0 && s.buffer.Len()+len(p) > s.cfg.MaxPayload {
		pendingFlush = s.takeBufferLocked()
	}
	s.buffer.Write(p)
	s.lastWrite = time.Now()
	if s.timer == nil {
		s.timer = time.AfterFunc(s.cfg.BurstWindow, s.timerFlush)
	}
	s.mu.Unlock()

	if pendingFlush != nil {
		if err := s.sender.SendData(pendingFlush); err != nil {
			return err
		}
	}
	return nil
}

// Flush forces any buffered data out now.
func (s *Shaper) Flush() error {
	s.mu.Lock()
	out := s.takeBufferLocked()
	s.mu.Unlock()
	if out == nil {
		return nil
	}
	return s.sender.SendData(out)
}

// Close stops chaff (if running), drains the burst buffer, and prevents
// further writes. Safe to call multiple times.
func (s *Shaper) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	out := s.takeBufferLocked()
	s.mu.Unlock()

	if s.chaffStop != nil {
		close(s.chaffStop)
		<-s.chaffDone
	}
	if out != nil {
		_ = s.sender.SendData(out)
	}
	return nil
}

// takeBufferLocked drains the buffer and stops the burst timer. Caller
// must hold s.mu. Returns nil if the buffer is empty.
func (s *Shaper) takeBufferLocked() []byte {
	if s.buffer.Len() == 0 {
		return nil
	}
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	out := make([]byte, s.buffer.Len())
	copy(out, s.buffer.Bytes())
	s.buffer.Reset()
	return out
}

func (s *Shaper) timerFlush() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	out := s.takeBufferLocked()
	s.mu.Unlock()
	if out != nil {
		_ = s.sender.SendData(out)
	}
}

func (s *Shaper) chaffLoop() {
	defer close(s.chaffDone)
	for {
		wait := s.nextChaffDelay()
		select {
		case <-s.chaffStop:
			return
		case <-time.After(wait):
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		skip := time.Since(s.lastWrite) < s.cfg.ChaffSilenceMin
		s.mu.Unlock()
		if skip {
			continue
		}
		var payload [8]byte
		binary.BigEndian.PutUint64(payload[:], uint64(time.Now().UnixNano()))
		_ = s.sender.SendChaff(payload[:])
	}
}

// nextChaffDelay returns a uniform random delay in
// [ChaffInterval/2, ChaffInterval*3/2).
func (s *Shaper) nextChaffDelay() time.Duration {
	base := s.cfg.ChaffInterval
	half := int64(base / 2)
	if half <= 0 {
		return base
	}
	j := rand.Int64N(2*half) - half
	return base + time.Duration(j)
}
