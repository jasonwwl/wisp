package server

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// PortAllocator hands out free TCP ports from an inclusive range.
// It is the in-memory authority for what's currently leased — it does
// not itself bind any sockets. The caller is responsible for actually
// listening on the port returned by Acquire, and for calling Release
// once the listener is torn down.
type PortAllocator struct {
	lo, hi int

	mu   sync.Mutex
	used map[int]struct{}
}

// ErrExhausted is returned by Acquire when no port in the range is free.
var ErrExhausted = errors.New("portalloc: range exhausted")

// NewPortAllocator parses a range spec ("lo-hi" inclusive) and returns
// an allocator. Both endpoints are required; "0-0" is rejected — use
// a real range like "22000-22099".
func NewPortAllocator(spec string) (*PortAllocator, error) {
	dash := strings.IndexByte(spec, '-')
	if dash < 1 || dash == len(spec)-1 {
		return nil, fmt.Errorf("portalloc: bad spec %q (want lo-hi)", spec)
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

// Acquire returns the lowest free port in the range, marking it as used.
func (p *PortAllocator) Acquire() (int, error) {
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
// that was never acquired is a no-op.
func (p *PortAllocator) Release(port int) {
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
