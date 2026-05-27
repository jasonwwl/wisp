package server

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

// regAndAlloc returns a fresh registry over a tiny fixed-range allocator,
// the allocator itself (so tests can acquire ports the way the real
// handler does), and a short resume window for fast tests.
func regAndAlloc(t *testing.T, resumeWindow time.Duration) (*sessionRegistry, *PortAllocator) {
	t.Helper()
	alloc, err := NewPortAllocator("22000-22003")
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	r := newSessionRegistry(alloc, resumeWindow, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return r, alloc
}

// freshAcquire emulates what the handler does: take a port from the
// allocator and hand it to the registry. Fails the test on exhaustion.
func freshAcquire(t *testing.T, r *sessionRegistry, alloc *PortAllocator, id [32]byte, ttl time.Duration) *sessionEntry {
	t.Helper()
	port, err := alloc.Acquire()
	if err != nil {
		t.Fatalf("alloc.Acquire: %v", err)
	}
	e, err := r.BindFresh(id, port, ttl)
	if err != nil {
		alloc.Release(port)
		t.Fatalf("BindFresh: %v", err)
	}
	return e
}

func idN(n byte) [32]byte {
	var id [32]byte
	id[0] = n
	return id
}

func TestRegistry_BindFresh_RecordsPort(t *testing.T) {
	r, alloc := regAndAlloc(t, time.Minute)
	defer r.Close()

	e := freshAcquire(t, r, alloc, idN(1), time.Hour)
	if e.Port() != 22000 {
		t.Errorf("port: got %d, want 22000", e.Port())
	}
	if !alloc.InUse(22000) {
		t.Error("allocator should hold port 22000")
	}
}

func TestRegistry_BindFresh_DuplicateID_Rejects(t *testing.T) {
	r, alloc := regAndAlloc(t, time.Minute)
	defer r.Close()

	freshAcquire(t, r, alloc, idN(1), time.Hour)

	// Caller-acquired port for the collision attempt.
	port2, _ := alloc.Acquire()
	defer alloc.Release(port2)
	_, err := r.BindFresh(idN(1), port2, time.Hour)
	if !errors.Is(err, ErrSessionInUse) {
		t.Errorf("got %v, want ErrSessionInUse", err)
	}
}

func TestRegistry_Unbind_HoldsPortAcrossWindow(t *testing.T) {
	r, alloc := regAndAlloc(t, time.Minute)
	defer r.Close()

	e := freshAcquire(t, r, alloc, idN(1), time.Hour)
	port := e.Port()

	r.Unbind(idN(1))
	if !alloc.InUse(port) {
		t.Error("port should still be held during resume window")
	}
}

func TestRegistry_Unbind_Idempotent_AndUnknownIDs(t *testing.T) {
	r, alloc := regAndAlloc(t, time.Minute)
	defer r.Close()

	// Unknown id: no-op, no panic.
	r.Unbind(idN(7))

	freshAcquire(t, r, alloc, idN(1), time.Hour)
	r.Unbind(idN(1))
	r.Unbind(idN(1)) // second call is a no-op
}

func TestRegistry_BindResume_HappyPath(t *testing.T) {
	r, alloc := regAndAlloc(t, time.Minute)
	defer r.Close()

	e1 := freshAcquire(t, r, alloc, idN(1), time.Hour)
	port := e1.Port()

	r.Unbind(idN(1))

	e2, err := r.BindResume(idN(1))
	if err != nil {
		t.Fatalf("BindResume: %v", err)
	}
	if e2.Port() != port {
		t.Errorf("port changed: %d -> %d", port, e2.Port())
	}
	if !e2.TTLDeadline().Equal(e1.TTLDeadline()) {
		t.Errorf("ttl deadline changed by resume")
	}
}

func TestRegistry_BindResume_StillBound_Rejects(t *testing.T) {
	r, alloc := regAndAlloc(t, time.Minute)
	defer r.Close()

	freshAcquire(t, r, alloc, idN(1), time.Hour)
	// No Unbind; entry is still bound.
	_, err := r.BindResume(idN(1))
	if !errors.Is(err, ErrResumeNotFound) {
		t.Errorf("got %v, want ErrResumeNotFound", err)
	}
}

func TestRegistry_BindResume_Unknown_Rejects(t *testing.T) {
	r, _ := regAndAlloc(t, time.Minute)
	defer r.Close()

	_, err := r.BindResume(idN(42))
	if !errors.Is(err, ErrResumeNotFound) {
		t.Errorf("got %v, want ErrResumeNotFound", err)
	}
}

func TestRegistry_BindResume_TTLExpired_Rejects(t *testing.T) {
	r, alloc := regAndAlloc(t, time.Minute)
	defer r.Close()

	freshAcquire(t, r, alloc, idN(1), 10*time.Millisecond)
	r.Unbind(idN(1))
	time.Sleep(25 * time.Millisecond)

	_, err := r.BindResume(idN(1))
	if !errors.Is(err, ErrResumeNotFound) {
		t.Errorf("got %v, want ErrResumeNotFound", err)
	}
}

func TestRegistry_BindResume_WindowExpired_Rejects(t *testing.T) {
	r, alloc := regAndAlloc(t, 10*time.Millisecond)
	defer r.Close()

	freshAcquire(t, r, alloc, idN(1), time.Hour)
	r.Unbind(idN(1))
	time.Sleep(25 * time.Millisecond)

	_, err := r.BindResume(idN(1))
	if !errors.Is(err, ErrResumeNotFound) {
		t.Errorf("got %v, want ErrResumeNotFound", err)
	}
}

func TestRegistry_Unbind_ClampsToTTLDeadline(t *testing.T) {
	// Resume window is generous, but TTL deadline is sooner.
	r, alloc := regAndAlloc(t, time.Hour)
	defer r.Close()

	e := freshAcquire(t, r, alloc, idN(1), 50*time.Millisecond)
	r.Unbind(idN(1))

	r.mu.Lock()
	got := e.resumeUntil
	ttl := e.ttlDeadline
	r.mu.Unlock()
	if !got.Equal(ttl) {
		t.Errorf("resumeUntil should clamp to ttlDeadline; got %v, ttl %v", got, ttl)
	}
}

func TestRegistry_Evict_ReleasesPort(t *testing.T) {
	r, alloc := regAndAlloc(t, time.Minute)
	defer r.Close()

	e := freshAcquire(t, r, alloc, idN(1), time.Hour)
	port := e.Port()

	r.Evict(idN(1))
	if alloc.InUse(port) {
		t.Error("port should be released after Evict")
	}
	if r.Count() != 0 {
		t.Errorf("entries: got %d, want 0", r.Count())
	}
}

func TestRegistry_SweepNow_EvictsResumeWindowExpired(t *testing.T) {
	r, alloc := regAndAlloc(t, 10*time.Millisecond)
	defer r.Close()

	e := freshAcquire(t, r, alloc, idN(1), time.Hour)
	port := e.Port()
	r.Unbind(idN(1))

	r.SweepNow(time.Now().Add(time.Hour))
	if alloc.InUse(port) {
		t.Error("sweep should release port for window-expired entry")
	}
}

func TestRegistry_SweepNow_EvictsTTLExpiredEvenIfBound(t *testing.T) {
	// TTL is authoritative: if a handler crashed without Unbind-ing,
	// the sweeper still has to release the port eventually.
	r, alloc := regAndAlloc(t, time.Hour)
	defer r.Close()

	e := freshAcquire(t, r, alloc, idN(1), 10*time.Millisecond)
	port := e.Port()

	r.SweepNow(time.Now().Add(time.Second))
	if alloc.InUse(port) {
		t.Error("sweep should release port for TTL-expired bound entry")
	}
}

func TestRegistry_Close_StopsSweeperAndEvicts(t *testing.T) {
	r, alloc := regAndAlloc(t, time.Minute)

	e := freshAcquire(t, r, alloc, idN(1), time.Hour)
	port := e.Port()

	r.Close()
	if alloc.InUse(port) {
		t.Error("Close should release all ports")
	}
	// Double-Close must be safe.
	r.Close()
}
