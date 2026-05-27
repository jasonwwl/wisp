package server

import (
	"errors"
	"testing"
)

func TestPortAllocator_AcquireRelease(t *testing.T) {
	a, err := NewPortAllocator("22000-22002")
	if err != nil {
		t.Fatal(err)
	}
	p1, _ := a.Acquire()
	p2, _ := a.Acquire()
	p3, _ := a.Acquire()
	if p1 != 22000 || p2 != 22001 || p3 != 22002 {
		t.Errorf("got %d,%d,%d want 22000,22001,22002", p1, p2, p3)
	}
	_, err = a.Acquire()
	if !errors.Is(err, ErrExhausted) {
		t.Errorf("got %v, want ErrExhausted", err)
	}
	a.Release(22001)
	p4, _ := a.Acquire()
	if p4 != 22001 {
		t.Errorf("post-release acquire: got %d, want 22001 (lowest free)", p4)
	}
}

func TestPortAllocator_BadSpec(t *testing.T) {
	cases := []string{"", "22000", "-22000", "22000-", "abc-22000", "22000-abc", "22001-22000", "0-100", "70000-70100"}
	for _, c := range cases {
		if _, err := NewPortAllocator(c); err == nil {
			t.Errorf("spec %q should fail", c)
		}
	}
}

func TestPortAllocator_SingleEntry(t *testing.T) {
	a, err := NewPortAllocator("9999-9999")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := a.Acquire()
	if p != 9999 {
		t.Errorf("got %d, want 9999", p)
	}
}

func TestPortAllocator_ReleaseUnknown(t *testing.T) {
	a, _ := NewPortAllocator("100-200")
	a.Release(150) // should not panic
	if a.InUse(150) {
		t.Error("InUse should be false after Release(150)")
	}
}

func TestPortAllocator_Ephemeral(t *testing.T) {
	for _, spec := range []string{"0", "auto"} {
		a, err := NewPortAllocator(spec)
		if err != nil {
			t.Fatalf("spec %q: %v", spec, err)
		}
		if !a.Ephemeral() {
			t.Errorf("spec %q: Ephemeral() = false, want true", spec)
		}
		for i := 0; i < 3; i++ {
			p, err := a.Acquire()
			if err != nil {
				t.Errorf("spec %q Acquire #%d: %v", spec, i, err)
			}
			if p != 0 {
				t.Errorf("spec %q Acquire #%d: got %d, want 0 (OS-picks)", spec, i, p)
			}
		}
		a.Release(0) // no-op, must not panic
	}
}
