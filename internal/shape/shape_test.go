package shape

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeSender records every SendData / SendChaff call for assertion.
type fakeSender struct {
	mu    sync.Mutex
	data  [][]byte
	chaff [][]byte
}

func (f *fakeSender) SendData(p []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	f.data = append(f.data, cp)
	return nil
}

func (f *fakeSender) SendChaff(p []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	f.chaff = append(f.chaff, cp)
	return nil
}

func (f *fakeSender) dataCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.data)
}

func (f *fakeSender) chaffCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.chaff)
}

func (f *fakeSender) lastData() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.data) == 0 {
		return nil
	}
	return f.data[len(f.data)-1]
}

// TestShape_PassthroughByDefault: with no shape mode enabled, every
// Write turns into one immediate SendData of the same bytes.
func TestShape_PassthroughByDefault(t *testing.T) {
	f := &fakeSender{}
	s := New(Config{}, f)
	defer s.Close()

	for i := range 3 {
		if err := s.Write([]byte("abc")); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if got := f.dataCount(); got != 3 {
		t.Errorf("dataCount: got %d, want 3", got)
	}
	if got := f.chaffCount(); got != 0 {
		t.Errorf("chaffCount: got %d, want 0", got)
	}
}

// TestBurst_CoalescesWithinWindow: with burst on, three quick Writes
// fold into a single SendData carrying the concatenation.
func TestBurst_CoalescesWithinWindow(t *testing.T) {
	f := &fakeSender{}
	s := New(Config{
		Mode:        Mode{Burst: true},
		BurstWindow: 30 * time.Millisecond,
	}, f)
	defer s.Close()

	for _, p := range [][]byte{[]byte("aa"), []byte("bb"), []byte("cc")} {
		if err := s.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	// Buffer should still be in flight; nothing emitted yet.
	if got := f.dataCount(); got != 0 {
		t.Errorf("before window expiry: got %d sends, want 0", got)
	}
	// Wait past the window for the timer to fire.
	time.Sleep(80 * time.Millisecond)

	if got := f.dataCount(); got != 1 {
		t.Fatalf("after window: got %d sends, want 1", got)
	}
	if want := []byte("aabbcc"); !bytes.Equal(f.lastData(), want) {
		t.Errorf("payload: got %q, want %q", f.lastData(), want)
	}
}

// TestBurst_FlushesOnMaxPayload: when the next Write would push the
// buffer past MaxPayload, the current buffer is flushed first.
func TestBurst_FlushesOnMaxPayload(t *testing.T) {
	f := &fakeSender{}
	s := New(Config{
		Mode:        Mode{Burst: true},
		BurstWindow: 5 * time.Second, // long, so only size triggers flush
		MaxPayload:  100,
	}, f)
	defer s.Close()

	if err := s.Write(bytes.Repeat([]byte("a"), 80)); err != nil {
		t.Fatal(err)
	}
	if got := f.dataCount(); got != 0 {
		t.Errorf("80-byte write should buffer; got %d sends", got)
	}
	// 30 more would put us at 110 > 100: flush first 80, buffer 30.
	if err := s.Write(bytes.Repeat([]byte("b"), 30)); err != nil {
		t.Fatal(err)
	}
	if got := f.dataCount(); got != 1 {
		t.Fatalf("after overflow write: got %d sends, want 1", got)
	}
	if got := len(f.lastData()); got != 80 {
		t.Errorf("first send len: got %d, want 80", got)
	}
	// Closing flushes the leftover 30 bytes.
	_ = s.Close()
	if got := f.dataCount(); got != 2 {
		t.Fatalf("after close: got %d sends, want 2", got)
	}
	if got := len(f.lastData()); got != 30 {
		t.Errorf("second send len: got %d, want 30", got)
	}
}

// TestBurst_FlushOnClose: explicit Close drains the buffer.
func TestBurst_FlushOnClose(t *testing.T) {
	f := &fakeSender{}
	s := New(Config{
		Mode:        Mode{Burst: true},
		BurstWindow: 5 * time.Second,
	}, f)

	if err := s.Write([]byte("pending")); err != nil {
		t.Fatal(err)
	}
	if got := f.dataCount(); got != 0 {
		t.Errorf("before close: got %d sends, want 0", got)
	}
	_ = s.Close()
	if got := f.dataCount(); got != 1 {
		t.Errorf("after close: got %d sends, want 1", got)
	}
}

// TestShape_WriteAfterCloseReturnsErr asserts the API contract.
func TestShape_WriteAfterCloseReturnsErr(t *testing.T) {
	f := &fakeSender{}
	s := New(Config{Mode: Mode{Burst: true}}, f)
	_ = s.Close()

	if err := s.Write([]byte("late")); !errors.Is(err, ErrClosed) {
		t.Errorf("Write after Close: got %v, want ErrClosed", err)
	}
}

// TestChaff_EmitsDuringIdle: with chaff on and no real writes, the
// loop fires several times.
func TestChaff_EmitsDuringIdle(t *testing.T) {
	f := &fakeSender{}
	s := New(Config{
		Mode:            Mode{Chaff: true},
		ChaffInterval:   30 * time.Millisecond,
		ChaffSilenceMin: 1 * time.Millisecond, // basically always allow
	}, f)
	defer s.Close()

	time.Sleep(200 * time.Millisecond)

	if got := f.chaffCount(); got < 2 {
		t.Errorf("chaffCount: got %d, want >= 2 (idle 200ms / mean 30ms)", got)
	}
}

// TestChaff_SuppressedDuringTraffic: when real writes are continuous,
// the chaff loop sees lastWrite recent and skips its tick.
func TestChaff_SuppressedDuringTraffic(t *testing.T) {
	f := &fakeSender{}
	s := New(Config{
		Mode:            Mode{Chaff: true},
		ChaffInterval:   30 * time.Millisecond,
		ChaffSilenceMin: 200 * time.Millisecond, // wide silence window
	}, f)
	defer s.Close()

	// Hammer Write for 200ms.
	stop := time.After(200 * time.Millisecond)
	tick := time.NewTicker(15 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			goto done
		case <-tick.C:
			_ = s.Write([]byte("traffic"))
		}
	}
done:
	// Allow loop a chance to fire once more after our last write.
	time.Sleep(20 * time.Millisecond)

	if got := f.chaffCount(); got > 0 {
		t.Errorf("chaffCount: got %d, want 0 — chaff should be suppressed during active traffic", got)
	}
}

// TestChaff_StoppedOnClose: no chaff emitted after Close returns.
func TestChaff_StoppedOnClose(t *testing.T) {
	f := &fakeSender{}
	s := New(Config{
		Mode:            Mode{Chaff: true},
		ChaffInterval:   10 * time.Millisecond,
		ChaffSilenceMin: 1 * time.Millisecond,
	}, f)
	time.Sleep(50 * time.Millisecond)
	_ = s.Close()
	beforeSleep := f.chaffCount()

	time.Sleep(80 * time.Millisecond)
	if got := f.chaffCount(); got != beforeSleep {
		t.Errorf("chaff after Close: %d -> %d", beforeSleep, got)
	}
}

// TestShape_DoubleClose is safe.
func TestShape_DoubleClose(t *testing.T) {
	f := &fakeSender{}
	s := New(Config{Mode: Mode{Burst: true, Chaff: true}, ChaffInterval: 10 * time.Millisecond}, f)
	_ = s.Close()
	_ = s.Close()
}

// TestMode_Empty checks the helper.
func TestMode_Empty(t *testing.T) {
	if !(Mode{}).Empty() {
		t.Error("zero Mode should be empty")
	}
	if (Mode{Burst: true}).Empty() {
		t.Error("Burst Mode should not be empty")
	}
	if (Mode{Chaff: true}).Empty() {
		t.Error("Chaff Mode should not be empty")
	}
}
