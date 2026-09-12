package admission

import "testing"

func TestLimiterRejectsBeyondCapacityAndRestoresReleasedSlot(t *testing.T) {
	// Given: a limiter with capacity one.
	limiter := NewLimiter(1)

	// When: one slot is acquired, capacity is exceeded, and the slot is released.
	first := limiter.TryAcquire()
	second := limiter.TryAcquire()
	limiter.Release()
	third := limiter.TryAcquire()

	// Then: acquisition remains fail-fast and release restores exactly one slot.
	if !first || second || !third {
		t.Fatalf("unexpected limiter sequence: first=%t second=%t third=%t", first, second, third)
	}
}

func TestLimiterPanicsOnOverRelease(t *testing.T) {
	// Given: an empty limiter.
	limiter := NewLimiter(1)

	// When: release is called without a matching acquisition.
	defer func() {
		// Then: the existing invariant panic remains observable.
		value := recover()
		if value != "execution limiter release invariant violated: no slot to release (capacity=1)" {
			t.Fatalf("unexpected panic: %v", value)
		}
	}()
	limiter.Release()
}
