package admission

import "fmt"

type Limiter struct {
	sem chan struct{}
}

func NewLimiter(capacity int) *Limiter {
	return &Limiter{sem: make(chan struct{}, capacity)}
}

func (l *Limiter) TryAcquire() bool {
	if l == nil {
		return true
	}
	select {
	case l.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *Limiter) Release() {
	if l == nil {
		return
	}
	select {
	case <-l.sem:
	default:
		panic(fmt.Sprintf("execution limiter release invariant violated: no slot to release (capacity=%d)", cap(l.sem)))
	}
}
