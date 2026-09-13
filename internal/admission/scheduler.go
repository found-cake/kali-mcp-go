package admission

import (
	"errors"
	"sync"
)

var (
	ErrGlobalCapacityExceeded = errors.New("global scan capacity exceeded")
	ErrTargetCapacityExceeded = errors.New("target scan capacity exceeded")
)

type CapacityScope string

const (
	CapacityScopeGlobal CapacityScope = "global"
	CapacityScopeTarget CapacityScope = "target"
)

type CapacityError struct {
	scope           CapacityScope
	used            int
	limit           int
	requestedWeight int
}

func (e *CapacityError) Error() string {
	return e.Unwrap().Error()
}

func (e *CapacityError) Unwrap() error {
	switch e.scope {
	case CapacityScopeGlobal:
		return ErrGlobalCapacityExceeded
	case CapacityScopeTarget:
		return ErrTargetCapacityExceeded
	default:
		return errors.New("scan capacity exceeded")
	}
}

func (e *CapacityError) Scope() CapacityScope { return e.scope }

func (e *CapacityError) Used() int { return e.used }

func (e *CapacityError) Limit() int { return e.limit }

func (e *CapacityError) RequestedWeight() int { return e.requestedWeight }

type Scheduler struct {
	mu             sync.Mutex
	globalCapacity int
	targetCapacity int
	globalUsed     int
	targetUsed     map[string]int
}

func NewScheduler(globalCapacity, targetCapacity int) *Scheduler {
	return &Scheduler{
		globalCapacity: globalCapacity,
		targetCapacity: targetCapacity,
		targetUsed:     make(map[string]int),
	}
}

func (s *Scheduler) Acquire(target string, weight int) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.globalUsed+weight > s.globalCapacity {
		return nil, &CapacityError{
			scope: CapacityScopeGlobal, used: s.globalUsed, limit: s.globalCapacity, requestedWeight: weight,
		}
	}
	if target != "" && s.targetUsed[target]+weight > s.targetCapacity {
		return nil, &CapacityError{
			scope: CapacityScopeTarget, used: s.targetUsed[target], limit: s.targetCapacity, requestedWeight: weight,
		}
	}
	s.globalUsed += weight
	if target != "" {
		s.targetUsed[target] += weight
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.globalUsed -= weight
			if target != "" {
				s.targetUsed[target] -= weight
				if s.targetUsed[target] == 0 {
					delete(s.targetUsed, target)
				}
			}
		})
	}, nil
}
