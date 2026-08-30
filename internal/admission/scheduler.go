package admission

import (
	"errors"
	"sync"
)

var (
	ErrGlobalCapacityExceeded = errors.New("global scan capacity exceeded")
	ErrTargetCapacityExceeded = errors.New("target scan capacity exceeded")
)

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
		return nil, ErrGlobalCapacityExceeded
	}
	if target != "" && s.targetUsed[target]+weight > s.targetCapacity {
		return nil, ErrTargetCapacityExceeded
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
