package executor

import (
	"context"
	"io"
	"time"
)

func closePipesAfterGrace(ctx context.Context, grace time.Duration, pipes ...io.ReadCloser) chan struct{} {
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			timer := time.NewTimer(grace)
			defer timer.Stop()
			select {
			case <-timer.C:
				for _, pipe := range pipes {
					_ = pipe.Close()
				}
			case <-stop:
			}
		case <-stop:
		}
	}()
	return stop
}
