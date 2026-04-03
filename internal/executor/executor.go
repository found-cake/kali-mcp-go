package executor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const DefaultTimeout = 180 * time.Second

type Result struct {
	Stdout     string
	Stderr     string
	ReturnCode int
	TimedOut   bool
}

func (r *Result) Success() bool {
	if r.TimedOut {
		return r.Stdout != "" || r.Stderr != ""
	}
	return r.ReturnCode == 0
}

type Line struct {
	Stream string
	Text   string
}

func Run(ctx context.Context, timeout time.Duration, args []string) *Result {
	return execute(ctx, timeout, args, nil)
}

func Stream(ctx context.Context, timeout time.Duration, args []string) (<-chan Line, <-chan *Result) {
	lines := make(chan Line, 256)
	done := make(chan *Result, 1)

	go func() {
		result := execute(ctx, timeout, args, func(execCtx context.Context, line Line) bool {
			select {
			case lines <- line:
				return true
			case <-execCtx.Done():
				return false
			}
		})
		close(lines)
		done <- result
		close(done)
	}()

	return lines, done
}

func execute(ctx context.Context, timeout time.Duration, args []string, emit func(context.Context, Line) bool) *Result {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := buildCmd(ctx, args)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return &Result{Stderr: fmt.Sprintf("stdout pipe: %v", err), ReturnCode: -1}
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return &Result{Stderr: fmt.Sprintf("stderr pipe: %v", err), ReturnCode: -1}
	}

	if err := cmd.Start(); err != nil {
		return &Result{Stderr: fmt.Sprintf("start: %v", err), ReturnCode: -1}
	}

	cancelPipeClose := closePipesOnCancel(ctx, stdoutPipe, stderrPipe)
	defer close(cancelPipeClose)

	var (
		stdout, stderr strings.Builder
		wg             sync.WaitGroup
		scanErrCh      = make(chan error, 2)
	)

	collect := func(r io.Reader, stream string, buf *strings.Builder) {
		defer wg.Done()
		sc := newScanner(r)
		for sc.Scan() {
			text := sc.Text()
			buf.WriteString(text)
			buf.WriteByte('\n')
			if emit != nil && !emit(ctx, Line{Stream: stream, Text: text}) {
				return
			}
		}
		if err := sc.Err(); err != nil {
			scanErrCh <- fmt.Errorf("%s scan: %w", stream, err)
		}
	}

	wg.Add(2)
	go collect(stdoutPipe, "stdout", &stdout)
	go collect(stderrPipe, "stderr", &stderr)
	wg.Wait()
	close(scanErrCh)

	_ = cmd.Wait()
	timedOut := ctx.Err() == context.DeadlineExceeded

	rc := 0
	if cmd.ProcessState != nil {
		rc = cmd.ProcessState.ExitCode()
	}
	if timedOut {
		rc = -1
	}

	scanFailed := false
	for scanErr := range scanErrCh {
		scanFailed = true
		if stderr.Len() > 0 {
			stderr.WriteByte('\n')
		}
		stderr.WriteString(scanErr.Error())
	}
	if scanFailed && rc == 0 {
		rc = -1
	}

	return &Result{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		ReturnCode: rc,
		TimedOut:   timedOut,
	}
}

func buildCmd(ctx context.Context, args []string) *exec.Cmd {
	if len(args) == 1 {
		return exec.CommandContext(ctx, "bash", "-c", args[0])
	}
	return exec.CommandContext(ctx, args[0], args[1:]...)
}

func newScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	return sc
}

func closePipesOnCancel(ctx context.Context, pipes ...io.ReadCloser) chan struct{} {
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			for _, p := range pipes {
				_ = p.Close()
			}
		case <-stop:
		}
	}()
	return stop
}

func Which(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func WriteTemp(prefix, content string) (string, error) {
	f, err := os.CreateTemp("", prefix+"_*.rc")
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return f.Name(), err
}
