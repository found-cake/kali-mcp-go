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
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := buildCmd(ctx, args)

	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return &Result{Stderr: fmt.Sprintf("start: %v", err), ReturnCode: -1}
	}

	cancelPipeClose := closePipesOnCancel(ctx, stdoutPipe, stderrPipe)
	defer close(cancelPipeClose)

	var (
		stdout, stderr strings.Builder
		wg             sync.WaitGroup
	)

	collect := func(r io.Reader, buf *strings.Builder) {
		defer wg.Done()
		sc := newScanner(r)
		for sc.Scan() {
			buf.WriteString(sc.Text())
			buf.WriteByte('\n')
		}
	}

	wg.Add(2)
	go collect(stdoutPipe, &stdout)
	go collect(stderrPipe, &stderr)
	wg.Wait()

	_ = cmd.Wait()
	timedOut := ctx.Err() == context.DeadlineExceeded

	rc := 0
	if cmd.ProcessState != nil {
		rc = cmd.ProcessState.ExitCode()
	}
	if timedOut {
		rc = -1
	}

	return &Result{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		ReturnCode: rc,
		TimedOut:   timedOut,
	}
}

func Stream(ctx context.Context, timeout time.Duration, args []string) (<-chan Line, <-chan *Result) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	lines := make(chan Line, 256)
	done := make(chan *Result, 1)

	go func() {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		cmd := buildCmd(ctx, args)
		stdoutPipe, _ := cmd.StdoutPipe()
		stderrPipe, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			close(lines)
			done <- &Result{Stderr: fmt.Sprintf("start: %v", err), ReturnCode: -1}
			close(done)
			return
		}

		cancelPipeClose := closePipesOnCancel(ctx, stdoutPipe, stderrPipe)
		defer close(cancelPipeClose)

		var (
			stdout, stderr strings.Builder
			wg             sync.WaitGroup
		)

		pipe := func(r io.Reader, stream string, buf *strings.Builder) {
			defer wg.Done()
			sc := newScanner(r)
			for sc.Scan() {
				text := sc.Text()
				buf.WriteString(text)
				buf.WriteByte('\n')
				select {
				case lines <- Line{Stream: stream, Text: text}:
				case <-ctx.Done():
					return
				}
			}
		}

		wg.Add(2)
		go pipe(stdoutPipe, "stdout", &stdout)
		go pipe(stderrPipe, "stderr", &stderr)
		wg.Wait()

		_ = cmd.Wait()
		timedOut := ctx.Err() == context.DeadlineExceeded

		rc := 0
		if cmd.ProcessState != nil {
			rc = cmd.ProcessState.ExitCode()
		}
		if timedOut {
			rc = -1
		}

		close(lines)
		done <- &Result{
			Stdout:     stdout.String(),
			Stderr:     stderr.String(),
			ReturnCode: rc,
			TimedOut:   timedOut,
		}
		close(done)
	}()

	return lines, done
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
