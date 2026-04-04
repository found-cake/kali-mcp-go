package executor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

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

type commandSpec struct {
	name string
	args []string
}

func RunExec(ctx context.Context, timeout time.Duration, name string, args ...string) *Result {
	return execute(ctx, timeout, commandSpec{name: name, args: args}, nil)
}

func RunShell(ctx context.Context, timeout time.Duration, command string) *Result {
	return execute(ctx, timeout, commandSpec{name: "bash", args: []string{"-c", command}}, nil)
}

func StreamShell(ctx context.Context, timeout time.Duration, command string) (<-chan Line, <-chan *Result) {
	lines := make(chan Line, 256)
	done := make(chan *Result, 1)

	go func() {
		result := execute(ctx, timeout, commandSpec{name: "bash", args: []string{"-c", command}}, func(execCtx context.Context, line Line) bool {
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

func execute(ctx context.Context, timeout time.Duration, cmdSpec commandSpec, emit func(context.Context, Line) bool) *Result {
	if timeout <= 0 {
		timeout = dto.DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdSpec.name, cmdSpec.args...)

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

	waitErr := cmd.Wait()
	timedOut := ctx.Err() == context.DeadlineExceeded

	rc := 0
	if cmd.ProcessState != nil {
		rc = cmd.ProcessState.ExitCode()
	}
	if timedOut {
		rc = -1
	}
	if waitErr != nil && !timedOut {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			if stderr.Len() > 0 {
				stderr.WriteByte('\n')
			}
			fmt.Fprintf(&stderr, "wait: %v", waitErr)
			if rc == 0 {
				rc = -1
			}
		}
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
	name := f.Name()
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}
