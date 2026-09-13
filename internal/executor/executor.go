package executor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func RunExec(ctx context.Context, timeout time.Duration, name string, args ...string) *Result {
	return execute(ctx, timeout, commandSpec{name: name, args: args}, nil)
}

func StreamExec(ctx context.Context, timeout time.Duration, name string, args ...string) (<-chan Line, <-chan *Result) {
	return stream(ctx, timeout, commandSpec{name: name, args: args})
}

func RunShell(ctx context.Context, timeout time.Duration, command string) *Result {
	return execute(ctx, timeout, commandSpec{name: "bash", args: []string{"-c", command}}, nil)
}

func StreamShell(ctx context.Context, timeout time.Duration, command string) (<-chan Line, <-chan *Result) {
	return stream(ctx, timeout, commandSpec{name: "bash", args: []string{"-c", command}})
}

func stream(ctx context.Context, timeout time.Duration, cmdSpec commandSpec) (<-chan Line, <-chan *Result) {
	lines := make(chan Line, 256)
	done := make(chan *Result, 1)

	go func() {
		result := execute(ctx, timeout, cmdSpec, func(execCtx context.Context, line Line) bool {
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
	startedAt := time.Now().UTC()
	progress := newOutputProgress()
	tool := commandTool(cmdSpec.name, cmdSpec.args)
	result := &Result{
		ReturnCode:   -1,
		StartedAt:    startedAt,
		Tool:         tool,
		ToolVersion:  toolVersion(ctx, tool),
		ArgvRedacted: redactArgs(cmdSpec.name, cmdSpec.args),
		Timeout:      timeout,
	}
	defer func() {
		result.Duration = time.Since(startedAt)
		result.Progress = progress.snapshot()
		result.FinalizeProgress()
	}()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdSpec.name, cmdSpec.args...)
	configureCommandCancellation(cmd)
	cmd.WaitDelay = gracefulStopTimeout

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		result.Stderr = fmt.Sprintf("stdout pipe: %v", err)
		result.FailureCode = "process_setup_failed"
		return result
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_ = stdoutPipe.Close()
		result.Stderr = fmt.Sprintf("stderr pipe: %v", err)
		result.FailureCode = "process_setup_failed"
		return result
	}

	if err := cmd.Start(); err != nil {
		_ = stdoutPipe.Close()
		_ = stderrPipe.Close()
		result.Stderr = fmt.Sprintf("start: %v", err)
		if errors.Is(ctx.Err(), context.Canceled) {
			result.Cancelled = true
			result.FailureCode = "cancelled"
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			result.TimedOut = true
			result.FailureCode = "timed_out"
		} else {
			result.FailureCode = "process_start_failed"
		}
		return result
	}
	result.ProcessStarted = true
	result.GracefulStop = gracefulStopTimeout
	cancelPipeClose := closePipesAfterGrace(ctx, gracefulStopTimeout, stdoutPipe, stderrPipe)
	defer close(cancelPipeClose)

	var (
		stdout    = newOutputCapture(maximumRetainedOutputBytes)
		stderr    = newOutputCapture(maximumRetainedOutputBytes)
		wg        sync.WaitGroup
		scanErrCh = make(chan error, 2)
	)

	collect := func(r io.Reader, stream string, capture *outputCapture) {
		defer wg.Done()
		sc := newScanner(r)
		for sc.Scan() {
			raw := sc.Bytes()
			observedBytes := len(raw)
			if bytes.HasSuffix(raw, []byte{'\n'}) {
				raw = raw[:len(raw)-1]
			}
			if bytes.HasSuffix(raw, []byte{'\r'}) {
				raw = raw[:len(raw)-1]
			}
			text := string(raw)
			sequence := progress.observe(text)
			capture.WriteLine(text, observedBytes)
			if emit != nil && !emit(ctx, Line{Stream: stream, Text: text, Sequence: sequence, ObservedBytes: observedBytes}) {
				return
			}
		}
		if err := sc.Err(); err != nil && !(ctx.Err() != nil && errors.Is(err, os.ErrClosed)) {
			scanErrCh <- fmt.Errorf("%s scan: %w", stream, err)
		}
	}

	wg.Add(2)
	go collect(stdoutPipe, "stdout", stdout)
	go collect(stderrPipe, "stderr", stderr)
	wg.Wait()
	close(scanErrCh)
	waitErr := cmd.Wait()
	cleanupErr := cleanupCommandProcesses(cmd)
	timedOut := ctx.Err() == context.DeadlineExceeded
	cancelled := ctx.Err() == context.Canceled

	rc := 0
	if cmd.ProcessState != nil {
		rc = cmd.ProcessState.ExitCode()
	}
	if timedOut {
		rc = -1
		result.FailureCode = "timed_out"
	} else if cancelled {
		rc = -1
		result.FailureCode = "cancelled"
	}
	if waitErr != nil && !timedOut {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			if stderr.Len() > 0 {
				_, _ = stderr.Write([]byte{'\n'})
			}
			fmt.Fprintf(stderr, "wait: %v", waitErr)
			if rc == 0 {
				rc = -1
			}
		}
	}

	scanFailed := false
	for scanErr := range scanErrCh {
		scanFailed = true
		if stderr.Len() > 0 {
			_, _ = stderr.Write([]byte{'\n'})
		}
		_, _ = stderr.Write([]byte(scanErr.Error()))
	}
	if scanFailed && rc == 0 {
		rc = -1
		result.FailureCode = "output_read_failed"
	}
	if cleanupErr != nil {
		if stderr.Len() > 0 {
			_, _ = stderr.Write([]byte{'\n'})
		}
		fmt.Fprintf(stderr, "cleanup process group: %v", cleanupErr)
		result.FailureCode = "process_cleanup_failed"
		rc = -1
	}
	if rc != 0 && result.FailureCode == "" {
		result.FailureCode = "nonzero_exit"
	}
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.StdoutBytes = stdout.TotalBytes()
	result.StderrBytes = stderr.TotalBytes()
	result.StdoutTruncated = stdout.Truncated()
	result.StderrTruncated = stderr.Truncated()
	result.ReturnCode = rc
	result.TimedOut = timedOut
	result.Cancelled = cancelled
	return result
}

func newScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	sc.Split(scanOutputLines)
	return sc
}

func scanOutputLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if index := bytes.IndexByte(data, '\n'); index >= 0 {
		return index + 1, data[:index+1], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
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
