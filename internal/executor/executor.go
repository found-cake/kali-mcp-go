package executor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type Result struct {
	CallID             string
	Stdout             string
	Stderr             string
	ReturnCode         int
	TimedOut           bool
	Cancelled          bool
	HTTPRequests       *int
	RequestCountSource dto.RequestCountSource
	Warnings           []string
	StartedAt          time.Time
	Duration           time.Duration
	FailureCode        string
	Tool               string
	ToolVersion        string
	ArgvRedacted       []string
	Timeout            time.Duration
	Target             *dto.TargetProvenance
	Policy             dto.ScanOptions
	Controls           dto.ScanControlApplication
	SPABaseline        *dto.SPABaseline
	FalsePositiveRisk  string
	Artifacts          []dto.ArtifactRef
	HTTPRequest        *dto.HTTPRequestMetadata
	HTTPResponse       *dto.HTTPResponseMetadata
	Progress           *dto.ProgressMetadata
	JWTAnalysis        *dto.JWTAnalysisMetadata
}

func (r *Result) Success() bool {
	return !r.TimedOut && !r.Cancelled && r.ReturnCode == 0
}

type Line struct {
	Stream   string
	Text     string
	Sequence int
}

type commandSpec struct {
	name string
	args []string
}

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
	result := &Result{
		ReturnCode:   -1,
		StartedAt:    startedAt,
		Tool:         cmdSpec.name,
		ToolVersion:  toolVersion(ctx, cmdSpec.name),
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
			sequence := progress.observe(text)
			buf.WriteString(text)
			buf.WriteByte('\n')
			if emit != nil && !emit(ctx, Line{Stream: stream, Text: text, Sequence: sequence}) {
				return
			}
		}
		if err := sc.Err(); err != nil && !(ctx.Err() != nil && errors.Is(err, os.ErrClosed)) {
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
		result.FailureCode = "output_read_failed"
	}
	if rc != 0 && result.FailureCode == "" {
		result.FailureCode = "nonzero_exit"
	}
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.ReturnCode = rc
	result.TimedOut = timedOut
	result.Cancelled = cancelled
	return result
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
