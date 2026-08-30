package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/gofiber/fiber/v3"
)

func TestNewExecutionLimiterUsesExplicitValue(t *testing.T) {
	// Given: an explicitly configured execution capacity.
	limiter := newExecutionLimiter(30)

	// When: callers acquire every configured slot.
	for range 30 {
		if !limiter.TryAcquire() {
			t.Fatal("explicit limiter capacity was exhausted early")
		}
	}

	// Then: one additional acquisition is rejected.
	if limiter.TryAcquire() {
		t.Fatal("explicit limiter accepted work beyond capacity")
	}
}

func TestNewExecutionLimiterFallsBackToDefaultForInvalidValue(t *testing.T) {
	// Given: a nonpositive server configuration.
	limiter := newExecutionLimiter(0)

	// When: callers acquire the documented default number of slots.
	for range defaultMaxConcurrentExecutions {
		if !limiter.TryAcquire() {
			t.Fatal("default limiter capacity was exhausted early")
		}
	}

	// Then: the next acquisition is rejected.
	if limiter.TryAcquire() {
		t.Fatal("default limiter accepted work beyond capacity")
	}
}

func TestWithExecutionLimitRejectsWhenServerIsBusy(t *testing.T) {
	// Given: one request already occupying the only execution slot.
	limiter := newExecutionLimiter(1)
	app := fiber.New()
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	app.Get("/limited", withExecutionLimit(limiter, func(c fiber.Ctx) error {
		startedOnce.Do(func() { close(started) })
		<-release
		return c.SendStatus(fiber.StatusOK)
	}))
	firstRespCh := make(chan *http.Response, 1)
	firstErrCh := make(chan error, 1)
	go func() {
		req, err := http.NewRequest(http.MethodGet, "/limited", nil)
		if err != nil {
			firstErrCh <- err
			return
		}
		resp, err := app.Test(req, fiber.TestConfig{Timeout: time.Second})
		if err != nil {
			firstErrCh <- err
			return
		}
		firstRespCh <- resp
	}()
	select {
	case <-started:
	case err := <-firstErrCh:
		t.Fatalf("first request failed before limiter test: %v", err)
	case <-time.After(time.Second):
		t.Fatal("first request did not acquire the limiter in time")
	}

	// When: a second request reaches the same limited route.
	secondReq, err := http.NewRequest(http.MethodGet, "/limited", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	secondResp, err := app.Test(secondReq, fiber.TestConfig{Timeout: time.Second})
	if err != nil {
		t.Fatalf("second request should fail fast with 503: %v", err)
	}
	defer secondResp.Body.Close()
	secondBody, err := io.ReadAll(secondResp.Body)
	if err != nil {
		t.Fatalf("read busy response: %v", err)
	}

	// Then: admission fails immediately with the existing 503 response.
	if secondResp.StatusCode != fiber.StatusServiceUnavailable || !strings.Contains(string(secondBody), "too many concurrent executions") {
		t.Fatalf("unexpected busy response: status=%d body=%s", secondResp.StatusCode, secondBody)
	}
	close(release)
	select {
	case err := <-firstErrCh:
		t.Fatalf("first request failed: %v", err)
	case firstResp := <-firstRespCh:
		defer firstResp.Body.Close()
		if firstResp.StatusCode != fiber.StatusOK {
			t.Fatalf("expected first request to complete with 200, got %d", firstResp.StatusCode)
		}
	case <-time.After(time.Second):
		t.Fatal("first request did not finish after release")
	}
}

func TestWithExecutionLimitRetainsLeaseForStreamingResponses(t *testing.T) {
	// Given: one streaming response retaining the only execution slot.
	limiter := newExecutionLimiter(1)
	app := fiber.New()
	started := make(chan struct{})
	streamRelease := make(chan struct{})
	var startedOnce sync.Once
	app.Get("/limited-stream", withExecutionLimit(limiter, func(c fiber.Ctx) error {
		startedOnce.Do(func() { close(started) })
		lines := make(chan executor.Line)
		done := make(chan *executor.Result, 1)
		release := retainExecutionLease(c)
		go func() {
			<-streamRelease
			close(lines)
			done <- &executor.Result{ReturnCode: 0}
			close(done)
		}()
		return sendToolStreamWithCancel(c, lines, done, nil, release)
	}))
	firstRespCh := make(chan *http.Response, 1)
	firstErrCh := make(chan error, 1)
	go func() {
		req, err := http.NewRequest(http.MethodGet, "/limited-stream", nil)
		if err != nil {
			firstErrCh <- err
			return
		}
		resp, err := app.Test(req, fiber.TestConfig{Timeout: 2 * time.Second})
		if err != nil {
			firstErrCh <- err
			return
		}
		firstRespCh <- resp
	}()
	select {
	case <-started:
	case err := <-firstErrCh:
		t.Fatalf("first stream request failed before limiter test: %v", err)
	case <-time.After(time.Second):
		t.Fatal("first stream request did not start in time")
	}

	// When: another stream request arrives before the first stream completes.
	secondReq, err := http.NewRequest(http.MethodGet, "/limited-stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	secondResp, err := app.Test(secondReq, fiber.TestConfig{Timeout: time.Second})
	if err != nil {
		t.Fatalf("second stream request should fail fast with 503: %v", err)
	}
	defer secondResp.Body.Close()
	secondBody, err := io.ReadAll(secondResp.Body)
	if err != nil {
		t.Fatalf("read busy response: %v", err)
	}

	// Then: the retained lease blocks the second stream until completion cleanup.
	if secondResp.StatusCode != fiber.StatusServiceUnavailable || !strings.Contains(string(secondBody), "too many concurrent executions") {
		t.Fatalf("unexpected busy response: status=%d body=%s", secondResp.StatusCode, secondBody)
	}
	close(streamRelease)
	select {
	case err := <-firstErrCh:
		t.Fatalf("first stream request failed: %v", err)
	case firstResp := <-firstRespCh:
		defer firstResp.Body.Close()
		if firstResp.StatusCode != fiber.StatusOK {
			t.Fatalf("expected first stream request to complete with 200, got %d", firstResp.StatusCode)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first stream request did not finish after release")
	}
}

func TestExecutionLimiterReleasePanicsOnOverRelease(t *testing.T) {
	// Given: an empty execution limiter.
	limiter := newExecutionLimiter(1)

	// When: the adapter releases without a matching acquisition.
	defer func() {
		// Then: the invariant panic remains visible through the adapter boundary.
		recovered := recover()
		if recovered == nil || !strings.Contains(fmt.Sprint(recovered), "execution limiter release invariant violated") {
			t.Fatalf("unexpected invariant panic: %v", recovered)
		}
	}()
	limiter.Release()
}
