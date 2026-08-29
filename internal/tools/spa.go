package tools

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const spaBaselineSamples = 3

var spaHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	},
}

type baselineSample struct {
	statusCode int
	length     int
	hash       string
}

func MeasureSPABaseline(ctx context.Context, target string) (dto.SPABaseline, error) {
	if !strings.Contains(target, "FUZZ") {
		return dto.SPABaseline{}, fmt.Errorf("FFUF target must contain FUZZ")
	}
	samples := make([]baselineSample, 0, spaBaselineSamples)
	for range spaBaselineSamples {
		randomBytes := make([]byte, 8)
		if _, err := rand.Read(randomBytes); err != nil {
			return dto.SPABaseline{}, fmt.Errorf("generate baseline path: %w", err)
		}
		missingPath := ".kali-mcp-missing-" + hex.EncodeToString(randomBytes)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.ReplaceAll(target, "FUZZ", missingPath), nil)
		if err != nil {
			return dto.SPABaseline{}, fmt.Errorf("create baseline request: %w", err)
		}
		response, err := spaHTTPClient.Do(request)
		if err != nil {
			return dto.SPABaseline{}, fmt.Errorf("request SPA baseline: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
		closeErr := response.Body.Close()
		if readErr != nil {
			return dto.SPABaseline{}, fmt.Errorf("read SPA baseline: %w", readErr)
		}
		if closeErr != nil {
			return dto.SPABaseline{}, fmt.Errorf("close SPA baseline: %w", closeErr)
		}
		normalized := strings.Join(strings.Fields(string(body)), " ")
		hash := sha256.Sum256([]byte(normalized))
		samples = append(samples, baselineSample{
			statusCode: response.StatusCode,
			length:     len(body),
			hash:       hex.EncodeToString(hash[:]),
		})
	}
	first := samples[0]
	stable := first.statusCode >= 200 && first.statusCode < 300
	for _, sample := range samples[1:] {
		stable = stable && sample == first
	}
	return dto.SPABaseline{
		Samples:       len(samples),
		StatusCode:    first.statusCode,
		ContentLength: first.length,
		BodyHash:      first.hash,
		Stable:        stable,
	}, nil
}

func ApplyFFUFBaseline(args []string, baseline dto.SPABaseline) ([]string, error) {
	if len(args) == 0 || args[0] != "ffuf" {
		return nil, fmt.Errorf("FFUF command is required")
	}
	result := append([]string(nil), args...)
	if !baseline.Stable || baseline.ContentLength <= 0 || containsArg(result, "-fs") {
		return result, nil
	}
	return append(result, "-fs", strconv.Itoa(baseline.ContentLength)), nil
}

func containsArg(args []string, target string) bool {
	for _, arg := range args {
		if arg == target {
			return true
		}
	}
	return false
}
