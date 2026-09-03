package tools

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type SQLMapPlan struct {
	args        []string
	requestFile string
	trafficFile string
	tempDir     string
}

const maximumSQLMapRequestBytes = 16 * 1024 * 1024

func PrepareSQLMap(request dto.SQLMapRequest) (*SQLMapPlan, error) {
	sourceCount := 0
	for _, source := range []string{request.URL, request.RequestFile, request.RawRequest} {
		if strings.TrimSpace(source) != "" {
			sourceCount++
		}
	}
	if sourceCount != 1 {
		return nil, fmt.Errorf("provide exactly one of url, request_file, or raw_request")
	}
	tempDir, err := os.MkdirTemp("", "kali-mcp-sqlmap-*")
	if err != nil {
		return nil, fmt.Errorf("create sqlmap workspace: %w", err)
	}
	plan := &SQLMapPlan{
		args:        []string{"sqlmap", "--batch", "--flush-session", "--ignore-stdin"},
		trafficFile: filepath.Join(tempDir, "traffic.txt"),
		tempDir:     tempDir,
	}
	if err := plan.addSource(request); err != nil {
		plan.Cleanup()
		return nil, err
	}
	if request.Data != "" {
		plan.args = append(plan.args, "--data", request.Data)
	}
	headerNames := make([]string, 0, len(request.Headers))
	for name := range request.Headers {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	for _, name := range headerNames {
		plan.args = append(plan.args, "--header", name+": "+request.Headers[name])
	}
	if request.Cookie != "" {
		plan.args = append(plan.args, "--cookie", request.Cookie)
	}
	if request.ContentType != "" {
		plan.args = append(plan.args, "--header", "Content-Type: "+request.ContentType)
	}
	if request.IgnoreCodes != "" {
		plan.args = append(plan.args, "--ignore-code", request.IgnoreCodes)
	}
	if request.TestParameters != "" {
		plan.args = append(plan.args, "-p", request.TestParameters)
	}
	plan.args = append(plan.args, "-t", plan.trafficFile, "--output-dir", filepath.Join(tempDir, "output"))
	plan.args, err = appendSplitArgs(plan.args, request.AdditionalArgs, "additional_args")
	if err != nil {
		plan.Cleanup()
		return nil, err
	}
	return plan, nil
}

func (p *SQLMapPlan) addSource(request dto.SQLMapRequest) error {
	if request.URL != "" {
		p.args = append(p.args, "-u", request.URL)
		return nil
	}
	if request.RawRequest != "" {
		return p.writeRequest(request.RawRequest)
	}
	return p.copyRequest(request.RequestFile)
}

func (p *SQLMapPlan) writeRequest(content string) error {
	p.requestFile = filepath.Join(p.tempDir, "request.txt")
	if err := os.WriteFile(p.requestFile, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write raw request: %w", err)
	}
	p.args = append(p.args, "-r", p.requestFile)
	return nil
}

func (p *SQLMapPlan) copyRequest(source string) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open raw request: %w", err)
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return fmt.Errorf("inspect raw request: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("raw request file must be a regular file")
	}
	if info.Size() > maximumSQLMapRequestBytes {
		return fmt.Errorf("raw request file exceeds %d bytes", maximumSQLMapRequestBytes)
	}
	p.requestFile = filepath.Join(p.tempDir, "request.txt")
	output, err := os.OpenFile(p.requestFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create request snapshot: %w", err)
	}
	written, err := io.Copy(output, io.LimitReader(input, maximumSQLMapRequestBytes+1))
	if err != nil {
		_ = output.Close()
		return fmt.Errorf("copy raw request: %w", err)
	}
	if written > maximumSQLMapRequestBytes {
		_ = output.Close()
		return fmt.Errorf("raw request file exceeds %d bytes", maximumSQLMapRequestBytes)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close request snapshot: %w", err)
	}
	p.args = append(p.args, "-r", p.requestFile)
	return nil
}

func (p *SQLMapPlan) Args() []string {
	return append([]string(nil), p.args...)
}

func (p *SQLMapPlan) EphemeralPath() string {
	return p.tempDir
}

func (p *SQLMapPlan) RequestFile() string {
	return p.requestFile
}

func (p *SQLMapPlan) HTTPRequestCount() int {
	return p.Analysis("", "").HTTPRequests
}

func (p *SQLMapPlan) Cleanup() {
	if p != nil && p.tempDir != "" {
		_ = os.RemoveAll(p.tempDir)
	}
}
