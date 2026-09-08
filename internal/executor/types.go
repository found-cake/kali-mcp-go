package executor

import (
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type Result struct {
	CallID                string
	Stdout                string
	Stderr                string
	ReturnCode            int
	TimedOut              bool
	Cancelled             bool
	DryRun                bool
	HTTPRequests          *int
	RequestCountSource    dto.RequestCountSource
	Warnings              []string
	StartedAt             time.Time
	Duration              time.Duration
	FailureCode           string
	Tool                  string
	ToolVersion           string
	ArgvRedacted          []string
	Timeout               time.Duration
	ProcessStarted        bool
	GracefulStop          time.Duration
	Target                *dto.TargetProvenance
	Policy                dto.ScanOptions
	Controls              dto.ScanControlApplication
	SPABaseline           *dto.SPABaseline
	FalsePositiveRisk     string
	Artifacts             []dto.ArtifactRef
	HTTPRequest           *dto.HTTPRequestMetadata
	HTTPResponse          *dto.HTTPResponseMetadata
	Progress              *dto.ProgressMetadata
	JWTAnalysis           *dto.JWTAnalysisMetadata
	SQLMapAnalysis        *dto.SQLMapAnalysis
	NucleiPreview         *dto.NucleiPreviewMetadata
	Evidence              *dto.EvidenceManifest
	BrowserScreenshotPath string
}

const gracefulStopTimeout = time.Second

type Line struct {
	Stream   string
	Text     string
	Sequence int
}

type commandSpec struct {
	name string
	args []string
}
