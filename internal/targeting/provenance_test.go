package targeting

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestValidateHealthURLConfinesRequestsToSelectedService(t *testing.T) {
	tests := []struct {
		name       string
		healthURL  string
		provenance *dto.TargetProvenance
		wantErr    bool
	}{
		{
			name: "same web origin", healthURL: "http://192.168.65.254:3000/health",
			provenance: &dto.TargetProvenance{Selected: "http://192.168.65.254:3000/app", Port: 3000},
		},
		{
			name: "same network service", healthURL: "http://192.168.65.254:3000/health",
			provenance: &dto.TargetProvenance{Selected: "192.168.65.254", Port: 3000},
		},
		{
			name: "different host", healthURL: "http://foreign.test:3000/health",
			provenance: &dto.TargetProvenance{Selected: "192.168.65.254", Port: 3000}, wantErr: true,
		},
		{
			name: "different port", healthURL: "http://192.168.65.254:8080/health",
			provenance: &dto.TargetProvenance{Selected: "192.168.65.254", Port: 3000}, wantErr: true,
		},
		{name: "missing target", healthURL: "http://192.168.65.254:3000/health", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateHealthURL(test.healthURL, test.provenance)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateHealthURL() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}
