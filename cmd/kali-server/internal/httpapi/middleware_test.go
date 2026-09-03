package httpapi

import "testing"

func TestCallOperationDistinguishesHydraStream(t *testing.T) {
	t.Parallel()

	if got := callOperation("/api/tools/hydra/stream"); got != "hydra_attack_stream" {
		t.Fatalf("Hydra stream telemetry operation=%q", got)
	}
}
