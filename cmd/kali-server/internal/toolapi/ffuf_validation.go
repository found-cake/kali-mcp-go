package toolapi

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func validateFFUFRequest(req dto.FFUFRequest) error {
	if req.URL == "" {
		return fmt.Errorf("url is required")
	}
	if !strings.Contains(req.URL, "FUZZ") && !strings.Contains(req.AdditionalArgs, "FUZZ") {
		return fmt.Errorf("FUZZ must appear in url or additional_args")
	}
	if req.RequestTimeout < 0 || req.RequestTimeout > 300 {
		return fmt.Errorf("request_timeout must be between 1 and 300 seconds, or 0 for the FFUF default")
	}
	if req.FilterStatuses == "" {
		return nil
	}
	for item := range strings.SplitSeq(req.FilterStatuses, ",") {
		bounds := strings.Split(strings.TrimSpace(item), "-")
		if len(bounds) < 1 || len(bounds) > 2 {
			return fmt.Errorf("filter_status_codes must contain HTTP codes between 100 and 599")
		}
		lower, err := strconv.Atoi(bounds[0])
		if err != nil || lower < 100 || lower > 599 {
			return fmt.Errorf("filter_status_codes must contain HTTP codes between 100 and 599")
		}
		upper := lower
		if len(bounds) == 2 {
			upper, err = strconv.Atoi(bounds[1])
		}
		if err != nil || upper < lower || upper > 599 {
			return fmt.Errorf("filter_status_codes must contain HTTP codes between 100 and 599")
		}
	}
	return nil
}
