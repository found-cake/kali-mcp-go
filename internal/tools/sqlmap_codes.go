package tools

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

func ParseSQLMapStatusCodes(field, value string) ([]int, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	codes := make([]int, 0)
	for token := range strings.SplitSeq(value, ",") {
		code, err := strconv.Atoi(strings.TrimSpace(token))
		if err != nil || code < 100 || code > 599 {
			return nil, fmt.Errorf("%s must contain HTTP codes between 100 and 599", field)
		}
		if !slices.Contains(codes, code) {
			codes = append(codes, code)
		}
	}
	return codes, nil
}
