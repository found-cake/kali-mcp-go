package dto

const (
	FailureCodeTargetCapacityExceeded = "target_capacity_exceeded"
	FailureCodeGlobalCapacityExceeded = "global_capacity_exceeded"
)

type CapacityScope string

const (
	CapacityScopeTarget CapacityScope = "target"
	CapacityScopeGlobal CapacityScope = "global"
)

type CapacityMetadata struct {
	Scope           CapacityScope `json:"scope"`
	Used            int           `json:"used"`
	Limit           int           `json:"limit"`
	RequestedWeight int           `json:"requested_weight"`
}

type ErrorResponse struct {
	Error    string            `json:"error"`
	Code     string            `json:"code,omitempty"`
	Capacity *CapacityMetadata `json:"capacity,omitempty"`
}
