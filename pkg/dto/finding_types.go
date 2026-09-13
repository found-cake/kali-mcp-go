package dto

type FindingType string

const (
	FindingTypeService          FindingType = "service"
	FindingTypeTechnology       FindingType = "technology"
	FindingTypeContent          FindingType = "content"
	FindingTypeVulnerability    FindingType = "vulnerability"
	FindingTypeMisconfiguration FindingType = "misconfiguration"
	FindingTypeCredential       FindingType = "credential"
	FindingTypeAuthentication   FindingType = "authentication"
)
