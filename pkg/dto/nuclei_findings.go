package dto

type NucleiFinding struct {
	TemplateID  string `json:"template_id"`
	Name        string `json:"name,omitempty"`
	Severity    string `json:"severity,omitempty"`
	MatcherName string `json:"matcher_name,omitempty"`
	Type        string `json:"type,omitempty"`
	MatchedAt   string `json:"matched_at,omitempty"`
}
