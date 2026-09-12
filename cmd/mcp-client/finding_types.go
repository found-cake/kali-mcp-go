package main

import "github.com/found-cake/kali-mcp-go/pkg/dto"

func findingTypesForTool(tool string) []dto.FindingType {
	switch tool {
	case "nmap_scan", "enum4linux_scan":
		return []dto.FindingType{dto.FindingTypeService}
	case "whatweb_scan":
		return []dto.FindingType{dto.FindingTypeTechnology}
	case "gobuster_scan", "dirb_scan", "ffuf_scan", "feroxbuster_scan":
		return []dto.FindingType{dto.FindingTypeContent}
	case "nuclei_scan", "nikto_scan", "wpscan_analyze":
		return []dto.FindingType{dto.FindingTypeVulnerability, dto.FindingTypeMisconfiguration}
	case "sqlmap_scan", "dalfox_scan", "browser_check", "retirejs_scan", "osv_scan":
		return []dto.FindingType{dto.FindingTypeVulnerability}
	case "john_crack", "hydra_attack", "hydra_attack_stream":
		return []dto.FindingType{dto.FindingTypeCredential}
	case "jwt_analyze":
		return []dto.FindingType{dto.FindingTypeAuthentication}
	default:
		return nil
	}
}
