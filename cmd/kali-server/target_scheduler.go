package main

import ()

func scanWeight(tool string) int {
	switch tool {
	case "nuclei", "nikto", "sqlmap", "ffuf", "feroxbuster", "dalfox":
		return 3
	case "gobuster", "dirb", "wpscan", "hydra", "browser-check":
		return 2
	default:
		return 1
	}
}
