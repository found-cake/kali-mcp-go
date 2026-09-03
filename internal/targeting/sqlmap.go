package targeting

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const maximumSQLMapRequestHeaderBytes = 64 * 1024

func sqlMapContextTarget(request dto.SQLMapRequest, claims targetContextClaims) (string, error) {
	requestText := request.RawRequest
	if request.RequestFile != "" {
		file, err := os.Open(request.RequestFile)
		if err != nil {
			return "", fmt.Errorf("open SQLMap request file: %w", err)
		}
		defer file.Close()
		content, err := io.ReadAll(io.LimitReader(file, maximumSQLMapRequestHeaderBytes+1))
		if err != nil {
			return "", fmt.Errorf("read SQLMap request file: %w", err)
		}
		requestText = string(content)
	}
	authority, requestTarget, err := rawHTTPRequestDestination(requestText)
	if err != nil {
		return "", err
	}
	expectedURL, err := url.Parse(claims.BrowserTarget)
	if err != nil || expectedURL.Hostname() == "" {
		return "", fmt.Errorf("target_context does not contain a valid browser target")
	}
	defaultPort := 80
	if strings.EqualFold(expectedURL.Scheme, "https") {
		defaultPort = 443
	}
	host, port, err := splitHTTPAuthority(authority, defaultPort)
	if err != nil {
		return "", err
	}
	expectedPort := claims.Port
	if expectedPort == 0 {
		expectedPort = defaultPort
	}
	hostMatches := sqlMapHostMatches(host, claims, expectedURL)
	if !hostMatches || port != expectedPort {
		return "", fmt.Errorf("SQLMap request Host %q does not match target_context destination %s:%d", authority, claims.NetworkTarget, expectedPort)
	}
	if err := validateSQLMapRequestTarget(requestTarget, claims, expectedURL, expectedPort); err != nil {
		return "", err
	}
	return claims.NetworkTarget, nil
}

func rawHTTPRequestDestination(request string) (string, string, error) {
	normalized := strings.ReplaceAll(request, "\r\n", "\n")
	headerEnd := strings.Index(normalized, "\n\n")
	if headerEnd < 0 {
		if len(normalized) > maximumSQLMapRequestHeaderBytes {
			return "", "", fmt.Errorf("SQLMap request headers exceed %d bytes", maximumSQLMapRequestHeaderBytes)
		}
		headerEnd = len(normalized)
	} else if headerEnd > maximumSQLMapRequestHeaderBytes {
		return "", "", fmt.Errorf("SQLMap request headers exceed %d bytes", maximumSQLMapRequestHeaderBytes)
	}
	header := normalized[:headerEnd]
	lineEnd := strings.IndexByte(header, '\n')
	if lineEnd < 0 {
		return "", "", fmt.Errorf("SQLMap request must contain a request line and Host header")
	}
	requestLine := strings.Fields(header[:lineEnd])
	if len(requestLine) != 3 || !strings.HasPrefix(requestLine[2], "HTTP/") {
		return "", "", fmt.Errorf("SQLMap request contains an invalid request line")
	}
	var authority string
	for line := range strings.Lines(header[lineEnd+1:]) {
		name, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "host") {
			continue
		}
		if authority != "" {
			return "", "", fmt.Errorf("SQLMap request contains multiple Host headers")
		}
		authority = strings.TrimSpace(value)
	}
	if authority == "" {
		return "", "", fmt.Errorf("SQLMap request must contain one Host header when target_context is supplied")
	}
	return authority, requestLine[1], nil
}

func validateSQLMapRequestTarget(requestTarget string, claims targetContextClaims, expectedURL *url.URL, expectedPort int) error {
	if strings.HasPrefix(requestTarget, "/") || requestTarget == "*" {
		return nil
	}
	parsed, err := url.Parse(requestTarget)
	if err != nil || parsed.User != nil || parsed.Hostname() == "" || parsed.Fragment != "" ||
		!strings.EqualFold(parsed.Scheme, expectedURL.Scheme) {
		return fmt.Errorf("SQLMap request target %q does not match target_context destination", requestTarget)
	}
	defaultPort := 80
	if strings.EqualFold(parsed.Scheme, "https") {
		defaultPort = 443
	}
	host, port, err := splitHTTPAuthority(parsed.Host, defaultPort)
	if err != nil || !sqlMapHostMatches(host, claims, expectedURL) || port != expectedPort {
		return fmt.Errorf("SQLMap request target %q does not match target_context destination", requestTarget)
	}
	return nil
}

func sqlMapHostMatches(host string, claims targetContextClaims, expectedURL *url.URL) bool {
	return strings.EqualFold(host, claims.NetworkTarget) || strings.EqualFold(host, expectedURL.Hostname())
}

func splitHTTPAuthority(authority string, defaultPort int) (string, int, error) {
	parsed, err := url.Parse("//" + authority)
	if err != nil || parsed.User != nil || parsed.Hostname() == "" || parsed.Path != "" {
		return "", 0, fmt.Errorf("invalid SQLMap request Host %q", authority)
	}
	port := defaultPort
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid SQLMap request Host port %q", parsed.Port())
		}
	}
	return parsed.Hostname(), port, nil
}
