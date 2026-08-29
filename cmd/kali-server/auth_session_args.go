package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func applyAuthSession(args []string, target string, session authSession) ([]string, error) {
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse target for authentication session: %w", err)
	}
	targetOrigin, err := normalizeOrigin(targetURL.Scheme + "://" + targetURL.Host)
	if err != nil || targetOrigin != session.origin {
		return nil, errAuthSessionOriginMismatch
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("cannot apply authentication session to empty command")
	}
	if len(session.metadata.AllowedTools) > 0 && !slices.Contains(session.metadata.AllowedTools, args[0]) {
		return nil, fmt.Errorf("authentication session does not allow %s", args[0])
	}
	updated := append([]string(nil), args...)
	names := make([]string, 0, len(session.headers))
	for name := range session.headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		updated, err = appendSessionHeader(updated, name+": "+session.headers[name])
		if err != nil {
			return nil, err
		}
	}
	if session.cookie != "" {
		updated, err = appendSessionCookie(updated, session.cookie)
	}
	return updated, err
}

func appendSessionHeader(args []string, header string) ([]string, error) {
	switch args[0] {
	case "ffuf", "nuclei", "feroxbuster", "dalfox":
		return append(args, "-H", header), nil
	case "gobuster":
		return append(args, "-H", header), nil
	case "sqlmap":
		return append(args, "--header", header), nil
	case "whatweb":
		return append(args, "--header", header), nil
	case "browser-check":
		return appendBrowserHeader(args, header)
	default:
		return nil, fmt.Errorf("authentication sessions are not supported for %s", args[0])
	}
}

func appendSessionCookie(args []string, cookie string) ([]string, error) {
	switch args[0] {
	case "gobuster":
		return append(args, "-c", cookie), nil
	case "sqlmap", "dalfox":
		return append(args, "--cookie", cookie), nil
	case "browser-check":
		return appendBrowserHeader(args, "Cookie: "+cookie)
	case "ffuf", "nuclei", "feroxbuster", "whatweb":
		return appendSessionHeader(args, "Cookie: "+cookie)
	default:
		return nil, fmt.Errorf("authentication sessions are not supported for %s", args[0])
	}
}

func appendBrowserHeader(args []string, header string) ([]string, error) {
	headers := map[string]string{}
	for index := 0; index+1 < len(args); index++ {
		if args[index] != "--headers-base64" {
			continue
		}
		decoded, err := base64.RawURLEncoding.DecodeString(args[index+1])
		if err != nil || json.Unmarshal(decoded, &headers) != nil {
			return nil, fmt.Errorf("decode browser session headers")
		}
		args = append(args[:index], args[index+2:]...)
		break
	}
	name, value, found := stringsCutHeader(header)
	if !found {
		return nil, fmt.Errorf("invalid browser header")
	}
	headers[name] = value
	payload, err := json.Marshal(headers)
	if err != nil {
		return nil, fmt.Errorf("encode browser session headers: %w", err)
	}
	return append(args, "--headers-base64", base64.RawURLEncoding.EncodeToString(payload)), nil
}

func stringsCutHeader(header string) (string, string, bool) {
	for index, character := range header {
		if character == ':' {
			return header[:index], header[index+1:], index > 0
		}
	}
	return "", "", false
}

func applyRequestedAuthSession(c fiber.Ctx, options dto.ScanOptions, args []string, target string) ([]string, error) {
	if options.SessionID == "" {
		return args, nil
	}
	store := authSessionStoreFromContext(c)
	if store == nil {
		return nil, fmt.Errorf("authentication session store is unavailable")
	}
	session, err := store.get(options.SessionID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return applyAuthSession(args, target, session)
}
