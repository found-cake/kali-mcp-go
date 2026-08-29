package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func applyRequestTargetContext[T any](secret string, request T, now time.Time) (T, error) {
	scanRequest, ok := any(request).(dto.ScanRequest)
	if !ok {
		return request, nil
	}
	options := scanRequest.GetScanOptions()
	if options.TargetContext == "" {
		return request, nil
	}
	if options.ResolutionReceipt != "" {
		return request, fmt.Errorf("target_context and resolution_receipt cannot be used together")
	}
	claims, err := verifyTargetContext(secret, options.TargetContext, now)
	if err != nil {
		return request, err
	}
	if err := applyContextTarget(&request, claims); err != nil {
		return request, err
	}
	return request, nil
}

func applyContextTarget(request any, claims targetContextClaims) error {
	switch value := request.(type) {
	case *dto.NmapRequest:
		return setNetworkTarget(&value.Target, claims.NetworkTarget)
	case *dto.GobusterRequest:
		if strings.EqualFold(value.Mode, "dns") {
			return setNetworkTarget(&value.URL, claims.NetworkTarget)
		}
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.DirbRequest:
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.NiktoRequest:
		return setWebTarget(&value.Target, claims.BrowserTarget)
	case *dto.SQLMapRequest:
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.HydraRequest:
		return setNetworkTarget(&value.Target, claims.NetworkTarget)
	case *dto.WPScanRequest:
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.Enum4linuxRequest:
		return setNetworkTarget(&value.Target, claims.NetworkTarget)
	case *dto.FFUFRequest:
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.FeroxbusterRequest:
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.NucleiRequest:
		return setURLOrHostTarget(&value.Target, claims)
	case *dto.WhatWebRequest:
		return setURLOrHostTarget(&value.Target, claims)
	case *dto.JWTRequest:
		return setWebTarget(&value.TargetURL, claims.BrowserTarget)
	case *dto.DalfoxRequest:
		return setWebTarget(&value.Target, claims.BrowserTarget)
	case *dto.BrowserRequest:
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.RetireRequest:
		return setWebTarget(&value.URL, claims.BrowserTarget)
	default:
		return fmt.Errorf("target_context is not supported for this request")
	}
}

func setNetworkTarget(current *string, expected string) error {
	if *current != "" && !strings.EqualFold(*current, expected) {
		return fmt.Errorf("request target does not match target_context network target")
	}
	*current = expected
	return nil
}

func setWebTarget(current *string, expected string) error {
	if expected == "" {
		return fmt.Errorf("target_context does not contain a browser target")
	}
	if *current != "" {
		currentOrigin, currentOK := webOrigin(*current)
		expectedOrigin, expectedOK := webOrigin(expected)
		if !currentOK || !expectedOK || currentOrigin != expectedOrigin {
			return fmt.Errorf("request URL does not match target_context browser origin")
		}
		return nil
	}
	*current = expected
	return nil
}

func setURLOrHostTarget(current *string, claims targetContextClaims) error {
	if *current != "" && !strings.Contains(*current, "://") {
		return setNetworkTarget(current, claims.NetworkTarget)
	}
	if claims.BrowserTarget != "" {
		return setWebTarget(current, claims.BrowserTarget)
	}
	return setNetworkTarget(current, claims.NetworkTarget)
}
