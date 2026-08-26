/*
This file is part of REANA.
Copyright (C) 2026 CERN.

REANA is free software; you can redistribute it and/or modify it
under the terms of the MIT License; see LICENSE file for more details.
*/

// Package auth implements OIDC authentication for the REANA command-line client.
package auth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	configPathEnv = "REANA_CLIENT_CONFIG"
	caCertsEnv    = "REANA_SERVER_CA_CERTS"
	insecureEnv   = "REANA_INSECURE"
)

// NormalizeServerURL returns the canonical credential-store key for a server.
func NormalizeServerURL(serverURL string) (string, error) {
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" {
		return "", errors.New("REANA server URL is not set")
	}
	if !strings.Contains(serverURL, "://") {
		serverURL = "https://" + serverURL
	}
	parsed, err := url.Parse(serverURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("REANA server URL must include scheme and host")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	// DNS hostnames are case-insensitive; without this, two otherwise-
	// identical server URLs differing only in host casing would normalize
	// to different credential-store keys instead of being recognized as
	// the same server.
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.Scheme != "https" {
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if parsed.Scheme != "http" || (!strings.EqualFold(host, "localhost") &&
			(ip == nil || !ip.IsLoopback())) {
			return "", errors.New("REANA server URL must use HTTPS")
		}
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New(
			"REANA server URL must not contain credentials, a query, or a fragment",
		)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String(), nil
}

// ConfigPath returns the shared Python/Go client credential-store path.
func ConfigPath() (string, error) {
	if configured := strings.TrimSpace(os.Getenv(configPathEnv)); configured != "" {
		if strings.HasPrefix(configured, "~"+string(filepath.Separator)) {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			configured = filepath.Join(
				home,
				strings.TrimPrefix(configured, "~"+string(filepath.Separator)),
			)
		}
		return filepath.Abs(configured)
	}
	return defaultConfigPath()
}

func defaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "reana", "reana-client.json"), nil
}

// NewHTTPClient builds the common TLS policy used for REANA and OIDC requests.
func NewHTTPClient() (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath := strings.TrimSpace(os.Getenv(caCertsEnv)); caPath != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("could not read REANA CA bundle: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New(
				"REANA CA bundle does not contain a valid certificate",
			)
		}
		tlsConfig.RootCAs = roots
	} else if raw := strings.TrimSpace(os.Getenv(insecureEnv)); raw != "" {
		insecure, valid := parseBoolean(raw)
		if !valid {
			return nil, fmt.Errorf("invalid %s value %q", insecureEnv, raw)
		}
		// This is an explicit local-development escape hatch matching the Python client.
		tlsConfig.InsecureSkipVerify = insecure //nolint:gosec
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func parseBoolean(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}
