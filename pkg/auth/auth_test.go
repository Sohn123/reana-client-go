/*
This file is part of REANA.
Copyright (C) 2026 CERN.

REANA is free software; you can redistribute it and/or modify it
under the terms of the MIT License; see LICENSE file for more details.
*/

package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	return function(request)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func testManager(t *testing.T, handler roundTripFunc) *Manager {
	t.Helper()
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	return &Manager{
		Store: &Store{Path: filepath.Join(t.TempDir(), "reana-client.json")},
		HTTPClient: &http.Client{
			Transport: handler,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Now:   func() time.Time { return now },
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
}

func TestStoreUsesPythonCompatibleSchemaAndPermissions(t *testing.T) {
	store := &Store{Path: filepath.Join(t.TempDir(), "reana-client.json")}
	stored, err := store.Put("HTTPS://reana.example.org/", Credentials{
		Issuer:      "https://issuer.example.org",
		ClientID:    "reana-cli",
		AccessToken: "access",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CredentialEpoch != 1 {
		t.Fatalf("credential epoch = %d, want 1", stored.CredentialEpoch)
	}
	contents, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(contents, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["active_server"] != "https://reana.example.org" {
		t.Fatalf("active server = %v", raw["active_server"])
	}
	info, err := os.Stat(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("credential permissions = %o, want 600", permissions)
	}
}

func TestDefaultCredentialDirectoryHasRestrictivePermissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("REANA_CLIENT_CONFIG", "")
	directory := filepath.Join(home, ".config", "reana")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore()
	if err != nil {
		t.Fatal(err)
	}
	if store.Path != filepath.Join(directory, "reana-client.json") {
		t.Fatalf("default credential path = %q", store.Path)
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o700 {
		t.Fatalf("credential directory permissions = %o, want 700", permissions)
	}
}

func TestNormalizeServerURL(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{"reana.example.org/", "https://reana.example.org"},
		{"https://reana.example.org/base/", "https://reana.example.org/base"},
		{"http://127.0.0.1:5000/", "http://127.0.0.1:5000"},
	} {
		got, err := NormalizeServerURL(test.input)
		if err != nil || got != test.want {
			t.Errorf(
				"NormalizeServerURL(%q) = %q, %v; want %q",
				test.input,
				got,
				err,
				test.want,
			)
		}
	}
	if _, err := NormalizeServerURL("http://reana.example.org"); err == nil {
		t.Fatal("non-loopback HTTP server was accepted")
	}
}

func TestDiscoverValidatesRelayedMetadata(t *testing.T) {
	manager := testManager(
		t,
		func(request *http.Request) (*http.Response, error) {
			if request.URL.Path != discoveryPath {
				t.Fatalf("discovery path = %q", request.URL.Path)
			}
			return jsonResponse(http.StatusOK, `{
            "issuer":"https://issuer.example.org",
            "authorization_endpoint":"https://issuer.example.org/auth",
            "token_endpoint":"https://issuer.example.org/token",
            "device_authorization_endpoint":"https://issuer.example.org/device",
            "revocation_endpoint":"https://issuer.example.org/revoke",
            "reana_cli_client_id":"reana-cli"
        }`), nil
		},
	)
	metadata, err := manager.Discover(
		context.Background(),
		"https://reana.example.org",
	)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.CLIClientID != "reana-cli" {
		t.Fatalf("client id = %q", metadata.CLIClientID)
	}
}

func TestDiscoverRejectsCredentialEndpointRedirect(t *testing.T) {
	manager := testManager(t, func(*http.Request) (*http.Response, error) {
		response := jsonResponse(http.StatusTemporaryRedirect, `{}`)
		response.Header.Set("Location", "http://attacker.example/metadata")
		return response, nil
	})
	_, err := manager.Discover(
		context.Background(),
		"https://reana.example.org",
	)
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
}

func TestDeviceLoginUsesPKCEAndStoresTokens(t *testing.T) {
	requests := 0
	manager := testManager(
		t,
		func(request *http.Request) (*http.Response, error) {
			requests++
			switch request.URL.Path {
			case discoveryPath:
				return jsonResponse(http.StatusOK, `{
                "issuer":"https://issuer.example.org",
                "authorization_endpoint":"https://issuer.example.org/auth",
                "token_endpoint":"https://issuer.example.org/token",
                "device_authorization_endpoint":"https://issuer.example.org/device",
                "reana_cli_client_id":"reana-cli"
            }`), nil
			case "/device":
				form := readForm(t, request)
				if form.Get("code_challenge") == "" ||
					form.Get("code_challenge_method") != "S256" {
					t.Fatalf("device PKCE form = %v", form)
				}
				return jsonResponse(
					http.StatusOK,
					`{"device_code":"device","user_code":"ABCD","verification_uri":"https://issuer.example.org/verify","expires_in":300,"interval":1}`,
				), nil
			case "/token":
				form := readForm(t, request)
				if form.Get("code_verifier") == "" ||
					form.Get(
						"grant_type",
					) != "urn:ietf:params:oauth:grant-type:device_code" {
					t.Fatalf("device token form = %v", form)
				}
				return jsonResponse(
					http.StatusOK,
					`{"access_token":"a.b.c","refresh_token":"refresh","expires_in":3600}`,
				), nil
			default:
				t.Fatalf("unexpected request: %s", request.URL)
				return nil, nil
			}
		},
	)
	prompted := false
	credentials, err := manager.LoginDevice(
		context.Background(),
		"https://reana.example.org",
		func(prompt DevicePrompt) {
			prompted = prompt.UserCode == "ABCD"
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !prompted || credentials.AccessToken != "a.b.c" ||
		credentials.RefreshToken != "refresh" ||
		requests != 3 {
		t.Fatalf(
			"unexpected device result: prompted=%v credentials=%+v requests=%d",
			prompted,
			credentials,
			requests,
		)
	}
}

func TestBrowserLoginValidatesStateAndUsesPKCE(t *testing.T) {
	manager := testManager(
		t,
		func(request *http.Request) (*http.Response, error) {
			switch request.URL.Path {
			case discoveryPath:
				return jsonResponse(http.StatusOK, `{
                "issuer":"https://issuer.example.org",
                "authorization_endpoint":"https://issuer.example.org/auth",
                "token_endpoint":"https://issuer.example.org/token",
                "reana_cli_client_id":"reana-cli"
            }`), nil
			case "/token":
				form := readForm(t, request)
				if form.Get("grant_type") != "authorization_code" ||
					form.Get("code_verifier") == "" ||
					form.Get("code") != "code" {
					t.Fatalf("authorization code form = %v", form)
				}
				return jsonResponse(
					http.StatusOK,
					`{"access_token":"browser.jwt.token","refresh_token":"refresh","expires_in":3600}`,
				), nil
			default:
				t.Fatalf("unexpected request: %s", request.URL)
				return nil, nil
			}
		},
	)
	var displayed string
	credentials, err := manager.LoginBrowser(
		context.Background(),
		"https://reana.example.org",
		func(value string) { displayed = value },
		func(authorizationURL string) error {
			parsed, err := url.Parse(authorizationURL)
			if err != nil {
				return err
			}
			if parsed.Query().Get("code_challenge_method") != "S256" ||
				parsed.Query().Get("code_challenge") == "" {
				t.Fatalf("authorization URL lacks PKCE: %s", authorizationURL)
			}
			callback := parsed.Query().
				Get("redirect_uri") +
				"?code=code&state=" + url.QueryEscape(
				parsed.Query().Get("state"),
			)
			response, err := http.Get(callback) //nolint:gosec
			if err == nil {
				response.Body.Close()
			}
			return err
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if displayed == "" || credentials.AccessToken != "browser.jwt.token" {
		t.Fatalf(
			"unexpected browser login result: displayed=%q credentials=%+v",
			displayed,
			credentials,
		)
	}
}

func TestAccessTokenRefreshesAndPreservesRotatedRefreshToken(t *testing.T) {
	manager := testManager(
		t,
		func(request *http.Request) (*http.Response, error) {
			form := readForm(t, request)
			if form.Get("grant_type") != "refresh_token" ||
				form.Get("refresh_token") != "old-refresh" {
				t.Fatalf("refresh form = %v", form)
			}
			return jsonResponse(
				http.StatusOK,
				`{"access_token":"new.access.token","expires_in":3600}`,
			), nil
		},
	)
	_, err := manager.Store.Put("https://reana.example.org", Credentials{
		Issuer:                "https://issuer.example.org",
		ClientID:              "reana-cli",
		TokenEndpoint:         "https://issuer.example.org/token",
		AuthorizationEndpoint: "https://issuer.example.org/auth",
		AccessToken:           "old.access.token",
		AccessTokenExpiresAt: manager.Now().
			Add(10 * time.Second).
			Format(time.RFC3339),
		RefreshToken: "old-refresh",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	token, err := manager.AccessToken(
		context.Background(),
		"https://reana.example.org",
	)
	if err != nil {
		t.Fatal(err)
	}
	if token != "new.access.token" {
		t.Fatalf("access token = %q", token)
	}
	stored, _ := manager.Store.Get("https://reana.example.org")
	if stored.RefreshToken != "old-refresh" {
		t.Fatalf(
			"refresh token = %q, want preserved token",
			stored.RefreshToken,
		)
	}
}

func TestLogoutAcceptsEmptyRevocationResponseAndClearsTokens(t *testing.T) {
	var manager *Manager
	manager = testManager(
		t,
		func(request *http.Request) (*http.Response, error) {
			if request.URL.Path != "/revoke" {
				t.Fatalf("revocation path = %q", request.URL.Path)
			}
			probe, err := os.OpenFile(
				manager.Store.Path+".lock",
				os.O_CREATE|os.O_RDWR,
				0o600,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Close()
			if err := unix.Flock(
				int(probe.Fd()),
				unix.LOCK_EX|unix.LOCK_NB,
			); err == nil {
				_ = unix.Flock(int(probe.Fd()), unix.LOCK_UN)
				t.Fatal("credential lock was not held during token revocation")
			}
			return jsonResponse(http.StatusNoContent, ""), nil
		},
	)
	_, err := manager.Store.Put("https://reana.example.org", Credentials{
		ClientID:           "reana-cli",
		RevocationEndpoint: "https://issuer.example.org/revoke",
		AccessToken:        "access",
		RefreshToken:       "refresh",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	warning, err := manager.Logout(
		context.Background(),
		"https://reana.example.org",
	)
	if err != nil || warning != "" {
		t.Fatalf("logout = warning %q, error %v", warning, err)
	}
	stored, _ := manager.Store.Get("https://reana.example.org")
	if stored.AccessToken != "" || stored.RefreshToken != "" {
		t.Fatalf("tokens were not cleared: %+v", stored)
	}
}

func readForm(t *testing.T, request *http.Request) url.Values {
	t.Helper()
	contents, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	form, err := url.ParseQuery(string(contents))
	if err != nil {
		t.Fatal(err)
	}
	return form
}
