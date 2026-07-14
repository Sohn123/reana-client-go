// This file is part of REANA.
// Copyright (C) 2026 CERN.

package client

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"reanahub/reana-client-go/client/operations"

	"github.com/spf13/viper"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	return function(request)
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (body *trackedBody) Close() error {
	body.closed = true
	return nil
}

func TestBoundedResponseBodyRejectsBytesPastLimit(t *testing.T) {
	body := &boundedResponseBody{
		body:      io.NopCloser(strings.NewReader("four")),
		remaining: 3,
	}
	contents, err := io.ReadAll(body)
	if err == nil ||
		!strings.Contains(err.Error(), ErrResponseTooLarge.Error()) {
		t.Fatalf("expected response limit error, got %q and %v", contents, err)
	}
	if !bytes.Equal(contents, []byte("fou")) {
		t.Fatalf("unexpected bounded contents %q", contents)
	}
}

func TestBoundedResponseBodyAcceptsExactLimit(t *testing.T) {
	body := &boundedResponseBody{
		body:      io.NopCloser(strings.NewReader("three")),
		remaining: 5,
	}
	contents, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, []byte("three")) {
		t.Fatalf("unexpected contents %q", contents)
	}
}

func TestBoundedResponseTransportRejectsDeclaredOversize(t *testing.T) {
	body := &trackedBody{Reader: strings.NewReader("response")}
	transport := &boundedResponseTransport{transport: roundTripFunc(func(
		*http.Request,
	) (*http.Response, error) {
		return &http.Response{
			Body:          body,
			ContentLength: maxAPIResponseBytes + 1,
		}, nil
	})}
	_, err := transport.RoundTrip(
		httptest.NewRequest(http.MethodGet, "https://reana.test", nil),
	)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("expected %v, got %v", ErrResponseTooLarge, err)
	}
	if !body.closed {
		t.Error("expected rejected response body to be closed")
	}
}

func TestAPIClientBoundsControlResponses(t *testing.T) {
	payload := `{"status":"` + strings.Repeat("x", maxAPIResponseBytes) + `"}`
	server := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			_, _ = w.Write([]byte(payload))
		}),
	)
	defer server.Close()
	viper.Set("server-url", server.URL)
	t.Cleanup(viper.Reset)
	t.Setenv("REANA_INSECURE", "true")

	api, err := ControlAPIClient("token")
	if err != nil {
		t.Fatal(err)
	}
	params := operations.NewGetWorkflowStatusParams().
		WithWorkflowIDOrName("analysis")
	_, err = api.Operations.GetWorkflowStatus(params, nil)
	if err == nil ||
		!strings.Contains(err.Error(), ErrResponseTooLarge.Error()) {
		t.Fatalf("expected bounded response error, got %v", err)
	}
}
