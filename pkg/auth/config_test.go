/*
This file is part of REANA.
Copyright (C) 2026 CERN.

REANA is free software; you can redistribute it and/or modify it
under the terms of the MIT License; see LICENSE file for more details.
*/

package auth

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"

	log "github.com/sirupsen/logrus"
)

func captureInsecureWarning(t *testing.T) *bytes.Buffer {
	t.Helper()
	output := &bytes.Buffer{}
	logger := log.StandardLogger()
	previousOutput := logger.Out
	logger.SetOutput(output)
	insecureWarningOnce = sync.Once{}
	t.Cleanup(func() {
		logger.SetOutput(previousOutput)
		insecureWarningOnce = sync.Once{}
	})
	return output
}

func TestNewHTTPClientWarnsOnceForInsecureTLS(t *testing.T) {
	output := captureInsecureWarning(t)
	t.Setenv(insecureEnv, "true")
	t.Setenv(caCertsEnv, "")

	if _, err := NewHTTPClient(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHTTPClient(); err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(output.String(), "disabled by REANA_INSECURE"); count != 1 {
		t.Fatalf("warning count = %d, output = %q", count, output.String())
	}
}

func TestNewHTTPClientKeepsFalseAndCABundlePrecedenceSilent(t *testing.T) {
	output := captureInsecureWarning(t)
	t.Setenv(insecureEnv, "false")
	if _, err := NewHTTPClient(); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("false setting warned: %q", output.String())
	}

	insecureWarningOnce = sync.Once{}
	t.Setenv(insecureEnv, "true")
	caPath := t.TempDir() + "/invalid-ca.pem"
	if err := os.WriteFile(caPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(caCertsEnv, caPath)
	if _, err := NewHTTPClient(); err == nil {
		t.Fatal("invalid CA bundle unexpectedly accepted")
	}
	if output.Len() != 0 {
		t.Fatalf("CA precedence emitted insecure warning: %q", output.String())
	}
}
