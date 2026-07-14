// This file is part of REANA.
// Copyright (C) 2026 CERN.

package cmd

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if err := os.Setenv("REANA_INSECURE", "true"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
