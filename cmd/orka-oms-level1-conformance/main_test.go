/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunRequiresEndpointAndToken(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr, func(string) string { return "" }); code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--endpoint is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code := run(
		[]string{"--endpoint", "https://oms.example"},
		&stdout, &stderr, func(string) string { return "" },
	)
	if code != 2 {
		t.Fatalf("run() without token = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "ORKA_OMS_BEARER_TOKEN is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
