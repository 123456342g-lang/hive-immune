package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunPrintsFramesAndSummary(t *testing.T) {
	var out bytes.Buffer

	if err := run([]string{"-ticks", "12", "-every", "10"}, &out); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"tick 0", "tick 10", "tick 11", "legend:", "first detection"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestRunSummaryOnly(t *testing.T) {
	var out bytes.Buffer

	if err := run([]string{"-every", "0"}, &out); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(out.String(), "legend:") || !strings.Contains(out.String(), "reputation") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
}

func TestRunRejectsBadInput(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{{"-malicious", "1.5"}, {"-no-such-flag"}} {
		if err := run(args, &out); err == nil {
			t.Errorf("args %v should fail", args)
		}
	}
}
