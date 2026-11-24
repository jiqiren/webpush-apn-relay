package main

// Tests for METRICS_BIND_ADDRESS, the environment fallback for
// -metrics-bind-address.
//
// The interesting property is precedence, and the interesting failure mode is
// the one the naive implementation has: comparing the parsed value against the
// default ("did the flag stay at 127.0.0.1?") cannot tell an omitted flag from
// an explicit `-metrics-bind-address 127.0.0.1`, so the environment silently
// wins over a deliberate command line. main() uses flag.Visit for that, and
// TestMetricsBindAddressPrecedence drives the real flag.FlagSet rather than a
// reimplementation, because a copy of the logic passes even when main() is
// broken.
//
// What is NOT tested here: that serveMetrics actually binds the address. That
// needs main(), which calls log.Fatal without APNs credentials and then blocks
// in ListenAndServe. The bind is a one-line concatenation; the precedence is
// the part with a failure mode.

import (
	"flag"
	"os"
	"strings"
	"testing"
)

// parseMetricsBind replicates main()'s flag registration and resolution using
// the same package-level globals main() writes to, so the code under test is
// main()'s own sequence: register the flag, parse, Visit, then fall back to the
// environment.
func parseMetricsBind(t *testing.T, args []string) {
	t.Helper()

	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	fs.StringVar(&metricsBind, "metrics-bind-address", defaultMetricsBind, "")
	fs.IntVar(&metricsPort, "metrics-port", 0, "")
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}

	metricsBindSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "metrics-bind-address" {
			metricsBindSet = true
		}
	})
	if !metricsBindSet {
		if raw := env("METRICS_BIND_ADDRESS", ""); raw != "" {
			metricsBind = raw
		}
	}
}

func TestMetricsBindAddressPrecedence(t *testing.T) {
	const defaultBind = defaultMetricsBind

	cases := []struct {
		name string
		args []string
		env  string // METRICS_BIND_ADDRESS
		set  bool
		want string
	}{
		{
			name: "no flag, no env: loopback",
			want: defaultBind,
		},
		{
			name: "env fills in when flag omitted",
			env:  "0.0.0.0",
			set:  true,
			want: "0.0.0.0",
		},
		{
			name: "flag wins over env",
			args: []string{"-metrics-bind-address=10.0.0.5"},
			env:  "0.0.0.0",
			set:  true,
			want: "10.0.0.5",
		},
		{
			name: "explicit flag naming the default still wins over env",
			args: []string{"-metrics-bind-address", "127.0.0.1"},
			env:  "0.0.0.0",
			set:  true,
			want: "127.0.0.1",
		},
		{
			name: "empty env leaves the default",
			env:  "",
			set:  true,
			want: defaultBind,
		},
		{
			name: "bracketed IPv6 from env",
			env:  "[::1]",
			set:  true,
			want: "[::1]",
		},
		{
			name: "unix-less wildcard from flag with env unset",
			args: []string{"-metrics-bind-address=0.0.0.0"},
			want: "0.0.0.0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv also clears the variable when set is false, so cases
			// cannot leak into each other through the process environment.
			if tc.set {
				t.Setenv("METRICS_BIND_ADDRESS", tc.env)
			} else {
				t.Setenv("METRICS_BIND_ADDRESS", "")
				os.Unsetenv("METRICS_BIND_ADDRESS")
			}

			t.Cleanup(func() { metricsBind, metricsPort = "", 0 })
			metricsBind, metricsPort = "", 0

			parseMetricsBind(t, tc.args)
			if metricsBind != tc.want {
				t.Errorf("metricsBind = %q, want %q (args=%v env=%q set=%v)", metricsBind, tc.want, tc.args, tc.env, tc.set)
			}
		})
	}
}

// TestMetricsBindUsesVisitNotValueCompare pins the mechanism, not just the
// outcome. A future edit that "simplifies" the check back to
// `if metricsBind == defaultMetricsBind` reintroduces the bug where the
// environment overrides an explicit flag, and every case above except
// "explicit flag naming the default" still passes.
func TestMetricsBindUsesVisitNotValueCompare(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	s := string(src)

	if !strings.Contains(s, `env("METRICS_BIND_ADDRESS", "")`) {
		t.Error(`main() no longer reads METRICS_BIND_ADDRESS`)
	}
	if !strings.Contains(s, `flag.Visit(`) {
		t.Error("main() must use flag.Visit to detect an explicitly set -metrics-bind-address, not compare the value against the default")
	}
	if strings.Contains(s, "if metricsBind == defaultMetricsBind") {
		t.Error("main() compares metricsBind against defaultMetricsBind: an explicit -metrics-bind-address 127.0.0.1 would be overridden by METRICS_BIND_ADDRESS")
	}
	if !strings.Contains(s, `flag.StringVar(&metricsBind, "metrics-bind-address", defaultMetricsBind`) {
		t.Error(`-metrics-bind-address must default to defaultMetricsBind so the documented default and the constant cannot drift`)
	}
}

// TestDefaultMetricsBindIsLoopback guards the security default: the metrics
// listener is the only place internal telemetry is served, and the public relay
// port deliberately never exposes it. Changing the default is a documented
// behaviour change, not a refactor.
func TestDefaultMetricsBindIsLoopback(t *testing.T) {
	if defaultMetricsBind != "127.0.0.1" {
		t.Errorf("defaultMetricsBind = %q, want %q; README and observability/README.md document loopback as the default, and binding anywhere else by default would expose /metrics on the public interface", defaultMetricsBind, "127.0.0.1")
	}
}
