package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		version   string
		exitCode  int
		wantUsage bool
		wantOut   string
		wantErr   string
	}{
		{
			name:      "help flag prints usage to stdout and exits 0",
			args:      []string{"styx", "--help"},
			version:   "v0.1.0",
			wantUsage: true,
			wantOut:   "Usage: styx",
		},
		{
			name:      "h shorthand behaves like help",
			args:      []string{"styx", "-h"},
			version:   "v0.1.0",
			wantUsage: true,
			wantOut:   "Usage: styx",
		},
		{
			name:    "version flag prints version line",
			args:    []string{"styx", "--version"},
			version: "v9.9.9-test",
			wantOut: "styx v9.9.9-test",
		},
		{
			name:      "no args prints usage",
			args:      []string{"styx"},
			version:   "v0.1.0",
			wantUsage: true,
			wantOut:   "Usage: styx",
		},
		{
			name:      "unknown flag fails with usage on stderr and exit 2",
			args:      []string{"styx", "--bogus"},
			version:   "v0.1.0",
			wantUsage: true,
			wantErr:   `unknown flag or command "--bogus"`,
			exitCode:  2,
		},
		{
			name:     "engagement flag is explicitly not implemented yet",
			args:     []string{"styx", "--engagement", "engagement.yaml"},
			version:  "v0.1.0",
			wantErr:  "not available in this scaffold",
			exitCode: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := run(tt.args, tt.version)
			if code != tt.exitCode {
				t.Fatalf("exit code = %d, want %d", code, tt.exitCode)
			}
			if tt.wantUsage && !strings.Contains(stdout+stderr, "Usage: styx") {
				t.Errorf("output does not contain usage: stdout=%q stderr=%q", stdout, stderr)
			}
			if tt.wantOut != "" && !strings.Contains(stdout, tt.wantOut) {
				t.Errorf("stdout %q does not contain %q", stdout, tt.wantOut)
			}
			if tt.wantErr != "" && !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("stderr %q does not contain %q", stderr, tt.wantErr)
			}
		})
	}
}

func TestVersionFallback(t *testing.T) {
	// The unit test binary carries no VCS stamping; version must fall back to dev.
	if got := moduleVersion(); got != "dev" {
		t.Errorf("moduleVersion() = %q, want %q", got, "dev")
	}
}

func TestVersionOverrideWins(t *testing.T) {
	// The release ldflags stamp takes precedence over build info.
	old := versionOverride
	defer func() { versionOverride = old }()
	versionOverride = "v7.7.7"
	if got := moduleVersion(); got != "v7.7.7" {
		t.Errorf("moduleVersion() = %q, want %q", got, "v7.7.7")
	}
}

func TestModuleVersionFrom(t *testing.T) {
	tests := []struct {
		name string
		main debug.Module
		want string
	}{
		{name: "stamped version passes through", main: debug.Module{Version: "v1.2.3"}, want: "v1.2.3"},
		{name: "devel placeholder maps to dev", main: debug.Module{Version: "(devel)"}, want: "dev"},
		{name: "empty version maps to dev", main: debug.Module{Version: ""}, want: "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := moduleVersionFrom(&debug.BuildInfo{Main: tt.main}); got != tt.want {
				t.Errorf("moduleVersionFrom() = %q, want %q", got, tt.want)
			}
		})
	}
}
