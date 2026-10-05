package main

import (
	"context"
	"errors"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/app"
	"github.com/mobley-trent/styx-agent/internal/update"
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
			name:      "unknown flag fails with usage on stderr and exit 2",
			args:      []string{"styx", "--bogus"},
			version:   "v0.1.0",
			wantUsage: true,
			wantErr:   `unknown flag or command "--bogus"`,
			exitCode:  2,
		},
		{
			name:      "missing flag value fails with usage and exit 2",
			args:      []string{"styx", "--engagement"},
			version:   "v0.1.0",
			wantUsage: true,
			wantErr:   "needs a value",
			exitCode:  2,
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

func TestRunLaunchesHarness(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantEngagement string
		wantProject    string
	}{
		{name: "no args launches in safe mode", args: []string{"styx"}},
		{
			name:           "engagement flag passes the file through the gate",
			args:           []string{"styx", "--engagement", "engagement.yaml"},
			wantEngagement: "engagement.yaml",
		},
		{
			name:           "inline flag form",
			args:           []string{"styx", "--engagement=acme.yaml", "--project", "/repo"},
			wantEngagement: "acme.yaml",
			wantProject:    "/repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got *app.Options
			previous := runApp
			runApp = func(_ context.Context, opts app.Options) error {
				got = &opts
				return nil
			}
			t.Cleanup(func() { runApp = previous })

			stdout, stderr, code := run(tt.args, "v0.1.0")
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty for a launch", stdout)
			}
			if got == nil {
				t.Fatal("the harness was never launched")
			}
			if got.Engagement != tt.wantEngagement {
				t.Errorf("engagement = %q, want %q", got.Engagement, tt.wantEngagement)
			}
			if got.ProjectDir != tt.wantProject {
				t.Errorf("project = %q, want %q", got.ProjectDir, tt.wantProject)
			}
		})
	}
}

func TestRunReportsLaunchFailure(t *testing.T) {
	previous := runApp
	runApp = func(context.Context, app.Options) error { return errors.New("refusing to start: bad engagement file") }
	t.Cleanup(func() { runApp = previous })

	_, stderr, code := run([]string{"styx"}, "v0.1.0")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "refusing to start") {
		t.Errorf("stderr = %q, want the launch failure", stderr)
	}
}

func TestRunUpdate(t *testing.T) {
	tests := []struct {
		name     string
		exe      string
		exeErr   error
		rel      update.Release
		fetchErr error
		wantOut  []string
		wantErr  string
		code     int
	}{
		{
			name:    "homebrew source prints the tap upgrade",
			exe:     "/opt/homebrew/Cellar/styx/0.1.0/bin/styx",
			rel:     update.Release{Version: "v0.2.0", URL: "https://example/rel"},
			wantOut: []string{"current: v0.1.0", "latest:  v0.2.0", "brew upgrade mobley-trent/styx/styx"},
			code:    0,
		},
		{
			name:    "unknown source points at the releases page",
			exe:     "/usr/local/bin/styx",
			rel:     update.Release{Version: "v0.1.0"},
			wantOut: []string{"already up to date"},
			code:    0,
		},
		{
			name:     "fetch failure still prints the upgrade command",
			exe:      "/home/eddy/.local/bin/styx",
			fetchErr: errors.New("offline"),
			wantOut:  []string{"curl -fsSL https://raw.githubusercontent.com/mobley-trent/styx-agent/main/install.sh | sh"},
			wantErr:  "update check failed",
			code:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pin HOME/GOPATH so install-source detection is deterministic
			// regardless of the machine running the tests.
			t.Setenv("HOME", "/home/eddy")
			t.Setenv("GOPATH", "")
			t.Setenv("GOBIN", "")
			previousExe, previousFetch := executablePath, fetchLatest
			t.Cleanup(func() { executablePath, fetchLatest = previousExe, previousFetch })
			executablePath = func() (string, error) { return tt.exe, tt.exeErr }
			fetchLatest = func(context.Context, string) (update.Release, error) {
				return tt.rel, tt.fetchErr
			}

			stdout, stderr, code := run([]string{"styx", "update"}, "v0.1.0")
			if code != tt.code {
				t.Fatalf("exit code = %d, want %d (stderr=%q)", code, tt.code, stderr)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout %q does not contain %q", stdout, want)
				}
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
