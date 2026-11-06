package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

func TestResolveSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "Cellar", "styx", "0.1.0", "bin", "styx")
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "bin", "styx")
	if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if got := resolveSymlinks(link); got != target {
		t.Errorf("resolveSymlinks(symlink) = %q, want %q", got, target)
	}
	missing := filepath.Join(dir, "absent")
	if got := resolveSymlinks(missing); got != missing {
		t.Errorf("resolveSymlinks(missing) = %q, want %q", got, missing)
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

func TestNonInteractiveFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  string
		wantTask string
	}{
		{name: "missing task", args: []string{"styx", "-n"}, wantErr: "-n needs one task"},
		{name: "long flag missing task", args: []string{"styx", "--non-interactive"}, wantErr: "-n needs one task"},
		{name: "two tasks", args: []string{"styx", "-n", "one", "two"}, wantErr: "-n takes exactly one task"},
		{name: "update with -n", args: []string{"styx", "update", "-n"}, wantErr: "-n cannot be combined with the update command"},
		{name: "version with -n", args: []string{"styx", "--version", "-n"}, wantErr: "-n cannot be combined with --version"},
		{name: "unknown flag after -n is never the task", args: []string{"styx", "-n", "--bogus"}, wantErr: `unknown flag or command "--bogus"`},
		{name: "bare word without -n is not a task", args: []string{"styx", "scan"}, wantErr: `unknown flag or command "scan"`},
		{name: "task after the flag", args: []string{"styx", "-n", "scan the box"}, wantTask: "scan the box"},
		{name: "task before the flag", args: []string{"styx", "scan the box", "-n"}, wantTask: "scan the box"},
		{name: "long flag form", args: []string{"styx", "--non-interactive", "scan the box"}, wantTask: "scan the box"},
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
			if tt.wantTask == "" {
				if code != 2 {
					t.Fatalf("exit code = %d, want 2 (stderr=%q)", code, stderr)
				}
				if !strings.Contains(stderr, tt.wantErr) {
					t.Errorf("stderr = %q, want %q", stderr, tt.wantErr)
				}
				if got != nil {
					t.Errorf("the harness was launched for a usage error: %+v", got)
				}
				return
			}

			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty for a launch", stdout)
			}
			if got == nil {
				t.Fatal("the harness was never launched")
			}
			if !got.NonInteractive || got.Task != tt.wantTask {
				t.Errorf("options = {NonInteractive:%v Task:%q}, want {true %q}", got.NonInteractive, got.Task, tt.wantTask)
			}
		})
	}
}

// TestOutFlag covers docs/findings-export.md §5: --out reaches the harness, and
// given without -n it is a usage error rather than a silently ignored flag.
func TestOutFlag(t *testing.T) {
	var got *app.Options
	previous := runApp
	runApp = func(_ context.Context, opts app.Options) error {
		got = &opts
		return nil
	}
	t.Cleanup(func() { runApp = previous })

	stdout, stderr, code := run([]string{"styx", "-n", "scan", "--out", "reports"}, "v0.1.0")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty for a launch", stdout)
	}
	if got == nil || got.OutDir != "reports" {
		t.Fatalf("options = %+v, want OutDir \"reports\"", got)
	}

	// Inline form, and the flag before the task.
	got = nil
	if _, stderr, code := run([]string{"styx", "--out=out/nested", "-n", "scan"}, "v0.1.0"); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, stderr)
	}
	if got == nil || got.OutDir != "out/nested" {
		t.Fatalf("options = %+v, want OutDir \"out/nested\"", got)
	}

	for _, c := range []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "without -n", args: []string{"styx", "--out", "reports"}, wantErr: "--out needs a non-interactive run"},
		{name: "empty value", args: []string{"styx", "-n", "scan", "--out="}, wantErr: "--out needs a directory"},
		{name: "missing value", args: []string{"styx", "-n", "scan", "--out"}, wantErr: "--out needs a value"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var launched *app.Options
			runApp = func(_ context.Context, opts app.Options) error {
				launched = &opts
				return nil
			}
			t.Cleanup(func() { runApp = previous })

			_, stderr, code := run(c.args, "v0.1.0")
			if code != 2 {
				t.Fatalf("exit code = %d, want 2 (stderr=%q)", code, stderr)
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Errorf("stderr = %q, want %q", stderr, c.wantErr)
			}
			if launched != nil {
				t.Errorf("the harness was launched for a usage error: %+v", launched)
			}
		})
	}
}
