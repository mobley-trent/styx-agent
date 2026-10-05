// Command styx is the styx-agent harness binary.
//
// v1 is a terminal agent harness for coding plus security work: the harness
// mediates everything an untrusted model may do. This file is only the CLI
// entry point — startup wiring lives in internal/app, and each internal
// package documents its boundary rule in its doc comment.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/app"
	"github.com/mobley-trent/styx-agent/internal/update"
)

const usage = `Usage: styx [flags]
       styx update

styx-agent: a terminal agent harness for coding plus red-team, reverse-
engineering, and blue-team work, with harness-enforced dual-mode safety.

Flags:
  --engagement <file>   Activate engagement mode through the engagement gate
                        (strict validation; without it, safe mode is default)
  --project <dir>       Project root to run in (default: the working directory)
  --version             Print the styx version
  --help, -h            Show this help

Commands:
  update                Print the latest release and the upgrade command for
                        the detected install source (no self-updater)

Environment:
  DEEPSEEK_API_KEY      DeepSeek credential (required for prompts; env-only, never persisted)
  STYX_BASE_URL         Override the OpenAI-compatible model base URL

Configuration:
  ~/.config/styx/config.yaml   Global configuration
  .styx/config.yaml            Project overlay (project wins)
  STYX.md                      Project memory, loaded into the system prompt
`

// runApp is the launch seam. Tests replace it to assert the options a CLI
// invocation produces without starting a terminal program.
var runApp = app.Run

func main() {
	stdout, stderr, code := run(os.Args, moduleVersion())
	writeOut(os.Stdout, stdout)
	writeOut(os.Stderr, stderr)
	os.Exit(code)
}

func writeOut(w io.Writer, s string) {
	if s != "" {
		// Best effort: a failed stdout/stderr write has no meaningful
		// recovery in main; the exit code still carries the verdict.
		_, _ = fmt.Fprint(w, s)
	}
}

// run is the testable seam for main: argv in, stdout/stderr text and exit
// code out. It parses flags and either prints something terminal (help,
// version, an error) or launches the harness.
func run(argv []string, version string) (stdout, stderr string, exitCode int) {
	opts, err := parseArgs(argv[1:])
	if err != nil {
		return "", fmt.Sprintf("styx: %v\n\n%s\n", err, usage), 2
	}
	switch {
	case opts.help:
		return usage, "", 0
	case opts.version:
		return fmt.Sprintf("styx %s\n", version), "", 0
	case opts.update:
		return runUpdate(context.Background(), version)
	}

	if err := runApp(context.Background(), app.Options{
		Engagement:  opts.engagement,
		ProjectDir:  opts.project,
		Version:     version,
		SourceBuild: isSourceBuild(),
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
	}); err != nil {
		return "", fmt.Sprintf("styx: %v\n", err), 1
	}
	return "", "", 0
}

// runUpdate implements `styx update` (§12.3): compare the running version with
// the latest release and print the exact upgrade command for the detected
// install source. It never rewrites the binary.
func runUpdate(ctx context.Context, version string) (stdout, stderr string, exitCode int) {
	source := update.Unknown
	if exe, err := executablePath(); err == nil {
		source = update.DetectSource(resolveSymlinks(exe), os.Getenv)
	}

	rel, err := fetchLatest(ctx, version)
	if err != nil {
		// An unreachable endpoint must not hide the useful half of the
		// report: the operator still gets the detected source and command.
		return update.Report(version, update.Release{}, source) + "\n",
			fmt.Sprintf("styx: update check failed: %v\n", err), 1
	}
	return update.Report(version, rel, source) + "\n", "", 0
}

// fetchLatest is the `styx update` network seam. Tests replace it so no test
// touches the network.
var fetchLatest = func(ctx context.Context, current string) (update.Release, error) {
	rel, _, err := update.NewNotifier(current, nil).Check(ctx)
	return rel, err
}

// executablePath locates the running binary; tests replace it.
var executablePath = os.Executable

// resolveSymlinks follows a Homebrew-style bin symlink back to its Cellar
// target, so `styx update` detects the tap even when the binary is launched
// through /opt/homebrew/bin or /usr/local/bin. A path that cannot be resolved
// (the usual case for a plain binary) is returned unchanged.
func resolveSymlinks(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// cliOptions is the parsed command line.
type cliOptions struct {
	engagement string
	project    string
	help       bool
	version    bool
	update     bool
}

// parseArgs parses the harness's flags. It accepts both `--flag value` and
// `--flag=value`, and rejects anything else: an unrecognized flag must never
// silently start the harness in a mode the operator did not ask for.
func parseArgs(args []string) (cliOptions, error) {
	var opts cliOptions
	// pendingFlag, when non-nil, is the flag whose value is the next
	// argument: `--flag value` rather than `--flag=value`.
	var pendingFlag *string
	var pendingName string

	for _, arg := range args {
		if pendingFlag != nil {
			*pendingFlag = arg
			pendingFlag = nil
			continue
		}

		name, inline, hasInline := strings.Cut(arg, "=")
		var target *string
		switch name {
		case "--help", "-h":
			opts.help = true
			continue
		case "--version":
			opts.version = true
			continue
		case "update":
			opts.update = true
			continue
		case "--engagement":
			target = &opts.engagement
		case "--project":
			target = &opts.project
		default:
			return opts, fmt.Errorf("unknown flag or command %q", arg)
		}

		if hasInline {
			*target = inline
			continue
		}
		pendingFlag, pendingName = target, name
	}
	if pendingFlag != nil {
		return opts, fmt.Errorf("flag %s needs a value", pendingName)
	}
	return opts, nil
}

// versionOverride is stamped at release build time via -ldflags
// (-X main.versionOverride). Empty for regular builds, which fall back to
// VCS-stamped build info, then "dev".
var versionOverride string

// releaseBuild is stamped "1" at release build time. Its absence marks a
// source build (go build / go install), for which the update notifier is
// disabled (§12.1, §12.3).
var releaseBuild string

// isSourceBuild reports whether this binary was built from source rather than
// shipped as a release artifact.
func isSourceBuild() bool { return releaseBuild == "" }

// moduleVersion reports the version for --version output. Release binaries
// are stamped by goreleaser; unstamped builds report "dev".
func moduleVersion() string {
	if versionOverride != "" {
		return versionOverride
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	return moduleVersionFrom(info)
}

// moduleVersionFrom extracts the version from build info, mapping the
// placeholder "(devel)" — what `go install` and local builds report — to "dev".
func moduleVersionFrom(info *debug.BuildInfo) string {
	v := info.Main.Version
	if v == "" || v == "(devel)" {
		return "dev"
	}
	return v
}
