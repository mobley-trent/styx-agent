// Command styx is the styx-agent harness binary.
//
// v1 is a terminal agent harness for coding plus security work: the harness
// mediates everything an untrusted model may do. This file is only the CLI
// entry point — startup wiring lives in internal/app, and each internal
// package documents its boundary rule in its doc comment.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

const usage = `Usage: styx [flags]

styx-agent: a terminal agent harness for coding plus red-team, reverse-
engineering, and blue-team work, with harness-enforced dual-mode safety.

Flags:
  --engagement <file>   Activate engagement mode through the engagement gate
                        (strict validation; without it, safe mode is default)
  --version             Print the styx version
  --help, -h            Show this help

This scaffold builds the module skeleton (docs/spec.md §2); the agent loop,
TUI, policy engine, and tooling land in subsequent tickets.
`

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
// code out. main performs no branching of its own.
func run(argv []string, version string) (stdout, stderr string, exitCode int) {
	args := argv[1:]
	for _, arg := range args {
		switch arg {
		case "--help", "-h":
			return usage, "", 0
		case "--version":
			return fmt.Sprintf("styx %s\n", version), "", 0
		case "--engagement":
			return "", "styx: --engagement is not available in this scaffold; the\nengagement gate lands in a later ticket (docs/spec.md §7).\n", 2
		default:
			return "", fmt.Sprintf("styx: unknown flag or command %q\n\n%s\n", arg, usage), 2
		}
	}
	return usage, "", 0
}

// versionOverride is stamped at release build time via -ldflags
// (-X main.versionOverride). Empty for regular builds, which fall back to
// VCS-stamped build info, then "dev".
var versionOverride string

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
