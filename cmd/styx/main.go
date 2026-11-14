// Command styx is the styx-agent harness binary.
//
// v1 is a terminal agent harness for coding plus security work: the harness
// mediates everything an untrusted model may do. This file is only the CLI
// entry point — startup wiring lives in internal/app, and each internal
// package documents its boundary rule in its doc comment.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/app"
	"github.com/mobley-trent/styx-agent/internal/findingsexport"
	"github.com/mobley-trent/styx-agent/internal/sandbox"
	"github.com/mobley-trent/styx-agent/internal/update"
)

const usage = `Usage: styx [flags]
       styx update

styx-agent: a terminal agent harness for coding plus red-team, reverse-
engineering, and blue-team work, with harness-enforced dual-mode safety.

Flags:
  -n, --non-interactive <task>
                        Run exactly one task in one turn with no terminal:
                        the answer goes to stdout, the transcript to stderr.
                        Prompts cannot be asked, so they are denied
                        (docs/headless-ci.md)
  --out <dir>           Write the findings export (vulnerabilities.json,
                        vulnerabilities.csv, findings.sarif) into <dir> after
                        a non-interactive run; needs -n
                        (docs/findings-export.md)
  --fail-on <severity>  Fail a non-interactive run when a gated finding is at
                        or above <severity>: critical, high, medium, low, or
                        info; needs -n (docs/headless-ci.md)
  --max-budget <usd>    Cap the run's model spend at <usd>: a positive amount
                        with at most four decimals (2.50, 0.0025). Once the
                        cap is spent the run refuses its next model turn and
                        exits 1; needs -n (docs/budget-cap.md)
  --allow-unverified-image
                        Run a digest-pinned image that is not the signed
                        sandbox image, without verifying it: asks once at
                        startup and records the waiver in the audit trail
                        (docs/sandbox-image.md)
  --engagement <file>   Activate engagement mode through the engagement gate
                        (strict validation; without it, safe mode is default)
  --project <dir>       Project root to run in (default: the working directory)
  --version             Print the styx version
  --help, -h            Show this help

Commands:
  update                Print the latest release and the upgrade command for
                        the detected install source (no self-updater)

Exit codes:
  0  clean — the run finished and no gate failed it
  1  broken — a turn error, the turn cap, or a signal
  2  usage error
  3  gate failed — a gated finding is at or above --fail-on
  4  run not clean — a prompt was denied with no operator

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
		// The pinned sandbox digest rides the version line so "what will this
		// binary run" is answerable without opening the source
		// (docs/sandbox-image.md §4.4).
		return fmt.Sprintf("styx %s\nsandbox image %s\n", version, sandbox.ImageRef), "", 0
	case opts.update:
		return runUpdate(context.Background(), version)
	}

	if err := runApp(context.Background(), app.Options{
		Engagement:           opts.engagement,
		ProjectDir:           opts.project,
		Version:              version,
		SourceBuild:          isSourceBuild(),
		NonInteractive:       opts.nonInteractive,
		Task:                 opts.task,
		OutDir:               opts.out,
		FailOn:               opts.failOn,
		MaxBudget:            opts.maxBudgetUSD,
		AllowUnverifiedImage: opts.allowUnverifiedImage,
		Stdin:                os.Stdin,
		Stdout:               os.Stdout,
		Stderr:               os.Stderr,
	}); err != nil {
		// A finished run's verdict is not a broken run (§8.1): the runner has
		// already printed the line that explains it, so only the code changes.
		if code, ok := app.VerdictCode(err); ok {
			return "", "", code
		}
		// A run the harness refused to configure — an image it will not trust,
		// a flag that needs a digest — is a usage error, not a broken run.
		if app.IsUsageError(err) {
			return "", fmt.Sprintf("styx: %v\n\n%s\n", err, usage), 2
		}
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
	engagement     string
	project        string
	nonInteractive bool
	// task is the single positional argument of a non-interactive run (§2).
	task string
	// out is the findings export directory (docs/findings-export.md §5),
	// and outSet records that the flag was given: an empty value is a usage
	// error, never an absent flag.
	out    string
	outSet bool
	// failOn is the severity gate's threshold (docs/headless-ci.md §8), and
	// failOnSet records that the flag was given, so an empty value is a usage
	// error rather than no gate.
	failOn    string
	failOnSet bool
	// maxBudget is the budget cap's value as given, and maxBudgetUSD its
	// parsed amount (docs/budget-cap.md §8). maxBudgetSet records that the
	// flag was given, so an empty value is a usage error rather than no cap.
	maxBudget    string
	maxBudgetSet bool
	maxBudgetUSD float64
	// allowUnverifiedImage waives image signature verification for an
	// operator-pinned digest (docs/sandbox-image.md §7).
	allowUnverifiedImage bool
	// positional collects the bare arguments; whether they are a task or a
	// stray command is decided once -n is known.
	positional []string
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
		case "-n", "--non-interactive":
			opts.nonInteractive = true
			continue
		case "--allow-unverified-image":
			opts.allowUnverifiedImage = true
			continue
		case "--engagement":
			target = &opts.engagement
		case "--project":
			target = &opts.project
		case "--out":
			target = &opts.out
			opts.outSet = true
		case "--fail-on":
			target = &opts.failOn
			opts.failOnSet = true
		case "--max-budget":
			target = &opts.maxBudget
			opts.maxBudgetSet = true
		default:
			// A bare argument is the task of a non-interactive run, and a stray
			// word anywhere else. Which one it is is decided once every flag
			// has been seen, since -n may follow the task. Anything with a
			// leading dash is a flag this build does not know, never a task.
			if strings.HasPrefix(arg, "-") {
				return opts, fmt.Errorf("unknown flag or command %q", arg)
			}
			opts.positional = append(opts.positional, arg)
			continue
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

	// --out is CI-shaped: given without -n it is a usage error (§2.2), never
	// silently ignored.
	if opts.outSet {
		opts.out = strings.TrimSpace(opts.out)
		if opts.out == "" {
			return opts, errors.New("--out needs a directory")
		}
		if !opts.nonInteractive {
			return opts, errors.New("--out needs a non-interactive run (-n)")
		}
	}

	// --fail-on is CI-shaped too (§2.2, §8.4): its value must be one of the five
	// store severities, and given without -n it is a usage error rather than a
	// silently ignored gate.
	if opts.failOnSet {
		opts.failOn = strings.TrimSpace(opts.failOn)
		if opts.failOn == "" {
			return opts, errors.New("--fail-on needs a severity")
		}
		if _, ok := findingsexport.Threshold(opts.failOn); !ok {
			return opts, fmt.Errorf("--fail-on %q: want critical, high, medium, low, or info", opts.failOn)
		}
		if !opts.nonInteractive {
			return opts, errors.New("--fail-on needs a non-interactive run (-n)")
		}
	}

	// --max-budget is CI-shaped too (§2.2, docs/budget-cap.md §8): a positive
	// plain decimal with at most four fractional digits, and a usage error
	// rather than a silently ignored ceiling without -n.
	if opts.maxBudgetSet {
		amount, err := parseUSD(opts.maxBudget)
		if err != nil {
			return opts, fmt.Errorf("--max-budget %q: %w", opts.maxBudget, err)
		}
		if !opts.nonInteractive {
			return opts, errors.New("--max-budget needs a non-interactive run (-n)")
		}
		opts.maxBudgetUSD = amount
	}

	if !opts.nonInteractive {
		if len(opts.positional) > 0 {
			return opts, fmt.Errorf("unknown flag or command %q", opts.positional[0])
		}
		return opts, nil
	}

	// With -n, a bare argument is always the task, never a command (§2): a
	// command combined with a flag that cannot honour it is a usage error, like
	// --version -n.
	switch {
	case opts.update:
		return opts, errors.New("-n cannot be combined with the update command")
	case opts.version:
		return opts, errors.New("-n cannot be combined with --version")
	case opts.help:
		return opts, errors.New("-n cannot be combined with --help")
	case len(opts.positional) == 0:
		return opts, errors.New("-n needs one task")
	case len(opts.positional) > 1:
		return opts, fmt.Errorf("-n takes exactly one task; got %d", len(opts.positional))
	}
	opts.task = strings.TrimSpace(opts.positional[0])
	if opts.task == "" {
		return opts, errors.New("-n needs one task")
	}
	return opts, nil
}

// errBadUSD is the budget cap's one usage error: the value is not a positive
// plain decimal with at most four fractional digits.
var errBadUSD = errors.New("want a positive USD amount with at most four decimals (2.50, 0.0025)")

// parseUSD parses the budget cap's value (docs/budget-cap.md §8). It refuses
// an empty value, a zero, a sign, an exponent, and more than four fractional
// digits rather than reinterpreting them: 0 is not "no budget", it is a run
// that may not make a single model call, and 1e3 is an amount nobody wrote the
// way a dollar figure is written.
func parseUSD(s string) (float64, error) {
	s = strings.TrimSpace(s)
	whole, frac, hasFrac := strings.Cut(s, ".")
	if whole == "" || !allDigits(whole) {
		return 0, errBadUSD
	}
	if hasFrac && (frac == "" || len(frac) > 4 || !allDigits(frac)) {
		return 0, errBadUSD
	}
	amount, err := strconv.ParseFloat(s, 64)
	if err != nil || amount <= 0 {
		return 0, errBadUSD
	}
	return amount, nil
}

// allDigits reports whether s is one or more ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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
