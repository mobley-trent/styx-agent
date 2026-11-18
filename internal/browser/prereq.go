package browser

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// PinnedChromiumVersion is the browser build the harness supports (§3.1). It is
// a declared prerequisite, like the operator's `ssh` client for ssh_logs: the
// harness resolves a Chromium binary and refuses a different major version
// rather than driving a browser its launch flags and CDP calls were not written
// for.
const PinnedChromiumVersion = "156"

// ChromiumExeEnv names a Chromium binary explicitly. It is checked before the
// PATH candidates, so an operator with a pinned build outside PATH can say so.
const ChromiumExeEnv = "STYX_CHROMIUM"

// chromiumCandidates are the PATH names a Chromium build commonly carries.
var chromiumCandidates = []string{
	"chromium",
	"chromium-browser",
	"google-chrome",
	"google-chrome-stable",
}

// versionPattern picks the version out of a `--version` line: "Chromium
// 156.0.8078.47 snap" and "Google Chrome 156.0.7444.175" both match.
var versionPattern = regexp.MustCompile(`(?i)\b(\d+\.\d+(?:\.\d+){0,3})\b`)

// Binary is a resolved browser build: the executable and the version it
// reported.
type Binary struct {
	Path    string
	Version string
}

// Major is the binary's major version.
func (b Binary) Major() string { return major(b.Version) }

// ResolveOptions are the prerequisite check's seams. Every one has a production
// default, and tests pin them so no test depends on the host's browsers.
type ResolveOptions struct {
	// Env reads an environment variable; nil means os.Getenv.
	Env func(string) string
	// LookPath resolves a PATH name; nil means exec.LookPath.
	LookPath func(string) (string, error)
	// Version reports a binary's `--version` output; nil runs it.
	Version func(ctx context.Context, path string) (string, error)
}

// Resolve finds the pinned Chromium build. A binary named by STYX_CHROMIUM is
// the only candidate; otherwise the PATH candidates are tried in order and the
// first one at the pinned major version wins. Absent, unrunnable, or
// wrong-version builds are ErrPrerequisite naming the prerequisite and the
// pinned version — never a fallback to whatever browser happens to exist.
func Resolve(ctx context.Context, opts ResolveOptions) (Binary, error) {
	if opts.Env == nil {
		opts.Env = os.Getenv
	}
	if opts.LookPath == nil {
		opts.LookPath = exec.LookPath
	}
	if opts.Version == nil {
		opts.Version = runVersion
	}

	type found struct {
		path    string
		version string
		err     error
	}
	var tried []found

	if named := strings.TrimSpace(opts.Env(ChromiumExeEnv)); named != "" {
		version, err := opts.Version(ctx, named)
		if err != nil {
			return Binary{}, fmt.Errorf("%w: %s=%s is not a runnable Chromium: %w",
				ErrPrerequisite, ChromiumExeEnv, named, err)
		}
		tried = append(tried, found{path: named, version: version})
	} else {
		for _, name := range chromiumCandidates {
			path, err := opts.LookPath(name)
			if err != nil || path == "" {
				continue
			}
			version, verr := opts.Version(ctx, path)
			tried = append(tried, found{path: path, version: version, err: verr})
		}
	}

	if len(tried) == 0 {
		return Binary{}, fmt.Errorf("%w: no Chromium binary found (looked for %s on PATH); install Chromium %s, or set %s to its path",
			ErrPrerequisite, strings.Join(chromiumCandidates, ", "), PinnedChromiumVersion, ChromiumExeEnv)
	}

	for _, candidate := range tried {
		if candidate.err != nil {
			continue
		}
		version := parseVersion(candidate.version)
		if version == "" {
			continue
		}
		if major(version) == PinnedChromiumVersion {
			return Binary{Path: candidate.path, Version: version}, nil
		}
	}

	var details []string
	for _, candidate := range tried {
		switch {
		case candidate.err != nil:
			details = append(details, fmt.Sprintf("%s: %v", candidate.path, candidate.err))
		case parseVersion(candidate.version) == "":
			details = append(details, fmt.Sprintf("%s: no version in %q", candidate.path, strings.TrimSpace(candidate.version)))
		default:
			details = append(details, fmt.Sprintf("%s is %s", candidate.path, parseVersion(candidate.version)))
		}
	}
	return Binary{}, fmt.Errorf("%w: want Chromium %s.x (found %s); install the pinned build rather than driving a different one",
		ErrPrerequisite, PinnedChromiumVersion, strings.Join(details, "; "))
}

// runVersion runs the binary's `--version` and returns its output.
//
//nolint:gosec // the path is a resolved browser binary, never model input.
func runVersion(ctx context.Context, path string) (string, error) {
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s --version: %w", path, err)
	}
	version := parseVersion(string(out))
	if version == "" {
		return "", fmt.Errorf("%s --version printed no version", path)
	}
	return version, nil
}

// parseVersion extracts the first version-shaped token from a `--version` line.
func parseVersion(raw string) string {
	match := versionPattern.FindStringSubmatch(raw)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

// major is a version's major component.
func major(version string) string {
	first, _, _ := strings.Cut(version, ".")
	return first
}
