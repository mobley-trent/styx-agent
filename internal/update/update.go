package update

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Repository coordinates and the release endpoints styx knows about (§12).
const (
	// Repo is the canonical GitHub repository slug.
	Repo = "mobley-trent/styx-agent"
	// ReleasesURL is the single endpoint the notifier fetches: the latest
	// published release. Nothing else leaves the machine (§12.3).
	ReleasesURL = "https://api.github.com/repos/" + Repo + "/releases/latest"
	// ReleasesPage is the human-facing latest-release page, used as the upgrade
	// hint for install sources styx cannot upgrade in place.
	ReleasesPage = "https://github.com/" + Repo + "/releases/latest"
	// InstallScriptURL is the blessed Linux install path (§12.1): it picks the
	// architecture, verifies the checksum, and installs to ~/.local/bin.
	InstallScriptURL = "https://raw.githubusercontent.com/" + Repo + "/main/install.sh"
	// NoNotifierEnv, when set to a truthy value, opts the process out of the
	// notifier regardless of config (§12.3).
	NoNotifierEnv = "STYX_NO_UPDATE_NOTIFIER"
)

// Source is where the running binary was installed from. Detection is a
// heuristic over the executable path; an unrecognized path is reported as
// unknown rather than guessed (§12.1).
type Source string

// The install surfaces of §12.1. The blessed surfaces (Homebrew, install
// script) map to an in-place upgrade command; the rest point at the releases
// page so the operator re-installs deliberately.
const (
	// Homebrew is a macOS (or Linuxbrew) install through the blessed tap.
	Homebrew Source = "homebrew"
	// InstallScript is the blessed Linux install under ~/.local/bin.
	InstallScript Source = "install-script"
	// GoInstall is a `go install` build, which lives under GOBIN/GOPATH/bin.
	GoInstall Source = "go-install"
	// Unknown is any other install path (manual download, release archive,
	// distro package). It maps to the releases page rather than guessing at an
	// in-place upgrade.
	Unknown Source = "unknown"
)

// Label is the human-readable name for the source, used in the `styx update`
// report.
func (s Source) Label() string {
	switch s {
	case Homebrew:
		return "Homebrew tap"
	case InstallScript:
		return "install script (~/.local/bin)"
	case GoInstall:
		return "go install"
	default:
		return "unknown install path"
	}
}

// DetectSource classifies the running binary by its executable path. env reads
// environment variables (HOME, GOBIN, GOPATH); nil means os.Getenv. The
// detection is intentionally conservative: it only claims a blessed source
// when the path is unambiguous, so `styx update` never prints a command that
// would not work for the install it is running from.
func DetectSource(exePath string, env func(string) string) Source {
	if env == nil {
		env = os.Getenv
	}
	p := filepath.ToSlash(filepath.Clean(strings.TrimSpace(exePath)))
	if p == "" || p == "." {
		return Unknown
	}

	// Homebrew keeps every formula version in a Cellar directory, on both the
	// macOS prefix (/opt/homebrew, /usr/local) and Linuxbrew.
	if strings.Contains(p, "/Cellar/") || strings.Contains(p, "homebrew") {
		return Homebrew
	}

	// The blessed Linux installer writes to ~/.local/bin.
	if home := strings.TrimSpace(env("HOME")); home != "" {
		if underDir(p, filepath.ToSlash(filepath.Join(home, ".local", "bin"))) {
			return InstallScript
		}
	}

	// A `go install` binary lands in GOBIN, or GOPATH/bin (default ~/go/bin).
	if gobin := strings.TrimSpace(env("GOBIN")); gobin != "" && underDir(p, filepath.ToSlash(gobin)) {
		return GoInstall
	}
	gopath := strings.TrimSpace(env("GOPATH"))
	if gopath == "" {
		if home := strings.TrimSpace(env("HOME")); home != "" {
			gopath = filepath.Join(home, "go")
		}
	}
	if gopath != "" && underDir(p, filepath.ToSlash(filepath.Join(gopath, "bin"))) {
		return GoInstall
	}

	// Release archives are unpacked anywhere, so an unstamped build under an
	// unexpected path is reported as unknown; the upgrade hint sends the
	// operator to the releases page.
	return Unknown
}

// underDir reports whether path is dir itself or beneath it.
func underDir(path, dir string) bool {
	dir = strings.TrimSuffix(dir, "/")
	return path == dir || strings.HasPrefix(path, dir+"/")
}

// UpgradeCommand is the exact command the operator runs to upgrade an install
// of the given source (§12.3). It never rewrites the binary itself.
func UpgradeCommand(s Source) string {
	switch s {
	case Homebrew:
		return "brew upgrade mobley-trent/styx/styx"
	case InstallScript:
		return "curl -fsSL " + InstallScriptURL + " | sh"
	case GoInstall:
		return "go install github.com/" + Repo + "/cmd/styx@latest"
	default:
		return "download the latest release from " + ReleasesPage
	}
}

// Version is a parsed semantic version. styx ships on a stable-only channel
// (§12.3), but pre-release components are still parsed and ordered so a tag
// like v0.2.0-rc1 never compares above v0.2.0.
type Version struct {
	Major int
	Minor int
	Patch int
	// Pre is the pre-release identifier ("rc1" in v0.2.0-rc1), empty for a
	// stable release. Build metadata after "+" is ignored.
	Pre string
}

// ParseVersion parses a leading-v semantic version ("v1.2.3", "1.2.3",
// "v1.2.3-rc1"). It tolerates a missing minor/patch (treated as zero). A
// string with no leading integer is not a version.
func ParseVersion(s string) (Version, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	// Drop build metadata; it does not affect ordering.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	pre := ""
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}
	if s == "" {
		return Version{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		parts = parts[:3]
	}
	nums := [3]int{}
	for i, part := range parts {
		if part == "" {
			return Version{}, false
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return Version{}, false
		}
		nums[i] = n
	}
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Pre: pre}, true
}

// String renders the version with a leading v.
func (v Version) String() string {
	out := fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		out += "-" + v.Pre
	}
	return out
}

// Compare orders two versions: -1 if v < o, 0 if equal, +1 if v > o. A stable
// release outranks any pre-release of the same numbers.
func (v Version) Compare(o Version) int {
	for _, pair := range [][2]int{
		{v.Major, o.Major},
		{v.Minor, o.Minor},
		{v.Patch, o.Patch},
	} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.Pre == o.Pre:
		return 0
	case v.Pre == "":
		return 1
	case o.Pre == "":
		return -1
	case v.Pre < o.Pre:
		return -1
	default:
		return 1
	}
}

// NewerThan reports whether v is strictly newer than o.
func (v Version) NewerThan(o Version) bool { return v.Compare(o) > 0 }

// Release is the subset of the GitHub releases-latest response styx uses. The
// JSON shape is pinned here so the notifier cannot accidentally depend on a
// wider response.
type Release struct {
	// Version is the release tag ("v0.2.0").
	Version string `json:"tag_name"`
	// URL is the release's human-facing page.
	URL string `json:"html_url"`
}

// NewerAvailable reports whether another release is strictly newer than the
// current version. An unparseable current or latest version is not "newer":
// nothing is advertised on a version styx cannot order.
func NewerAvailable(current string, rel Release) bool {
	cur, ok := ParseVersion(current)
	if !ok {
		return false
	}
	latest, ok := ParseVersion(rel.Version)
	if !ok {
		return false
	}
	return latest.NewerThan(cur)
}
