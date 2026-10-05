package update

import (
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in   string
		want Version
		ok   bool
	}{
		{"v1.2.3", Version{1, 2, 3, ""}, true},
		{"1.2.3", Version{1, 2, 3, ""}, true},
		{"v1.2", Version{1, 2, 0, ""}, true},
		{"v2", Version{2, 0, 0, ""}, true},
		{"v0.1.0-rc1", Version{0, 1, 0, "rc1"}, true},
		{"v1.2.3+build.5", Version{1, 2, 3, ""}, true},
		{"v1.2.3-rc1+build.5", Version{1, 2, 3, "rc1"}, true},
		{"dev", Version{}, false},
		{"", Version{}, false},
		{"vx.y.z", Version{}, false},
		{"v1.x.3", Version{}, false},
	}
	for _, tt := range tests {
		got, ok := ParseVersion(tt.in)
		if ok != tt.ok || got != tt.want {
			t.Errorf("ParseVersion(%q) = (%v, %v), want (%v, %v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"v1.2.3", "v1.2.3", 0},
		{"v1.2.3", "v1.2.4", -1},
		{"v1.3.0", "v1.2.9", 1},
		{"v2.0.0", "v1.9.9", 1},
		{"v1.2.3-rc1", "v1.2.3", -1},
		{"v1.2.3", "v1.2.3-rc1", 1},
		{"v1.2.3-rc1", "v1.2.3-rc2", -1},
	}
	for _, tt := range tests {
		a, _ := ParseVersion(tt.a)
		b, _ := ParseVersion(tt.b)
		if got := a.Compare(b); got != tt.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestDetectSource(t *testing.T) {
	env := func(vals map[string]string) func(string) string {
		return func(k string) string { return vals[k] }
	}
	tests := []struct {
		name string
		path string
		env  map[string]string
		want Source
	}{
		{"homebrew arm64", "/opt/homebrew/Cellar/styx/0.1.0/bin/styx", nil, Homebrew},
		{"homebrew intel", "/usr/local/Cellar/styx/0.1.0/bin/styx", nil, Homebrew},
		{"linuxbrew", "/home/linuxbrew/.linuxbrew/Cellar/styx/0.1.0/bin/styx", nil, Homebrew},
		{"install script", "/home/eddy/.local/bin/styx", map[string]string{"HOME": "/home/eddy"}, InstallScript},
		{"gobin", "/opt/gobin/styx", map[string]string{"GOBIN": "/opt/gobin"}, GoInstall},
		{"gopath default", "/home/eddy/go/bin/styx", map[string]string{"HOME": "/home/eddy"}, GoInstall},
		{"gopath custom", "/data/go/bin/styx", map[string]string{"GOPATH": "/data/go"}, GoInstall},
		{"manual", "/usr/local/bin/styx", map[string]string{"HOME": "/home/eddy"}, Unknown},
		{"empty", "", nil, Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectSource(tt.path, env(tt.env)); got != tt.want {
				t.Errorf("DetectSource(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestUpgradeCommand(t *testing.T) {
	for _, tt := range []struct {
		src  Source
		want string
	}{
		{Homebrew, "brew upgrade mobley-trent/styx/styx"},
		{InstallScript, "curl -fsSL " + InstallScriptURL + " | sh"},
		{GoInstall, "go install github.com/mobley-trent/styx-agent/cmd/styx@latest"},
		{Archive, "download the latest release from " + ReleasesPage},
		{Unknown, "download the latest release from " + ReleasesPage},
	} {
		if got := UpgradeCommand(tt.src); got != tt.want {
			t.Errorf("UpgradeCommand(%q) = %q, want %q", tt.src, got, tt.want)
		}
	}
}

func TestIsSourceBuild(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want bool
	}{
		{"", true},
		{"dev", true},
		{"(devel)", true},
		{"v0.1.0", false},
		{"v1.2.3", false},
	} {
		if got := IsSourceBuild(tt.in); got != tt.want {
			t.Errorf("IsSourceBuild(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestNewerAvailable(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{"v0.1.0", "v0.2.0", true},
		{"v0.2.0", "v0.2.0", false},
		{"v0.2.0", "v0.1.0", false},
		{"dev", "v0.2.0", false},
		{"v0.1.0", "not-a-version", false},
	}
	for _, tt := range tests {
		if got := NewerAvailable(tt.current, Release{Version: tt.latest}); got != tt.want {
			t.Errorf("NewerAvailable(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}

func TestGateActive(t *testing.T) {
	tests := []struct {
		name string
		gate Gate
		env  map[string]string
		want bool
	}{
		{"enabled", Gate{ConfigEnabled: true}, nil, true},
		{"config opt-out", Gate{ConfigEnabled: false}, nil, false},
		{"source build", Gate{ConfigEnabled: true, SourceBuild: true}, nil, false},
		{"engagement", Gate{ConfigEnabled: true, Engagement: true}, nil, false},
		{"env opt-out 1", Gate{ConfigEnabled: true}, map[string]string{NoNotifierEnv: "1"}, false},
		{"env opt-out true", Gate{ConfigEnabled: true}, map[string]string{NoNotifierEnv: "true"}, false},
		{"env not opt-out 0", Gate{ConfigEnabled: true}, map[string]string{NoNotifierEnv: "0"}, true},
		{"env empty", Gate{ConfigEnabled: true}, map[string]string{NoNotifierEnv: ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gate := tt.gate
			gate.Env = func(k string) string { return tt.env[k] }
			if got := gate.Active(); got != tt.want {
				t.Errorf("Gate.Active() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReport(t *testing.T) {
	got := Report("v0.1.0", Release{Version: "v0.2.0", URL: "https://example/release"}, Homebrew)
	for _, want := range []string{"current: v0.1.0", "latest:  v0.2.0", "Homebrew tap", "brew upgrade mobley-trent/styx/styx", "https://example/release"} {
		if !strings.Contains(got, want) {
			t.Errorf("Report() = %q, missing %q", got, want)
		}
	}

	got = Report("v0.2.0", Release{Version: "v0.2.0"}, InstallScript)
	if !strings.Contains(got, "already up to date") {
		t.Errorf("Report() = %q, want up-to-date notice", got)
	}

	// An unreachable endpoint carries no release: the report must not claim the
	// binary is up to date.
	got = Report("v0.2.0", Release{}, InstallScript)
	if strings.Contains(got, "already up to date") {
		t.Errorf("Report() with no release = %q, want no up-to-date claim", got)
	}
}
