package browser

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// pinVersion is a version at the pinned major.
var pinVersion = PinnedChromiumVersion + ".0.8078.47"

func TestResolveNamedBinary(t *testing.T) {
	options := ResolveOptions{
		Env: func(key string) string {
			if key == ChromiumExeEnv {
				return "/opt/chromium"
			}
			return ""
		},
		LookPath: func(string) (string, error) { return "", errors.New("not found") },
		Version: func(_ context.Context, path string) (string, error) {
			if path != "/opt/chromium" {
				t.Fatalf("Version(%q), want the named binary", path)
			}
			return "Chromium " + pinVersion + " snap", nil
		},
	}
	binary, err := Resolve(context.Background(), options)
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}
	if binary.Path != "/opt/chromium" || binary.Major() != PinnedChromiumVersion {
		t.Errorf("Resolve() = %+v, want /opt/chromium at major %s", binary, PinnedChromiumVersion)
	}
}

func TestResolvePrefersThePinnedCandidate(t *testing.T) {
	options := ResolveOptions{
		Env: func(string) string { return "" },
		LookPath: func(name string) (string, error) {
			switch name {
			case "chromium":
				return "/usr/bin/old-chromium", nil
			case "google-chrome":
				return "/usr/bin/pinned-chrome", nil
			}
			return "", errors.New("not found")
		},
		Version: func(_ context.Context, path string) (string, error) {
			if path == "/usr/bin/old-chromium" {
				return "Chromium 131.0.6778.204", nil
			}
			return "Google Chrome " + pinVersion, nil
		},
	}
	binary, err := Resolve(context.Background(), options)
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}
	if binary.Path != "/usr/bin/pinned-chrome" {
		t.Errorf("Resolve() = %+v, want the pinned candidate", binary)
	}
}

func TestResolveErrors(t *testing.T) {
	tests := []struct {
		name    string
		options ResolveOptions
		want    string
	}{
		{
			name: "absent",
			options: ResolveOptions{
				Env:      func(string) string { return "" },
				LookPath: func(string) (string, error) { return "", errors.New("not found") },
			},
			want: ChromiumExeEnv,
		},
		{
			name: "wrong version",
			options: ResolveOptions{
				Env: func(string) string { return "" },
				LookPath: func(name string) (string, error) {
					if name == "chromium" {
						return "/usr/bin/chromium", nil
					}
					return "", errors.New("not found")
				},
				Version: func(context.Context, string) (string, error) {
					return "Chromium 131.0.6778.204", nil
				},
			},
			want: "131.0.6778.204",
		},
		{
			name: "named binary is unrunnable",
			options: ResolveOptions{
				Env: func(key string) string {
					if key == ChromiumExeEnv {
						return "/missing/chromium"
					}
					return ""
				},
				Version: func(context.Context, string) (string, error) {
					return "", errors.New("no such file")
				},
			},
			want: "/missing/chromium",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Resolve(context.Background(), tt.options)
			if !errors.Is(err, ErrPrerequisite) {
				t.Fatalf("Resolve() = %v, want ErrPrerequisite", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to name %q", err, tt.want)
			}
			if !strings.Contains(err.Error(), PinnedChromiumVersion) && tt.name != "named binary is unrunnable" {
				t.Errorf("error = %v, want it to name the pinned version %s", err, PinnedChromiumVersion)
			}
		})
	}
}
