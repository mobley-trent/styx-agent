package agent

import (
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/skillpacks"
)

var update = flag.Bool("update", false, "rewrite the prompt golden snapshots")

// promptGoldenDir is the shared fixture directory (§11.3): prompt goldens are
// data, alongside transcripts.
var promptGoldenDir = filepath.Join("..", "testdata", "prompts")

// promptCases are the (mode × pack × engagement-state) combinations the
// byte-stable prefix is locked for (§11.1: "per (mode × skill pack ×
// engagement-state) combination").
func promptCases() []struct {
	name string
	in   PromptInput
} {
	return []struct {
		name string
		in   PromptInput
	}{
		{
			name: "safe",
			in:   PromptInput{Mode: policy.ModeSafe},
		},
		{
			name: "safe-with-memory",
			in: PromptInput{
				Mode:   policy.ModeSafe,
				Memory: "# STYX.md\n\nRun `make check` before committing.\n",
			},
		},
		{
			name: "safe-re",
			in: PromptInput{
				Mode:  policy.ModeSafe,
				Packs: skillpacks.Detection{REMCPConnected: true},
			},
		},
		{
			name: "safe-blue",
			in: PromptInput{
				Mode:  policy.ModeSafe,
				Packs: skillpacks.Detection{LogArtifactsOpen: true},
			},
		},
		{
			name: "engagement",
			in: PromptInput{
				Mode: policy.ModeEngagement,
				Engagement: &EngagementContext{
					Name:                 "acme-q4-redteam",
					Targets:              []string{"10.0.0.0/24", "192.0.2.44", "app.acme.example"},
					ExploitAllowed:       true,
					DestructiveForbidden: true,
					Expires:              "2026-10-15T23:59:59Z",
				},
				Memory: "# STYX.md\n\nEngagement notes go here.\n",
				Packs:  skillpacks.Detection{EngagementActive: true},
			},
		},
		{
			name: "engagement-no-memory",
			in: PromptInput{
				Mode: policy.ModeEngagement,
				Engagement: &EngagementContext{
					Name:                 "acme-q4-redteam",
					Targets:              []string{"10.0.0.0/24"},
					ExploitAllowed:       true,
					DestructiveForbidden: false,
				},
				Packs: skillpacks.Detection{EngagementActive: true},
			},
		},
		{
			name: "engagement-restrictive",
			in: PromptInput{
				Mode: policy.ModeEngagement,
				Engagement: &EngagementContext{
					Name:                 "acme-q4-redteam",
					Targets:              []string{"10.0.0.0/24", "192.0.2.44"},
					ExploitAllowed:       false,
					DestructiveForbidden: false,
					TimeWindow:           "08:00–18:00 America/New_York",
				},
				Memory: "# STYX.md\n\nEngagement notes go here.\n",
				Packs:  skillpacks.Detection{EngagementActive: true},
			},
		},
		{
			name: "engagement-blue",
			in: PromptInput{
				Mode: policy.ModeEngagement,
				Engagement: &EngagementContext{
					Name:           "acme-q4-redteam",
					Targets:        []string{"10.0.0.0/24"},
					ExploitAllowed: true,
				},
				Packs: skillpacks.Detection{EngagementActive: true, LogArtifactsOpen: true},
			},
		},
		{
			name: "engagement-re",
			in: PromptInput{
				Mode: policy.ModeEngagement,
				Engagement: &EngagementContext{
					Name:           "acme-q4-redteam",
					Targets:        []string{"10.0.0.0/24"},
					ExploitAllowed: true,
				},
				Packs: skillpacks.Detection{EngagementActive: true, REMCPConnected: true},
			},
		},
		{
			name: "engagement-all-packs",
			in: PromptInput{
				Mode: policy.ModeEngagement,
				Engagement: &EngagementContext{
					Name:           "acme-q4-redteam",
					Targets:        []string{"10.0.0.0/24"},
					ExploitAllowed: true,
				},
				Packs: skillpacks.Detection{
					EngagementActive: true,
					REMCPConnected:   true,
					LogArtifactsOpen: true,
				},
			},
		},
	}
}

func TestSystemPromptGolden(t *testing.T) {
	for _, tc := range promptCases() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildSystemPrompt(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(promptGoldenDir, tc.name+".golden")
			if *update {
				if err := os.MkdirAll(promptGoldenDir, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			//nolint:gosec // the golden path is built from test data above.
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden %s: %v (regenerate with `go test ./internal/agent -update`)", path, err)
			}
			if got != string(want) {
				t.Errorf("system prompt for %q changed.\n%s\nRegenerate with `go test ./internal/agent -update` if the change is intended.", tc.name, firstDifference(string(want), got))
			}
		})
	}
}

func TestSystemPromptIsByteStable(t *testing.T) {
	in := PromptInput{
		Mode: policy.ModeEngagement,
		Engagement: &EngagementContext{
			Name:                 "acme-q4-redteam",
			Targets:              []string{"10.0.0.0/24"},
			ExploitAllowed:       false,
			DestructiveForbidden: true,
		},
	}
	first, err := BuildSystemPrompt(in)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		again, err := BuildSystemPrompt(in)
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatalf("BuildSystemPrompt is not deterministic on call %d", i+2)
		}
	}
	if !strings.HasSuffix(first, "\n") {
		t.Error("system prompt does not end with a newline")
	}
}

func TestSystemPromptSectionOrder(t *testing.T) {
	prompt, err := BuildSystemPrompt(PromptInput{
		Mode: policy.ModeEngagement,
		Engagement: &EngagementContext{
			Name:    "acme-q4-redteam",
			Targets: []string{"10.0.0.0/24"},
		},
		Memory: "remember the thing",
	})
	if err != nil {
		t.Fatal(err)
	}
	order := []string{
		"You are styx,",
		"# Working rules",
		"# Engagement",
		"# Project memory (STYX.md)",
		"# Coding workflow",
	}
	last := -1
	for _, marker := range order {
		at := strings.Index(prompt, marker)
		if at < 0 {
			t.Fatalf("system prompt is missing section %q", marker)
		}
		if at < last {
			t.Errorf("section %q appears out of order", marker)
		}
		last = at
	}
}

func TestSafeModeOmitsEngagementSection(t *testing.T) {
	prompt, err := BuildSystemPrompt(PromptInput{Mode: policy.ModeSafe})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prompt, "# Engagement") {
		t.Error("safe-mode prompt contains an engagement section")
	}
	// Passing an engagement context is what injects the section; safe mode
	// never supplies one.
	if !strings.Contains(prompt, "# Coding workflow") {
		t.Error("coding workflow (the always-on pack) is missing")
	}
}

func TestEngagementContextRendersROE(t *testing.T) {
	prompt, err := BuildSystemPrompt(PromptInput{
		Mode: policy.ModeEngagement,
		Engagement: &EngagementContext{
			Name:                 "acme-q4-redteam",
			Targets:              []string{"10.0.0.0/24", "app.acme.example"},
			ExploitAllowed:       false,
			DestructiveForbidden: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"acme-q4-redteam",
		"- 10.0.0.0/24",
		"- app.acme.example",
		"exploit-class tooling: forbidden",
		"destructive-tagged calls: forbidden",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("engagement prompt is missing %q", want)
		}
	}
}

// TestSystemPromptPackInjection is the injection-trigger table at the prompt
// seam: each detection trigger swaps the matching pack's compact section for
// its full workflow section, and nothing else moves.
func TestSystemPromptPackInjection(t *testing.T) {
	tests := []struct {
		name          string
		packs         skillpacks.Detection
		fullMarker    string
		compactMarker string
	}{
		{
			name:          "engagement injects the red team full workflow",
			packs:         skillpacks.Detection{EngagementActive: true},
			fullMarker:    "# Red team workflow (four phases)",
			compactMarker: "# Red team (guidance)",
		},
		{
			name:          "RE MCP injects the RE full workflow",
			packs:         skillpacks.Detection{REMCPConnected: true},
			fullMarker:    "# Reverse engineering & malware workflow",
			compactMarker: "# Reverse engineering (guidance)",
		},
		{
			name:          "log artifacts inject the blue team full workflow",
			packs:         skillpacks.Detection{LogArtifactsOpen: true},
			fullMarker:    "# Blue team workflow (log triage & incident response)",
			compactMarker: "# Blue team (guidance)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prompt, err := BuildSystemPrompt(PromptInput{Packs: tc.packs})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(prompt, tc.fullMarker) {
				t.Errorf("prompt is missing the injected full section %q", tc.fullMarker)
			}
			if strings.Contains(prompt, tc.compactMarker) {
				t.Errorf("prompt still contains the compact section %q", tc.compactMarker)
			}
		})
	}
}

// TestSystemPromptPacksStayCompactWhenNotDetected pins the other half of the
// trigger table: with no detection, every security pack contributes its compact
// always-on section, never its full workflow.
func TestSystemPromptPacksStayCompactWhenNotDetected(t *testing.T) {
	prompt, err := BuildSystemPrompt(PromptInput{})
	if err != nil {
		t.Fatal(err)
	}
	for _, compact := range []string{
		"# Red team (guidance)",
		"# Reverse engineering (guidance)",
		"# Blue team (guidance)",
	} {
		if !strings.Contains(prompt, compact) {
			t.Errorf("prompt is missing the compact section %q", compact)
		}
	}
	for _, full := range []string{
		"# Red team workflow (four phases)",
		"# Reverse engineering & malware workflow",
		"# Blue team workflow (log triage & incident response)",
	} {
		if strings.Contains(prompt, full) {
			t.Errorf("prompt contains the un-triggered full section %q", full)
		}
	}
}

// TestSystemPromptPackInjectionIsByteStable guards the cache prefix: the pack
// decision is resolved into the prompt once and renders identically every time
// for the same detection.
func TestSystemPromptPackInjectionIsByteStable(t *testing.T) {
	in := PromptInput{
		Mode: policy.ModeEngagement,
		Engagement: &EngagementContext{
			Name:    "acme-q4-redteam",
			Targets: []string{"10.0.0.0/24"},
		},
		Packs: skillpacks.Detection{EngagementActive: true, REMCPConnected: true},
	}
	first, err := BuildSystemPrompt(in)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		again, err := BuildSystemPrompt(in)
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatalf("BuildSystemPrompt with packs is not deterministic on call %d", i+2)
		}
	}
}

// firstDifference renders a compact, line-oriented comparison so a golden
// mismatch shows the first changed line instead of a wall of text.
func firstDifference(want, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")
	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		var w, g string
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if w != g {
			return "first difference at line " + strconv.Itoa(i+1) + ":\n  want: " + w + "\n  got:  " + g
		}
	}
	return "the prompts are equal"
}
