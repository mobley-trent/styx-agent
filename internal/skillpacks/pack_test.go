package skillpacks

import (
	"reflect"
	"strings"
	"testing"
)

func TestSelectInjectionTriggers(t *testing.T) {
	tests := []struct {
		name string
		d    Detection
		want []string
	}{
		{name: "none", d: Detection{}, want: []string{"coding"}},
		{name: "engagement", d: Detection{EngagementActive: true}, want: []string{"coding", "red-team"}},
		{name: "re mcp", d: Detection{REMCPConnected: true}, want: []string{"coding", "re"}},
		{name: "log artifacts", d: Detection{LogArtifactsOpen: true}, want: []string{"coding", "blue-team"}},
		{
			name: "all triggers",
			d:    Detection{EngagementActive: true, REMCPConnected: true, LogArtifactsOpen: true},
			want: []string{"coding", "red-team", "re", "blue-team"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Select(tt.d).ActiveNames()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ActiveNames() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEachTriggerInjectsItsFullSection is the acceptance-criteria trigger
// table: each detection trigger injects the matching pack's full workflow
// section, and the same pack falls back to its compact section otherwise.
func TestEachTriggerInjectsItsFullSection(t *testing.T) {
	cases := []struct {
		name          string
		detected      Detection
		notDetected   Detection
		id            ID
		fullMarker    string
		compactMarker string
	}{
		{
			name:          "engagement injects red team full",
			detected:      Detection{EngagementActive: true},
			notDetected:   Detection{},
			id:            RedTeam,
			fullMarker:    "Do not skip ahead",
			compactMarker: "four-phase lifecycle",
		},
		{
			name:          "RE MCP injects RE full",
			detected:      Detection{REMCPConnected: true},
			notDetected:   Detection{},
			id:            RE,
			fullMarker:    "Detonation is destructive and gated",
			compactMarker: "never detonate a sample",
		},
		{
			name:          "log artifacts inject blue team full",
			detected:      Detection{LogArtifactsOpen: true},
			notDetected:   Detection{},
			id:            BlueTeam,
			fullMarker:    "Triage loop",
			compactMarker: "Analyst co-pilot",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			whenDetected := strings.Join(Select(tc.detected).Sections(), "\n\n")
			if !strings.Contains(whenDetected, tc.fullMarker) {
				t.Errorf("detected %s prompt is missing the full marker %q", tc.id, tc.fullMarker)
			}
			if strings.Contains(whenDetected, tc.compactMarker) {
				t.Errorf("detected %s prompt still carries the compact section", tc.id)
			}

			whenNot := strings.Join(Select(tc.notDetected).Sections(), "\n\n")
			if !strings.Contains(whenNot, tc.compactMarker) {
				t.Errorf("undetected %s prompt is missing the compact marker %q", tc.id, tc.compactMarker)
			}
			if strings.Contains(whenNot, tc.fullMarker) {
				t.Errorf("undetected %s prompt carries the full section", tc.id)
			}
		})
	}
}

func TestSelectionAlwaysRendersFourSections(t *testing.T) {
	// Coding full plus the three security packs, compact or full: the prefix is
	// never empty of guidance.
	want := len(All())
	for _, d := range []Detection{
		{},
		{EngagementActive: true, REMCPConnected: true, LogArtifactsOpen: true},
	} {
		if got := len(Select(d).Sections()); got != want {
			t.Errorf("Select(%+v).Sections() = %d sections, want %d", d, got, want)
		}
	}
}

func TestSelectionTagsRedTeamExploitClass(t *testing.T) {
	safe := Select(Detection{})
	if exploit, _ := safe.Tags("mcp__sqlmap__run"); exploit {
		t.Error("a compact red team pack tagged an exploit-class tool")
	}

	engaged := Select(Detection{EngagementActive: true})
	for _, tool := range []string{"mcp__sqlmap__run", "exploit_payload", "mcp__metasploit__run"} {
		exploit, _ := engaged.Tags(tool)
		if !exploit {
			t.Errorf("engagement did not tag %q exploit-class", tool)
		}
	}
	if exploit, _ := engaged.Tags("mcp__nmap__scan"); exploit {
		t.Error("recon tooling was tagged exploit-class")
	}
}

func TestSelectionTagsDetonationDestructive(t *testing.T) {
	safe := Select(Detection{})
	if _, destructive := safe.Tags("code_exec"); destructive {
		t.Error("a compact RE pack tagged code_exec destructive")
	}

	re := Select(Detection{REMCPConnected: true})
	for _, tool := range []string{"bash", "code_exec", "mcp__cuckoo__detonate", "mcp__sandbox__run"} {
		if _, destructive := re.Tags(tool); !destructive {
			t.Errorf("RE did not tag %q destructive", tool)
		}
	}
	// Static-analysis tooling rides the same active pack and must stay
	// non-destructive.
	if _, destructive := re.Tags("mcp__ghidra__decompile"); destructive {
		t.Error("static RE tooling was tagged destructive")
	}
}

func TestPackContentIsEmbeddedData(t *testing.T) {
	for _, p := range All() {
		if p.Full == "" {
			t.Errorf("pack %s has no embedded full section", p.ID)
		}
		if p.AlwaysOn {
			continue
		}
		if p.Always == "" {
			t.Errorf("pack %s has no compact always-on section", p.ID)
		}
	}
	coding, ok := Lookup(Coding)
	if !ok || !coding.AlwaysOn {
		t.Error("coding must be the always-on pack")
	}
}

func TestIsREMCPName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "ghidra", want: true},
		{name: "GhidraMCP", want: true},
		{name: "pyghidra-mcp", want: true},
		{name: "radare2", want: true},
		{name: "reverse-engineering-assistant", want: true},
		{name: "nmap", want: false},
		{name: "volatility", want: false},
		{name: "recipient", want: false},
	}
	for _, tt := range tests {
		if got := IsREMCPName(tt.name); got != tt.want {
			t.Errorf("IsREMCPName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestLooksLikeLogArtifact(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "auth.log", want: true},
		{name: "Security.evtx", want: true},
		{name: "capture.pcapng", want: true},
		{name: "memory.dmp", want: true},
		{name: "main.go", want: false},
		{name: "notes.md", want: false},
		{name: "session.jsonl", want: false},
	}
	for _, tt := range tests {
		if got := LooksLikeLogArtifact(tt.name); got != tt.want {
			t.Errorf("LooksLikeLogArtifact(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
