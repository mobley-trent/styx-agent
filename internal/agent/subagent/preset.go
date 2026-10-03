package subagent

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/agent"
)

// Network classifies a preset's reach (§5.4). A preset that is networkless has
// no network tool in its allowlist and its exec is confined to the session
// container, whose egress already follows the engagement scope.
type Network string

const (
	// NetworkNone is a preset with no network tooling at all.
	NetworkNone Network = "none"
	// NetworkScope is a preset whose network tools are scope-checked against
	// the engagement.
	NetworkScope Network = "scope"
)

// DefaultMaxTurns is every preset's turn bound (§4.1: each subagent run is
// bounded at 40 turns). It is per-run, not configurable per dispatch, so a
// runaway subagent is structurally impossible.
const DefaultMaxTurns = 40

// networkTools are the tools that reach the network directly. A networkless
// preset must not carry any of them.
var networkTools = map[string]bool{
	"web_fetch": true,
	"ssh_logs":  true,
}

// Preset is one built-in subagent role (§5.4): its system prompt, its tool
// allowlist, its turn bound, and its safety classification.
type Preset struct {
	// Name is the role the model dispatches by ("coder", "recon", ...).
	Name string
	// Description is the one-line role summary shown to the main model.
	Description string
	// Tools is the preset's tool allowlist, exactly as specced. The
	// delegation tool is never part of it; Allowlist enforces that even for a
	// hand-built preset.
	Tools []string
	// MaxTurns is the run's turn bound.
	MaxTurns int
	// Network classifies the preset's reach.
	Network Network
	// EngagementGated marks a preset that refuses to start outside engagement
	// mode (§5.4: exploit-dev).
	EngagementGated bool

	// section is the role's prompt data, embedded from promptdata.
	section string
}

// SystemPrompt is the preset's byte-stable system prompt: the shared subagent
// framing followed by the role section.
func (p Preset) SystemPrompt() string {
	base := strings.TrimSpace(preamble) + "\n\n" + strings.TrimSpace(p.section)
	return base + "\n"
}

// Allowlist is the preset's tool names, always with the delegation tool
// stripped: a subagent never receives dispatch_subagent, so one nesting level
// is structural rather than a rule the model could ignore (§4.2).
func (p Preset) Allowlist() []string {
	out := make([]string, 0, len(p.Tools))
	for _, name := range p.Tools {
		if name == agent.DispatchSubagentToolName {
			continue
		}
		out = append(out, name)
	}
	return out
}

//go:embed promptdata/base.md
var preamble string

//go:embed promptdata/coder.md
var coderSection string

//go:embed promptdata/recon.md
var reconSection string

//go:embed promptdata/exploit-dev.md
var exploitDevSection string

//go:embed promptdata/log-triage.md
var logTriageSection string

// presets is the built-in registry, in stable display order (§5.4).
var presets = []Preset{
	{
		Name:        "coder",
		Description: "Implement and modify code in the workspace, then build and test it.",
		Tools:       []string{"read_file", "write_file", "edit_file", "glob", "grep", "bash", "code_exec"},
		MaxTurns:    DefaultMaxTurns,
		Network:     NetworkNone,
		section:     coderSection,
	},
	{
		Name:        "recon",
		Description: "Reconnaissance within the engagement scope: passive collection, then active probes.",
		Tools:       []string{"web_fetch", "bash", "read_file", "glob", "grep"},
		MaxTurns:    DefaultMaxTurns,
		Network:     NetworkScope,
		section:     reconSection,
	},
	{
		Name:            "exploit-dev",
		Description:     "Develop and validate exploitation against authorized in-scope targets. Engagement-gated.",
		Tools:           []string{"bash", "code_exec", "read_file", "write_file", "edit_file", "glob", "grep", "web_fetch"},
		MaxTurns:        DefaultMaxTurns,
		Network:         NetworkScope,
		EngagementGated: true,
		section:         exploitDevSection,
	},
	{
		Name:        "log-triage",
		Description: "Read-only log and forensic triage: correlate events, extract indicators, build a timeline.",
		Tools:       []string{"read_file", "glob", "grep", "code_exec"},
		MaxTurns:    DefaultMaxTurns,
		Network:     NetworkNone,
		section:     logTriageSection,
	},
}

// Presets returns a copy of the built-in registry, in stable order.
func Presets() []Preset {
	out := make([]Preset, len(presets))
	copy(out, presets)
	return out
}

// Names returns the built-in role names, in stable order.
func Names() []string {
	out := make([]string, 0, len(presets))
	for _, p := range presets {
		out = append(out, p.Name)
	}
	return out
}

// Lookup returns the preset with the given role name.
func Lookup(name string) (Preset, bool) {
	for _, p := range presets {
		if p.Name == name {
			return p, true
		}
	}
	return Preset{}, false
}

// available is the sorted role list for error messages.
func available() string {
	names := Names()
	sort.Strings(names)
	return fmt.Sprintf("%v", names)
}

// ToolDescription is the model-facing description of the delegation tool: the
// built-in roles and what each is for. It is derived from the preset registry
// so the tool's advertised roles can never drift from the roles that exist.
func ToolDescription() string {
	var b strings.Builder
	b.WriteString("Dispatch a scoped subagent to work a task in an isolated context and return its report. Roles:")
	for _, p := range presets {
		b.WriteString("\n- " + p.Name + ": " + p.Description)
	}
	b.WriteString("\nThe subagent cannot delegate further; its tool calls pass the same policy engine and its permission prompts surface to the operator.")
	return b.String()
}
