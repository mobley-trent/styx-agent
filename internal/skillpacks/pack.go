package skillpacks

import (
	"path"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/naming"
)

// ID identifies one of the four built-in packs.
type ID string

const (
	// Coding is the always-on inner-loop coding pack (the Claude Code core).
	Coding ID = "coding"
	// RedTeam is the offensive four-phase lifecycle pack.
	RedTeam ID = "red-team"
	// RE is the reverse-engineering & malware pack.
	RE ID = "re"
	// BlueTeam is the analyst co-pilot pack (log triage & IR).
	BlueTeam ID = "blue-team"
)

// AllowlistDelta is a pack's tool-allowlist delta (§8.1): the tool families it
// brings, plus the classification globs that ride on them. The registry applies
// a delta to whatever tools a session actually has — built-in or MCP — by
// matching tool names, so a pack adds no new harness surface.
//
// Add is advisory (what the pack expects to use, shown by /pack). ExploitClass
// and Destructive are tool-name globs; a matching tool is tagged so the ROE
// hard limits bind to it (§6.3).
type AllowlistDelta struct {
	// Add lists the tool families the pack expects to use.
	Add []string
	// ExploitClass lists tool-name globs that carry the exploit-class tag.
	ExploitClass []string
	// Destructive lists tool-name globs that carry the destructive tag. RE
	// sample detonation rides here (§8.3).
	Destructive []string
}

// MCPRecommendation is one capability contract with the servers that satisfy
// it (§8.6). styx ships none of them; this is guidance for /pack.
type MCPRecommendation struct {
	// Capability is the need, in contract terms.
	Capability string
	// Recommended is the preferred server.
	Recommended string
	// Alternative lists other conformant servers.
	Alternative []string
}

// Pack is one built-in domain bundle (§8.1): its workflow prompt sections, its
// tool-allowlist delta, and its preset references. Prompt text is embedded data
// (promptdata/*.md), never a Go string literal.
type Pack struct {
	// ID is the pack's stable identifier.
	ID ID
	// Name is the human-facing pack name.
	Name string
	// Always is the compact always-on guidance section. Coding leaves it empty
	// (its full section is always injected).
	Always string
	// Full is the full workflow section, injected when the pack's domain is
	// detected.
	Full string
	// AlwaysOn marks a pack whose full section is always injected (coding).
	AlwaysOn bool
	// Presets are the subagent presets the pack's workflow references (§8.5).
	Presets []string
	// MCP names the pack's recommended MCP servers (§8.6).
	MCP []MCPRecommendation
	// Delta is the pack's tool-allowlist delta.
	Delta AllowlistDelta
}

// Detection is the harness's pack-domain evidence for one session prefix. It is
// evaluated once at session start / gate activation and is the only input to
// injection; the model never selects packs (§8.2).
type Detection struct {
	// EngagementActive is true when engagement mode is active: inject the red
	// team full workflow.
	EngagementActive bool
	// REMCPConnected is true when an RE-class MCP server is connected: inject
	// the RE full workflow.
	REMCPConnected bool
	// LogArtifactsOpen is true when log/IR artifacts are present at session
	// start: inject the blue team full workflow.
	LogArtifactsOpen bool
}

// State is one pack's resolved injection state.
type State struct {
	// Pack is the pack.
	Pack Pack
	// Full is true when the full workflow section is injected; false means the
	// compact always-on section is used.
	Full bool
	// Reason is why the pack is in this state (audit- and /pack-facing).
	Reason string
}

// Selection is the resolved pack state for a session prefix: which sections are
// injected, and which allowlist deltas apply. It carries the Detection it was
// resolved from so callers can pass the same evidence back to prompt assembly.
type Selection struct {
	Detection Detection
	states    []State
}

// Select resolves the session's pack state from its detection evidence. Coding
// is always full; each security pack is full when its trigger fires and compact
// otherwise (§8.2).
func Select(d Detection) Selection {
	all := All()
	states := make([]State, 0, len(all))
	for _, p := range all {
		switch p.ID {
		case Coding:
			states = append(states, State{Pack: p, Full: true, Reason: "always-on"})
		case RedTeam:
			if d.EngagementActive {
				states = append(states, State{Pack: p, Full: true, Reason: "engagement active"})
			} else {
				states = append(states, State{Pack: p, Full: false, Reason: "compact (no engagement)"})
			}
		case RE:
			if d.REMCPConnected {
				states = append(states, State{Pack: p, Full: true, Reason: "RE MCP connected"})
			} else {
				states = append(states, State{Pack: p, Full: false, Reason: "compact (no RE MCP connected)"})
			}
		case BlueTeam:
			if d.LogArtifactsOpen {
				states = append(states, State{Pack: p, Full: true, Reason: "log/IR artifacts opened"})
			} else {
				states = append(states, State{Pack: p, Full: false, Reason: "compact (no log/IR artifacts)"})
			}
		}
	}
	return Selection{Detection: d, states: states}
}

// States returns the resolved states in stable pack order.
func (s Selection) States() []State {
	return append([]State(nil), s.states...)
}

// ActiveNames returns the IDs of the packs whose full section is injected, in
// stable order. It is the status-bar and /pack "active pack" readout.
func (s Selection) ActiveNames() []string {
	out := make([]string, 0, len(s.states))
	for _, st := range s.states {
		if st.Full {
			out = append(out, string(st.Pack.ID))
		}
	}
	return out
}

// Sections renders the prompt sections the prefix injects, in stable order:
// coding full, then each security pack's full section (detected) or compact
// section (otherwise). Empty sections are dropped.
func (s Selection) Sections() []string {
	out := make([]string, 0, len(s.states))
	for _, st := range s.states {
		text := st.Pack.Always
		if st.Full {
			text = st.Pack.Full
		}
		if text = strings.TrimSpace(text); text != "" {
			out = append(out, text)
		}
	}
	return out
}

// Tags reports the classification a pack delta imposes on a tool name. Only
// full-injected packs contribute deltas: a compact pack has not activated its
// domain, so it changes nothing (§8.2).
func (s Selection) Tags(tool string) (exploitClass, destructive bool) {
	for _, st := range s.states {
		if !st.Full {
			continue
		}
		if matchesAny(st.Pack.Delta.ExploitClass, tool) {
			exploitClass = true
		}
		if matchesAny(st.Pack.Delta.Destructive, tool) {
			destructive = true
		}
	}
	return exploitClass, destructive
}

// matchesAny reports whether a tool name matches any glob in the set.
func matchesAny(globs []string, tool string) bool {
	for _, g := range globs {
		if ok, err := path.Match(g, tool); err == nil && ok {
			return true
		}
	}
	return false
}

// packs is the built-in registry, built once from embedded data.
var packs = []Pack{
	{
		ID:       Coding,
		Name:     "Coding",
		Full:     codingFull,
		AlwaysOn: true,
		Presets:  []string{"coder"},
		Delta: AllowlistDelta{
			Add: []string{"read_file", "write_file", "edit_file", "glob", "grep", "bash", "code_exec"},
		},
	},
	{
		ID:      RedTeam,
		Name:    "Red team",
		Always:  redTeamCompact,
		Full:    redTeamFull,
		Presets: []string{"recon", "exploit-dev"},
		MCP: []MCPRecommendation{
			{
				Capability:  "port scanning / service enumeration (standard scan types, structured output)",
				Recommended: "vorota-ai/nmap-mcp",
				Alternative: []string{"PhialsBasement/nmap-mcp-server", "cyproxio/mcp-for-security"},
			},
		},
		Delta: AllowlistDelta{
			Add: []string{"web_fetch", "bash", "mcp__nmap__*"},
			// Exploit-class tooling: the ROE's exploit_allowed gate hard-denies
			// these even in-scope in engagement mode (§6.3).
			ExploitClass: []string{"*exploit*", "mcp__*sqlmap*", "mcp__*metasploit*", "mcp__*msf*"},
		},
	},
	{
		ID:      RE,
		Name:    "Reverse engineering",
		Always:  reCompact,
		Full:    reFull,
		Presets: []string{"coder"},
		MCP: []MCPRecommendation{
			{
				Capability:  "decompile / xrefs / rename-retype on loaded binaries",
				Recommended: "LaurieWired/GhidraMCP",
				Alternative: []string{"cyberkaida/reverse-engineering-assistant"},
			},
			{
				Capability:  "headless, containerized project-wide multi-binary analysis",
				Recommended: "pyghidra-mcp",
			},
		},
		Delta: AllowlistDelta{
			Add: []string{"bash", "read_file", "glob", "grep", "mcp__*ghidra*", "mcp__*radare*"},
			// Dynamic execution of an analyzed sample is destructive-tagged: it
			// requires engagement mode and an explicit prompt, never
			// auto-allowed even in-scope (§8.3). The harness cannot tell a
			// detonation from any other command, so while the RE domain is
			// active its execution surfaces — `bash` and `code_exec` — are
			// tagged destructive, alongside dynamic-analysis MCP families.
			Destructive: []string{
				"bash",
				"code_exec",
				"mcp__*cuckoo*",
				"mcp__*sandbox*",
				"mcp__*detonat*",
				"mcp__*dynamic*",
				"mcp__*speakeasy*",
			},
		},
	},
	{
		ID:      BlueTeam,
		Name:    "Blue team",
		Always:  blueTeamCompact,
		Full:    blueTeamFull,
		Presets: []string{"log-triage"},
		MCP: []MCPRecommendation{
			{
				Capability:  "memory / forensic artifact analysis (Volatility 3 plugin coverage)",
				Recommended: "OMGhozlan/Volatility-MCP-Server",
				Alternative: []string{"Kirandawadi/volatility3-mcp", "0xhackerfren/Windows-Memory-Forensics-MCP"},
			},
		},
		Delta: AllowlistDelta{
			Add: []string{"read_file", "glob", "grep", "code_exec", "ssh_logs"},
		},
	},
}

// All returns the built-in packs in stable order.
func All() []Pack {
	out := make([]Pack, len(packs))
	copy(out, packs)
	return out
}

// Lookup returns the pack with the given ID.
func Lookup(id ID) (Pack, bool) {
	for _, p := range packs {
		if p.ID == id {
			return p, true
		}
	}
	return Pack{}, false
}

// reMCPTokens are the name tokens that mark an MCP server as an RE-class
// server. Matching is token-based, so "python-reva" and "GhidraMCP" match while
// an unrelated name does not.
var reMCPTokens = map[string]bool{
	"ghidra": true, "pyghidra": true,
	"radare": true, "radare2": true, "rizin": true, "r2": true,
	"reva": true, "reveng": true, "reverse": true,
	"binja": true, "binaryninja": true, "ida": true, "cutter": true,
}

// IsREMCPName reports whether an MCP server name identifies a reverse
// engineering capability (§8.2: "RE MCP server connected → RE").
func IsREMCPName(name string) bool {
	for _, tok := range naming.Tokens(name) {
		if reMCPTokens[tok] {
			return true
		}
	}
	return false
}

// logArtifactExts are the file extensions that mark a log or IR artifact.
var logArtifactExts = map[string]bool{
	".log":    true,
	".evtx":   true,
	".pcap":   true,
	".pcapng": true,
	".cap":    true,
	".mem":    true,
	".dmp":    true,
	".dump":   true,
	".vmem":   true,
	".vmsn":   true,
	".raw":    true,
	".hprof":  true,
}

// LooksLikeLogArtifact reports whether a file name is a log or incident-response
// artifact (§8.2: "log/IR artifacts opened → blue team"). It is deliberately
// conservative: only well-known forensic and log extensions qualify, so an
// unrelated file never activates the domain.
func LooksLikeLogArtifact(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	ext := path.Ext(lower)
	return logArtifactExts[ext]
}
