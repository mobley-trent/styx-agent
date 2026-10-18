package app

import (
	"context"
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/mobley-trent/styx-agent/internal/tui"
)

// commandSpec is one entry in the harness command registry: the single source
// the slash-command menu, the modal pickers, /help, and dispatch all draw from
// (docs/tui-parity.md §4). Adding a command here is the whole change — the
// menu, the help text, and the picker (when the command declares options)
// follow from it.
type commandSpec struct {
	// name is the canonical command, without the leading slash.
	name string
	// aliases are accepted spellings of name. They never appear in the menu or
	// the help text.
	aliases []string
	// usage is the command as the operator types it, arguments included
	// ("/model [id]"). It is the menu's first column and the help line.
	usage string
	// desc is the one-line explanation the menu and the help text show.
	desc string
	// run handles the command. A non-nil error renders as an error line.
	run func(*Harness, string) (string, error)
	// options lists the command's modal-picker entries. A command that declares
	// them opens the picker when it is run with no argument, and a picker entry
	// submits "/<name> <value>". Nil means the command has no picker.
	options func(*Harness) []tui.Option
}

// commandRegistry is the command surface, in menu and help order.
func commandRegistry() []commandSpec {
	return []commandSpec{
		{
			name:    "help",
			aliases: []string{"h", "?"},
			usage:   "/help",
			desc:    "show this help",
			run:     (*Harness).helpCommand,
		},
		{
			name:  "status",
			usage: "/status",
			desc:  "show mode, model, session, engagement, and cost state",
			run:   func(h *Harness, _ string) (string, error) { return h.statusText(), nil },
		},
		{
			name:    "model",
			usage:   "/model [id]",
			desc:    "list the pinned models, or switch to one (rescales compaction)",
			run:     (*Harness).modelCommand,
			options: modelOptions,
		},
		{
			name:    "theme",
			usage:   "/theme [dark|light|auto]",
			desc:    "show the color scheme, or choose one (auto follows the terminal)",
			run:     (*Harness).themeCommand,
			options: themeOptions,
		},
		{
			name:  "memory",
			usage: "/memory",
			desc:  "show the project's STYX.md as loaded into the system prompt",
			run:   func(h *Harness, _ string) (string, error) { return h.memoryText(), nil },
		},
		{
			name:  "clear",
			usage: "/clear",
			desc:  "forget the conversation context (keeps the system prompt)",
			run: func(h *Harness, _ string) (string, error) {
				h.ClearConversation()
				return "conversation context cleared", nil
			},
		},
		{
			name:    "pack",
			aliases: []string{"packs"},
			usage:   "/pack",
			desc:    "show the harness-selected skill packs and their state",
			run:     func(h *Harness, _ string) (string, error) { return h.packText(), nil },
		},
		{
			name:  "engagement",
			usage: "/engagement [file]",
			desc:  "list engagement files, or activate one",
			run:   (*Harness).engagementCommand,
		},
		{
			name:  "mode",
			usage: "/mode [safe]",
			desc:  "show the operating mode, or return to safe mode (tears the engagement down)",
			run:   (*Harness).modeCommand,
		},
		{
			name:    "resume",
			usage:   "/resume [id]",
			desc:    "list past sessions, or restore one",
			run:     (*Harness).resumeCommand,
			options: resumeOptions,
		},
		{
			name:  "compact",
			usage: "/compact [in]",
			desc:  "compact context now, with an optional custom instruction",
			run:   (*Harness).compactCommand,
		},
		{
			name:  "skills",
			usage: "/skills",
			desc:  "list discovered agent skills",
			run:   func(h *Harness, _ string) (string, error) { return h.skillsText(), nil },
		},
		{
			name:    "quit",
			aliases: []string{"exit"},
			usage:   "/quit",
			desc:    "leave styx",
			run:     func(*Harness, string) (string, error) { return "", nil },
		},
	}
}

// lookupCommand resolves a typed name against the registry.
func lookupCommand(name string) (commandSpec, bool) {
	for _, spec := range commandRegistry() {
		if spec.name == name {
			return spec, true
		}
		for _, alias := range spec.aliases {
			if alias == name {
				return spec, true
			}
		}
	}
	return commandSpec{}, false
}

// commandInfos is the registry as the TUI draws it: the slash menu's rows and
// each picker's entries. The TUI never keeps a second copy.
func (h *Harness) commandInfos() []tui.CommandInfo {
	registry := commandRegistry()
	infos := make([]tui.CommandInfo, 0, len(registry))
	for _, spec := range registry {
		info := tui.CommandInfo{
			Name:        spec.name,
			Usage:       spec.usage,
			Description: spec.desc,
		}
		if spec.options != nil {
			options := spec.options
			info.Options = func() []tui.Option { return options(h) }
		}
		infos = append(infos, info)
	}
	return infos
}

// helpText renders the command surface from the registry, so a new command is
// documented the moment it is registered.
func (h *Harness) helpCommand(string) (string, error) {
	registry := commandRegistry()
	var b strings.Builder
	b.WriteString("commands:\n")
	width := 0
	for _, spec := range registry {
		if w := lipgloss.Width(spec.usage); w > width {
			width = w
		}
	}
	for _, spec := range registry {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, spec.usage, spec.desc)
	}
	b.WriteString("\nAnything else is sent to the model.")
	return b.String(), nil
}

// compactCommand runs /compact, with an optional custom instruction.
func (h *Harness) compactCommand(arg string) (string, error) {
	return h.Compact(context.Background(), strings.TrimSpace(arg))
}

// modelOptions lists the pinned models for the /model picker, marking the one
// in force.
func modelOptions(h *Harness) []tui.Option {
	current := h.currentModel()
	opts := make([]tui.Option, 0, len(h.Config.Models))
	for _, m := range h.Config.Models {
		label := m.ID
		if m.ID == current {
			label += "  (current)"
		}
		opts = append(opts, tui.Option{
			Value:  m.ID,
			Label:  label,
			Detail: fmt.Sprintf("%d token window", m.ContextWindow),
		})
	}
	return opts
}

// resumeOptions lists past sessions for the /resume picker, newest first.
func resumeOptions(h *Harness) []tui.Option {
	list, err := h.ListSessions()
	if err != nil {
		return nil
	}
	opts := make([]tui.Option, 0, len(list))
	for _, s := range list {
		detail := s.Updated.Local().Format("2006-01-02 15:04")
		if preview := firstLine(s.FirstPrompt()); preview != "" {
			detail += " · " + preview
		}
		opts = append(opts, tui.Option{Value: s.ID, Label: s.ID, Detail: detail})
	}
	return opts
}

// themeOptions is the /theme picker's fixed set, with the choice in force
// marked.
func themeOptions(h *Harness) []tui.Option {
	current := h.themePreference()
	opts := []tui.Option{
		{Value: "dark", Label: "dark", Detail: "bright on a dark terminal"},
		{Value: "light", Label: "light", Detail: "dark on a light terminal"},
		{Value: "auto", Label: "auto", Detail: "follow the terminal background"},
	}
	for i := range opts {
		if opts[i].Value == current || (current == "" && opts[i].Value == "auto") {
			opts[i].Label += "  (current)"
		}
	}
	return opts
}

// themePreference is the operator's /theme choice: "dark", "light", or empty
// for auto.
func (h *Harness) themePreference() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.theme
}

// setThemePreference records a /theme choice; empty restores auto.
func (h *Harness) setThemePreference(pref string) {
	h.mu.Lock()
	h.theme = pref
	h.mu.Unlock()
}

// themeCommand reports the color scheme in force, or chooses one. "auto" hands
// the choice back to the terminal background (§9.6).
func (h *Harness) themeCommand(arg string) (string, error) {
	switch strings.TrimSpace(arg) {
	case "":
		return "theme: " + themeDescription(h.themePreference()) +
			"\nchoose one with /theme dark|light|auto", nil
	case "auto":
		h.setThemePreference("")
		return "theme: " + themeDescription(""), nil
	case "dark", "light":
		h.setThemePreference(strings.TrimSpace(arg))
		return "theme: " + themeDescription(strings.TrimSpace(arg)), nil
	default:
		return "", fmt.Errorf("unknown theme %q; use /theme dark|light|auto", arg)
	}
}

// themeDescription names a preference for the one-line readout.
func themeDescription(pref string) string {
	switch pref {
	case "dark":
		return "dark"
	case "light":
		return "light"
	default:
		return "auto (follows the terminal background)"
	}
}
