package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	tea "charm.land/bubbletea/v2"

	"github.com/mobley-trent/styx-agent/internal/sessions"
	"github.com/mobley-trent/styx-agent/internal/skills"
	"github.com/mobley-trent/styx-agent/internal/tui"
)

// helpText is the tracer-bullet command surface. The full set (§9.4) lands
// with the TUI completion ticket.
const helpText = `commands:
  /help          show this help
  /status        show mode, model, session, engagement, and cost state
  /model [id]    list the pinned models, or switch to one (rescales compaction)
  /memory        show the project's STYX.md as loaded into the system prompt
  /clear         forget the conversation context (keeps the system prompt)
  /pack          show the harness-selected skill packs and their state
  /engagement    list engagement files, or activate one with /engagement <file>
  /mode [safe]   show the operating mode, or return to safe mode (tears the engagement down)
  /resume [id]   list past sessions, or restore one by id
  /compact [in]  compact context now, with an optional custom instruction
  /skills        list discovered agent skills
  /<skill-name>  invoke an agent skill
  /quit          leave styx

Anything else is sent to the model.`

// runTUI runs one session in the thin chat stream (§9.1). The loop runs on its
// own goroutine; every event it emits reaches the UI through the harness bus,
// and nothing renders that is not also persisted.
func runTUI(ctx context.Context, h *Harness) error {
	var program *tea.Program
	var busy atomic.Bool

	// A cancelable child context unblocks a live permission card when the
	// program exits, so the loop goroutine never waits on a terminal that is
	// gone.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// submit runs one turn at a time: the loop is not reentrant. It is shared
	// by the input line and by slash-command invocations like /<skill-name>.
	submit := func(text string) {
		if !busy.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer func() {
				busy.Store(false)
				if program != nil {
					program.Send(tui.RefreshMsg{})
				}
			}()
			// The loop emits its own error event (§4.4); the turn stays
			// resumable and the UI already shows the failure.
			_ = h.Submit(runCtx, text)
		}()
	}

	model := tui.New(tui.Config{
		Status:  func() tui.Status { return h.Status(busy.Load()) },
		Version: h.Version,
		Submit:  submit,
		Clear:   h.ClearConversation,
		Command: h.command,
	})

	program = tea.NewProgram(model, tea.WithContext(runCtx))
	h.setUI(func(ev sessions.Event) { program.Send(tui.EventMsg{Event: ev}) })
	h.setPromptUI(func(msg tui.PromptMsg) { program.Send(msg) })
	h.setSubmitter(submit)
	// The opt-out update notifier makes its single releases fetch once, in the
	// background, after the UI is attached so the notice renders live (§12.3).
	go h.CheckForUpdate(runCtx)
	defer func() {
		h.setUI(nil)
		h.setPromptUI(nil)
		h.setSubmitter(nil)
	}()

	_, err := program.Run()
	cancel()
	if err != nil && !errors.Is(err, tea.ErrProgramKilled) {
		return err
	}
	return nil
}

// command handles a slash command line.
func (h *Harness) command(name, arg string) (string, error) {
	switch name {
	case "help", "h", "?":
		return helpText, nil
	case "status":
		return h.statusText(), nil
	case "model":
		return h.modelCommand(arg)
	case "memory":
		return h.memoryText(), nil
	case "clear":
		h.ClearConversation()
		return "conversation context cleared", nil
	case "pack", "packs":
		return h.packText(), nil
	case "engagement":
		return h.engagementCommand(arg)
	case "mode":
		return h.modeCommand(arg)
	case "resume":
		return h.resumeCommand(arg)
	case "compact":
		return h.Compact(context.Background(), strings.TrimSpace(arg))
	case "skills":
		return h.skillsText(), nil
	default:
		if sk, ok := h.lookupSkill(name); ok {
			return h.invokeSkill(sk, arg), nil
		}
		return "", fmt.Errorf("unknown command %q; try /help", name)
	}
}

// lookupSkill resolves a user-typed skill name against the discovered catalog.
func (h *Harness) lookupSkill(name string) (skills.Skill, bool) {
	if h.skillCatalog == nil {
		return skills.Skill{}, false
	}
	return h.skillCatalog.Lookup(name)
}

// skillsText is the /skills picker: every discovered skill with its source and
// whether the model may invoke it (§8.4). Project skills shadow global ones.
func (h *Harness) skillsText() string {
	if h.skillCatalog == nil || len(h.skillCatalog.Skills()) == 0 {
		return "no agent skills discovered (looked for SKILL.md under ~/.agents/skills and .styx/skills)"
	}
	var b strings.Builder
	b.WriteString("agent skills (project shadows global):")
	for _, sk := range h.skillCatalog.Skills() {
		mode := "model-invocable"
		if !sk.ModelInvocation {
			mode = "user-invoked"
		}
		fmt.Fprintf(&b, "\n  %s  [%s · %s]", sk.Name, mode, sk.Source)
		if sk.Description != "" {
			b.WriteString(" — " + firstLine(sk.Description))
		}
		if sk.Path != "" {
			b.WriteString("\n      " + sk.Path)
		}
	}
	b.WriteString("\n\ninvoke one with /<skill-name>")
	return b.String()
}

// invokeSkill runs a user invocation of a skill. A model-invocable skill is
// reached through the skill tool (so the model's call and its workflow result
// appear in the stream); a user-invoked skill is not available to the model, so
// the harness loads its workflow directly into the turn. With no interactive
// session attached, the rendered turn is returned as text.
func (h *Harness) invokeSkill(sk skills.Skill, arg string) string {
	text := userSkillPrompt(sk, arg)
	h.mu.Lock()
	submit := h.submitter
	h.mu.Unlock()
	if submit == nil {
		return text
	}
	submit(text)
	return fmt.Sprintf("invoking skill %q — the model will follow its workflow", sk.Name)
}

// userSkillPrompt renders the user turn a /<skill-name> invocation submits.
func userSkillPrompt(sk skills.Skill, arg string) string {
	arg = strings.TrimSpace(arg)
	if sk.ModelInvocation {
		var b strings.Builder
		fmt.Fprintf(&b, "Invoke the %q skill with the skill tool, then follow its workflow.", sk.Name)
		if arg != "" {
			fmt.Fprintf(&b, " Arguments for this invocation: %s", arg)
		}
		return b.String()
	}
	out := strings.TrimRight(sk.Invocation(nil), "\n")
	if arg != "" {
		out += "\n\nArguments for this invocation: " + arg
	}
	return out
}

// engagementCommand lists discovered engagement files, or activates one
// through the same gate the --engagement launch flag uses (§7.2).
func (h *Harness) engagementCommand(arg string) (string, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		files := h.ListEngagementFiles()
		if len(files) == 0 {
			return "no engagement files found (looked for *.engagement.yaml, engagement.yaml, and .styx/*.yaml)", nil
		}
		var b strings.Builder
		b.WriteString("engagement files:")
		for _, file := range files {
			b.WriteString("\n  " + file)
		}
		b.WriteString("\n\nactivate one with /engagement <file> (strict validation; a refusal leaves safe mode active)")
		return b.String(), nil
	}
	if _, eng := h.modeAndEngagement(); eng != nil {
		return "", fmt.Errorf("an engagement is already active (%s); run /mode safe first", eng.Name())
	}
	if err := h.ActivateEngagement(context.Background(), arg); err != nil {
		return "", err
	}
	_, eng := h.modeAndEngagement()
	return fmt.Sprintf("engagement active: %s (scope summary injected; egress allowlist programmed)", eng.Name()), nil
}

// modeCommand reports the operating mode, or returns to safe mode. Returning
// to safe mode tears the engagement down: notes are appended to STYX.md and
// the scope summary and egress allowlist are removed (§7.3).
func (h *Harness) modeCommand(arg string) (string, error) {
	switch strings.TrimSpace(arg) {
	case "":
		if _, eng := h.modeAndEngagement(); eng != nil {
			return fmt.Sprintf("mode: engagement (%s)\nrun /mode safe to tear it down", eng.Name()), nil
		}
		return "mode: safe", nil
	case "safe":
		_, eng := h.modeAndEngagement()
		if eng == nil {
			return "already in safe mode", nil
		}
		name := eng.Name()
		if err := h.Deactivate(); err != nil {
			return "", err
		}
		return fmt.Sprintf("returned to safe mode; engagement %s torn down (notes appended to STYX.md)", name), nil
	case "engagement":
		return "activate engagement mode with /engagement <file>", nil
	default:
		return "", fmt.Errorf("unknown mode %q; use /mode safe", arg)
	}
}

// modelCommand lists the pinned models, or switches the session to one by ID
// (§3.1). The pinned set is validated against the provider on first use (§1
// "fail on demand"), so a swap is local and never fails here: it rescales the
// compaction trigger to the new model's context window (§4.5), and the next
// prompt carries the provider check.
func (h *Harness) modelCommand(arg string) (string, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		current := h.currentModel()
		var b strings.Builder
		b.WriteString("pinned models (validated against the provider on first use):")
		for _, m := range h.Config.Models {
			mark := " "
			if m.ID == current {
				mark = "*"
			}
			fmt.Fprintf(&b, "\n  %s %-16s %d token window", mark, m.ID, m.ContextWindow)
		}
		b.WriteString("\n\nswitch with /model <id>; compaction rescales to the new window")
		return b.String(), nil
	}

	info, ok := h.Config.ModelByID(arg)
	if !ok {
		return "", fmt.Errorf("unknown model %q; pinned set: %s", arg, strings.Join(h.pinnedModelIDs(), ", "))
	}

	h.mu.Lock()
	if h.model == arg {
		h.mu.Unlock()
		return fmt.Sprintf("already using %s", arg), nil
	}
	h.model = arg
	h.mu.Unlock()

	if h.compactor != nil {
		h.compactor.SetContextWindow(info.ContextWindow)
	}
	return fmt.Sprintf("model: %s (compaction threshold rescaled to the %d token window)", arg, info.ContextWindow), nil
}

// pinnedModelIDs returns the configured model IDs in declaration order.
func (h *Harness) pinnedModelIDs() []string {
	ids := make([]string, 0, len(h.Config.Models))
	for _, m := range h.Config.Models {
		ids = append(ids, m.ID)
	}
	return ids
}

// resumeCommand lists past sessions, or restores one.
func (h *Harness) resumeCommand(arg string) (string, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		list, err := h.ListSessions()
		if err != nil {
			return "", err
		}
		if len(list) == 0 {
			return "no past sessions for this project yet", nil
		}
		var b strings.Builder
		b.WriteString("sessions (newest first):")
		for _, s := range list {
			fmt.Fprintf(&b, "\n  %s  %s  %s", s.ID, s.Updated.Local().Format("2006-01-02 15:04"), firstLine(s.FirstPrompt()))
		}
		b.WriteString("\n\nrestore one with /resume <id>")
		return b.String(), nil
	}

	summary, err := h.Resume(arg)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("resumed %s (%d messages in context)", summary.ID, len(h.Messages())), nil
}

// firstLine trims a prompt to its first line for a one-line preview.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) > 60 {
		s = s[:60] + "…"
	}
	return s
}
