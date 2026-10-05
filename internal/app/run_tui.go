package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	tea "charm.land/bubbletea/v2"

	"github.com/mobley-trent/styx-agent/internal/sessions"
	"github.com/mobley-trent/styx-agent/internal/tui"
)

// helpText is the tracer-bullet command surface. The full set (§9.4) lands
// with the TUI completion ticket.
const helpText = `commands:
  /help          show this help
  /status        show mode, model, session, and engagement state
  /engagement    list engagement files, or activate one with /engagement <file>
  /mode [safe]   show the operating mode, or return to safe mode (tears the engagement down)
  /resume [id]   list past sessions, or restore one by id
  /compact [in]  compact context now, with an optional custom instruction
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

	model := tui.New(tui.Config{
		Status: func() tui.Status { return h.Status(busy.Load()) },
		Submit: func(text string) {
			// One turn at a time: the loop is not reentrant.
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
		},
		Command: h.command,
	})

	program = tea.NewProgram(model, tea.WithContext(runCtx))
	h.setUI(func(ev sessions.Event) { program.Send(tui.EventMsg{Event: ev}) })
	h.setPromptUI(func(msg tui.PromptMsg) { program.Send(msg) })
	defer func() {
		h.setUI(nil)
		h.setPromptUI(nil)
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
	case "engagement":
		return h.engagementCommand(arg)
	case "mode":
		return h.modeCommand(arg)
	case "resume":
		return h.resumeCommand(arg)
	case "compact":
		return h.Compact(context.Background(), strings.TrimSpace(arg))
	default:
		return "", fmt.Errorf("unknown command %q; try /help", name)
	}
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
