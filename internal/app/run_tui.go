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
  /resume [id]   list past sessions, or restore one by id
  /quit          leave styx

Anything else is sent to the model.`

// runTUI runs one session in the thin chat stream (§9.1). The loop runs on its
// own goroutine; every event it emits reaches the UI through the harness bus,
// and nothing renders that is not also persisted.
func runTUI(ctx context.Context, h *Harness) error {
	var program *tea.Program
	var busy atomic.Bool

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
				_ = h.Submit(ctx, text)
			}()
		},
		Command: h.command,
	})

	program = tea.NewProgram(model, tea.WithContext(ctx))
	h.setUI(func(ev sessions.Event) { program.Send(tui.EventMsg{Event: ev}) })
	defer h.setUI(nil)

	if _, err := program.Run(); err != nil && !errors.Is(err, tea.ErrProgramKilled) {
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
	case "resume":
		return h.resumeCommand(arg)
	default:
		return "", fmt.Errorf("unknown command %q; try /help", name)
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
