package subagent

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/mobley-trent/styx-agent/internal/agent"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// Subagent lifecycle detail values, carried on KindSubagent events. They
// bracket a run so the TUI can open and close its block.
const (
	// DetailStart opens a run: the event's Text is the task brief.
	DetailStart = "start"
	// DetailReport closes a successful run: the event's Text is the report.
	DetailReport = "report"
	// DetailError closes a failed run: the event's Failure is the error.
	DetailError = "error"
)

// Config wires a Runner. Everything the nested loop needs is inherited from
// the main session, so a subagent is governed by exactly the same policy
// engine, audit trail, operator, and container as the main loop.
type Config struct {
	// Client is the model client every run streams through.
	Client model.ModelClient
	// Registry is the session's tool registry; a run gets the preset's
	// allowlist filtered out of it (never the delegation tool).
	Registry *agent.Registry
	// Engine is the session's policy engine: the same single choke point.
	Engine *policy.Engine
	// Audit is the session's audit writer.
	Audit agent.AuditWriter
	// Options are the main loop's options (prompter, diff reviewer, plan
	// approver, emitter, clock, model, isolation). A run reuses them, so its
	// permission prompts land in the same stream with attribution.
	Options []agent.LoopOption
	// Emit publishes subagent lifecycle events on the session bus.
	Emit func(sessions.Event)
	// ExploitAllowed reports whether the active engagement's rules of
	// engagement permit exploitation (§6.3, §8.3). It gates the
	// engagement-gated presets: an engagement with exploit_allowed: false must
	// not dispatch exploit-dev. Nil fails closed — the gate is only satisfied
	// when a caller affirmatively reports exploitation is allowed.
	ExploitAllowed func() bool
}

// Runner implements agent.Dispatcher over the built-in presets (§4.2, §5.4).
// It is safe for concurrent use: each run gets a fresh sequence number.
type Runner struct {
	cfg Config
	seq atomic.Uint64
}

// New builds a Runner.
func New(cfg Config) *Runner { return &Runner{cfg: cfg} }

// Dispatch runs one role-preset subagent in an isolated context and returns
// its report. The run is bounded at the preset's turn limit, receives only the
// preset's allowlist, and passes every tool call through the session's policy
// engine and audit trail.
func (r *Runner) Dispatch(ctx context.Context, req agent.DispatchRequest) (string, error) {
	preset, ok := Lookup(req.Role)
	if !ok {
		return "", fmt.Errorf("subagent: unknown role %q; available roles: %s", req.Role, available())
	}
	if err := r.gate(preset); err != nil {
		return "", err
	}
	if r.cfg.Client == nil {
		return "", errors.New("subagent: no model client is configured")
	}
	if r.cfg.Registry == nil {
		return "", errors.New("subagent: no tool registry is configured")
	}

	tools, err := r.cfg.Registry.Subset(preset.Allowlist()...)
	if err != nil {
		return "", fmt.Errorf("subagent %s: %w", preset.Name, err)
	}

	runID := fmt.Sprintf("%s-%d", preset.Name, r.seq.Add(1))
	r.emit(sessions.Event{
		Kind:     sessions.KindSubagent,
		Subagent: preset.Name,
		RunID:    runID,
		Detail:   DetailStart,
		Text:     req.Task,
	})

	opts := make([]agent.LoopOption, 0, len(r.cfg.Options)+3)
	opts = append(opts, r.cfg.Options...)
	opts = append(opts, agent.WithSubagent(preset.Name), agent.WithSubagentRun(runID), agent.WithMaxTurns(preset.MaxTurns))
	loop := agent.NewLoop(r.cfg.Client, tools, r.cfg.Engine, r.cfg.Audit, preset.SystemPrompt(), opts...)

	result, err := loop.Run(ctx, nil, req.Task)
	if err != nil {
		r.emit(sessions.Event{
			Kind:     sessions.KindSubagent,
			Subagent: preset.Name,
			RunID:    runID,
			Detail:   DetailError,
			Failure:  err.Error(),
		})
		return "", fmt.Errorf("subagent %s: %w", preset.Name, err)
	}

	r.emit(sessions.Event{
		Kind:     sessions.KindSubagent,
		Subagent: preset.Name,
		RunID:    runID,
		Detail:   DetailReport,
		Text:     result.Answer,
	})
	return result.Answer, nil
}

// gate enforces the preset's engagement requirements (§5.4). An
// engagement-gated preset runs only while an engagement is active and the
// rules of engagement permit exploitation.
func (r *Runner) gate(preset Preset) error {
	if !preset.EngagementGated {
		return nil
	}
	if r.cfg.Engine == nil || r.cfg.Engine.Mode() != policy.ModeEngagement {
		return fmt.Errorf("subagent: role %q is engagement-gated; activate an engagement before dispatching it", preset.Name)
	}
	if r.cfg.ExploitAllowed == nil || !r.cfg.ExploitAllowed() {
		return fmt.Errorf("subagent: role %q is refused: the rules of engagement do not permit exploitation (exploit_allowed)", preset.Name)
	}
	return nil
}

// emit publishes one lifecycle event, tolerating a nil bus.
func (r *Runner) emit(ev sessions.Event) {
	if r.cfg.Emit != nil {
		r.cfg.Emit(ev)
	}
}
