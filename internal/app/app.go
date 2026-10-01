// Package app wires styx-agent startup: config load, engagement gate
// activation, and TUI boot.
//
// Boundary rule: app is composition only. It connects config, engagement,
// policy, agent, model, and tui into a running harness; it owns no logic of
// its own and defines no shared types.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mobley-trent/styx-agent/internal/agent"
	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/config"
	"github.com/mobley-trent/styx-agent/internal/engagement"
	"github.com/mobley-trent/styx-agent/internal/memory"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
	"github.com/mobley-trent/styx-agent/internal/tui"
)

// Runner drives a built harness interactively. The default is the Bubble Tea
// TUI; tests substitute a scripted runner.
type Runner func(ctx context.Context, h *Harness) error

// Options is one harness launch.
type Options struct {
	// Engagement is the engagement file path, empty for safe mode (§7.2:
	// forgetting the flag means safe mode, never the reverse).
	Engagement string
	// ProjectDir is the project root; empty means the working directory.
	ProjectDir string
	// Version is the running binary's version, shown in the status line.
	Version string

	// Stdin, Stdout, and Stderr default to the process's streams.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Env reads an environment variable; nil means os.Getenv.
	Env func(string) string

	// Client replaces the DeepSeek client when non-nil (tests).
	Client model.ModelClient
	// Runner replaces the Bubble Tea program when non-nil (tests).
	Runner Runner
	// SkipModelCheck disables the startup GET /models validation (§3.1).
	SkipModelCheck bool
	// Now is the harness clock; nil means time.Now.
	Now func() time.Time
}

// Harness is the wired harness for one session: every component the loop needs
// plus the session log and audit trail it writes through.
type Harness struct {
	// Config is the merged global+project configuration (§10.3).
	Config *config.Config
	// Mode is the operating mode the engagement gate resolved.
	Mode policy.Mode
	// Engagement is the validated engagement, nil in safe mode.
	Engagement *engagement.Engagement
	// Engine is the single policy choke point (§6).
	Engine *policy.Engine
	// Tools is the session's tool registry.
	Tools *agent.Registry
	// Loop is the agent loop.
	Loop *agent.Loop
	// Prompt is the byte-stable system prompt (§3.3).
	Prompt string
	// WorkDir is the project root.
	WorkDir string
	// Version is the binary version.
	Version string

	sessions *sessions.Store
	audit    *audit.Writer
	out      io.Writer
	now      func() time.Time
	warned   bool

	mu       sync.Mutex
	session  *sessions.Session
	messages []model.Message
	ui       func(sessions.Event)
}

// Run builds the harness and hands it to the runner. Every startup failure is
// fatal: an unparseable config, a refused engagement file, a missing API key,
// or a pinned model the provider does not serve all refuse to start rather
// than run degraded.
func Run(ctx context.Context, opts Options) error {
	h, err := Build(ctx, opts)
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()

	runner := opts.Runner
	if runner == nil {
		runner = runTUI
	}
	return runner(ctx, h)
}

// Build wires a harness without running it. It is the seam tests use to assert
// wiring decisions (mode, overlay precedence, refusal behavior) without a
// terminal or a network.
func Build(ctx context.Context, opts Options) (*Harness, error) {
	env := opts.Env
	if env == nil {
		env = os.Getenv
	}
	out := opts.Stdout
	if out == nil {
		out = os.Stdout
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	workDir := strings.TrimSpace(opts.ProjectDir)
	if workDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("styx: determine working directory: %w", err)
		}
		workDir = wd
	}

	// Configuration: built-in defaults, then global, then project (§10.3).
	cfg, err := config.Load(config.DefaultGlobalPath(), config.ProjectPath(workDir))
	if err != nil {
		return nil, err
	}

	// Engagement gate: strict, refuse-to-start validation (§7.2).
	mode := policy.ModeSafe
	var eng *engagement.Engagement
	if path := strings.TrimSpace(opts.Engagement); path != "" {
		eng, err = engagement.Load(ctx, path, engagement.WithClock(now))
		if err != nil {
			return nil, fmt.Errorf("styx: refusing to start: %w", err)
		}
		mode = policy.ModeEngagement
	}

	// Project memory (§10.2): absent is fine, malformed is not our call.
	mem, err := memory.Load(workDir)
	if err != nil {
		return nil, err
	}

	engCtx := engagementContext(eng)
	prompt, err := agent.BuildSystemPrompt(agent.PromptInput{
		Mode:       mode,
		Engagement: engCtx,
		Memory:     mem,
	})
	if err != nil {
		return nil, err
	}

	// The policy engine: one choke point, scope and ROE from the gate (§6).
	engineOpts := []policy.Option{
		policy.WithProjectRules(cfg.Rules),
		policy.WithClock(now),
	}
	if eng != nil {
		engineOpts = append(engineOpts,
			policy.WithScope(eng.Scope()),
			policy.WithROE(eng.ROE()),
		)
	}
	engine, err := policy.NewEngine(mode, engineOpts...)
	if err != nil {
		return nil, err
	}

	tools, err := agent.NewRegistry(agent.ReadFileTool(workDir))
	if err != nil {
		return nil, err
	}

	// Resolve the model before creating any session artifacts: a launch that
	// cannot reach a model should leave no audit trail and no empty session
	// behind.
	client, err := modelClient(ctx, cfg, opts, env)
	if err != nil {
		return nil, err
	}

	// The audit trail is per session, in the project dir, operator-owned
	// (§7.5). Its write failures deny calls, never run unlogged.
	auditWriter, err := audit.OpenSession(workDir, audit.WithClock(now))
	if err != nil {
		return nil, err
	}

	store := sessions.NewStore("", sessions.WithClock(now))
	session, err := store.Open(workDir)
	if err != nil {
		_ = auditWriter.Close()
		return nil, err
	}

	h := &Harness{
		Config:     cfg,
		Mode:       mode,
		Engagement: eng,
		Engine:     engine,
		Tools:      tools,
		Prompt:     prompt,
		WorkDir:    workDir,
		Version:    opts.Version,
		sessions:   store,
		audit:      auditWriter,
		out:        out,
		now:        now,
		session:    session,
	}
	h.Loop = agent.NewLoop(client, tools, engine, auditWriter, prompt,
		agent.WithModel(cfg.Model),
		agent.WithClock(now),
		agent.WithEmitter(h.emit),
	)

	// An engagement gate activation is a session event (§4.3, §7.2).
	if eng != nil {
		h.emit(sessions.Event{Kind: sessions.KindEngagement, Engagement: eng.Name()})
	}
	return h, nil
}

// modelClient builds the model client, or validates an injected one.
func modelClient(ctx context.Context, cfg *config.Config, opts Options, env func(string) string) (model.ModelClient, error) {
	if opts.Client != nil {
		return opts.Client, nil
	}
	key := strings.TrimSpace(env("DEEPSEEK_API_KEY"))
	if key == "" {
		return nil, errors.New("styx: DEEPSEEK_API_KEY is not set; the harness has no model to talk to (§10.5: secrets are env-only)")
	}
	baseURL := strings.TrimSpace(env("STYX_BASE_URL"))
	client, err := model.NewDeepSeek(model.DeepSeekConfig{
		APIKey:       key,
		BaseURL:      baseURL,
		Models:       cfg.ModelInfo(),
		DefaultModel: cfg.Model,
	})
	if err != nil {
		return nil, err
	}
	if !opts.SkipModelCheck {
		if err := client.Validate(ctx); err != nil {
			return nil, fmt.Errorf("styx: model validation failed: %w", err)
		}
	}
	return client, nil
}

// engagementContext renders the §7.4 advisory scope summary, or nil in safe
// mode.
func engagementContext(eng *engagement.Engagement) *agent.EngagementContext {
	if eng == nil {
		return nil
	}
	ctx := &agent.EngagementContext{
		Name:                 eng.Name(),
		Targets:              eng.Targets(),
		ExploitAllowed:       eng.ROE().ExploitAllowed,
		DestructiveForbidden: eng.ROE().DestructiveForbidden,
	}
	if expires, ok := eng.Expires(); ok {
		ctx.Expires = expires.UTC().Format(time.RFC3339)
	}
	return ctx
}

// Submit runs one loop turn for a user input, appending the messages it
// produces to the session conversation.
func (h *Harness) Submit(ctx context.Context, text string) error {
	h.mu.Lock()
	history := append([]model.Message(nil), h.messages...)
	h.mu.Unlock()

	result, err := h.Loop.Run(ctx, history, text)

	h.mu.Lock()
	h.messages = append(h.messages, result.Messages...)
	h.mu.Unlock()
	return err
}

// Messages returns a copy of the session conversation.
func (h *Harness) Messages() []model.Message {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]model.Message(nil), h.messages...)
}

// SessionID is the current session's identifier.
func (h *Harness) SessionID() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.session == nil {
		return ""
	}
	return h.session.ID()
}

// Close releases the session log and the audit trail.
func (h *Harness) Close() error {
	h.mu.Lock()
	session := h.session
	h.session = nil
	h.mu.Unlock()

	var errs []error
	if session != nil {
		errs = append(errs, session.Close())
	}
	if h.audit != nil {
		errs = append(errs, h.audit.Close())
	}
	return errors.Join(errs...)
}

// setUI installs the live event sink (the TUI). Events are still persisted
// whether or not a UI is attached.
func (h *Harness) setUI(ui func(sessions.Event)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ui = ui
}

// emit is the loop's session event bus: persist, then render (§4.3).
func (h *Harness) emit(ev sessions.Event) {
	h.mu.Lock()
	session, ui := h.session, h.ui
	h.mu.Unlock()

	if session != nil {
		if err := session.Record(ev); err != nil && !h.warned {
			h.warned = true
			_, _ = fmt.Fprintf(h.out, "styx: session log is not recording: %v\n", err)
		}
	}
	if ui != nil {
		ui(ev)
	}
}

// Status is the status-bar state for the TUI (§9.1).
func (h *Harness) Status(busy bool) tui.Status {
	return tui.Status{
		Mode:    string(h.Mode),
		Model:   h.Config.Model,
		Session: shortID(h.SessionID()),
		Busy:    busy,
	}
}

// shortID trims a session ID for the one-line status bar.
func shortID(id string) string {
	if len(id) <= 24 {
		return id
	}
	return id[:24]
}

// ListSessions returns the project's past sessions, newest first.
func (h *Harness) ListSessions() ([]sessions.Summary, error) {
	return h.sessions.List(h.WorkDir)
}

// Resume restores a past session's conversation into this process (§10.1).
// The argument may be a full session ID or an unambiguous prefix.
func (h *Harness) Resume(id string) (sessions.Summary, error) {
	summaries, err := h.sessions.List(h.WorkDir)
	if err != nil {
		return sessions.Summary{}, err
	}
	var match *sessions.Summary
	for i := range summaries {
		if summaries[i].ID == id {
			match = &summaries[i]
			break
		}
		if strings.HasPrefix(summaries[i].ID, id) {
			if match != nil {
				return sessions.Summary{}, fmt.Errorf("session %q matches more than one session", id)
			}
			match = &summaries[i]
		}
	}
	if match == nil {
		return sessions.Summary{}, fmt.Errorf("no session matches %q", id)
	}

	events, err := h.sessions.Replay(h.WorkDir, match.ID)
	if err != nil {
		return sessions.Summary{}, err
	}
	conversation := agent.Conversation(events)
	resumed, err := h.sessions.Resume(h.WorkDir, match.ID)
	if err != nil {
		return sessions.Summary{}, err
	}

	h.mu.Lock()
	previous := h.session
	h.session = resumed
	h.messages = conversation
	h.mu.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
	return *match, nil
}

// statusText is the /status rendering.
func (h *Harness) statusText() string {
	lines := []string{
		fmt.Sprintf("mode:     %s", h.Mode),
		fmt.Sprintf("model:    %s", h.Config.Model),
		fmt.Sprintf("session:  %s", h.SessionID()),
		fmt.Sprintf("project:  %s", h.WorkDir),
	}
	if h.Engagement != nil {
		lines = append(lines, fmt.Sprintf("engagement: %s", h.Engagement.Name()))
		lines = append(lines, fmt.Sprintf("targets:  %s", strings.Join(h.Engagement.Targets(), ", ")))
	}
	lines = append(lines, fmt.Sprintf("messages: %d", len(h.Messages())))
	return strings.Join(lines, "\n")
}
