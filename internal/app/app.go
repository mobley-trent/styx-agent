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
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mobley-trent/styx-agent/internal/agent"
	"github.com/mobley-trent/styx-agent/internal/agent/subagent"
	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/config"
	"github.com/mobley-trent/styx-agent/internal/containerlayer"
	"github.com/mobley-trent/styx-agent/internal/engagement"
	"github.com/mobley-trent/styx-agent/internal/mcpclient"
	"github.com/mobley-trent/styx-agent/internal/memory"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/netfetch"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
	"github.com/mobley-trent/styx-agent/internal/skills"
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
	// ContainerRuntime overrides the container engine factory (tests).
	ContainerRuntime func() (containerlayer.Runtime, error)
	// ContainerFirewall overrides the host-edge firewall (tests).
	ContainerFirewall containerlayer.Firewall
	// Executor overrides exec dispatch entirely (tests): when set, no
	// container runtime is constructed.
	Executor agent.Executor
	// MCPConnector overrides how MCP servers are launched (tests). Nil means
	// the stdio launcher, which runs the configured command as a subprocess.
	MCPConnector mcpclient.Connector
	// Fetcher overrides the harness-side web_fetch transport (tests). Nil
	// means the scope-checked netfetch fetcher.
	Fetcher agent.Fetcher
	// LogFetcher overrides the ssh_logs transport (tests). Nil means the
	// scope-checked netfetch fetcher.
	LogFetcher agent.LogFetcher
	// SkipModelCheck disables the startup GET /models validation (§3.1).
	SkipModelCheck bool
	// GlobalSkillsDirs overrides the global skill roots (§8.4). Nil uses the
	// default roots (~/.agents/skills and its XDG data equivalent); an explicit
	// set replaces them, which is how tests stay hermetic.
	GlobalSkillsDirs []string
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
	// skillCatalog is the discovered agent-skill set (§8.4): global and
	// project skills, project shadowing global. It is fixed at build time.
	skillCatalog *skills.Catalog
	// Version is the binary version.
	Version string

	sessions  *sessions.Store
	audit     *audit.Writer
	container *containerlayer.Manager
	mcp       *mcpclient.Manager
	compactor *agent.Compactor
	out       io.Writer
	now       func() time.Time
	warned    bool

	// Wired once at Build and reused across mode switches.
	client         model.ModelClient
	memory         string
	mcpConnector   mcpclient.Connector
	execOverride   agent.Executor
	runtimeFactory func() (containerlayer.Runtime, error)
	firewall       containerlayer.Firewall
	fetcher        agent.Fetcher
	logFetcher     agent.LogFetcher

	mu              sync.Mutex
	session         *sessions.Session
	messages        []model.Message
	engagementStart time.Time
	notesWritten    bool
	ui              func(sessions.Event)
	// ask is the live operator-interaction sink (the TUI's inline cards). Nil
	// means no interactive operator is attached, and guarded actions take
	// their safe default: deny, reject, or no plan.
	ask func(tui.PromptMsg)
	// submitter runs a user turn on the interactive session. The TUI wires its
	// busy-guarded submit here, so a slash command like /<skill-name> can start
	// a turn without blocking the UI. Nil means no interactive session.
	submitter func(string)
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

	// Engagement gate: strict, refuse-to-start validation (§7.2). The launch
	// door and the in-session /engagement door run exactly this gate.
	var eng *engagement.Engagement
	if path := strings.TrimSpace(opts.Engagement); path != "" {
		eng, err = loadEngagement(ctx, path, now)
		if err != nil {
			return nil, fmt.Errorf("styx: refusing to start: %w", err)
		}
	}

	// Project memory (§10.2): absent is fine, malformed is not our call.
	mem, err := memory.Load(workDir)
	if err != nil {
		return nil, err
	}

	// Agent skills (§8.4): global roots then the project directory, project
	// shadowing global by name. A present-but-malformed SKILL.md refuses to
	// start rather than silently dropping a skill the operator expects.
	globalSkills := opts.GlobalSkillsDirs
	if globalSkills == nil {
		globalSkills = skills.GlobalDirs(env)
	}
	catalog, err := skills.Discover(globalSkills, skills.ProjectDir(workDir))
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

	factory := opts.ContainerRuntime
	if factory == nil {
		factory = func() (containerlayer.Runtime, error) { return containerlayer.NewDocker() }
	}

	h := &Harness{
		Config:         cfg,
		Engagement:     eng,
		WorkDir:        workDir,
		Version:        opts.Version,
		sessions:       store,
		audit:          auditWriter,
		compactor:      newCompactor(cfg, client),
		out:            out,
		now:            now,
		session:        session,
		client:         client,
		memory:         mem,
		skillCatalog:   catalog,
		mcpConnector:   opts.MCPConnector,
		execOverride:   opts.Executor,
		runtimeFactory: factory,
		firewall:       opts.ContainerFirewall,
		fetcher:        opts.Fetcher,
		logFetcher:     opts.LogFetcher,
	}
	if eng != nil {
		h.engagementStart = now()
	}
	if err := h.configure(); err != nil {
		_ = h.Close()
		return nil, err
	}

	// An engagement gate activation is a session event (§4.3, §7.2).
	if eng != nil {
		h.emit(sessions.Event{Kind: sessions.KindEngagement, Engagement: eng.Name()})
	}
	return h, nil
}

// loadEngagement is the engagement gate's single implementation (§7.2). Both
// doors — the launch flag and the in-session /engagement command — call it, so
// they share one validation and one refusal.
func loadEngagement(ctx context.Context, path string, now func() time.Time) (*engagement.Engagement, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("engagement: a file path is required")
	}
	return engagement.Load(ctx, path, engagement.WithClock(now))
}

// configure (re)builds everything that depends on the current mode: the
// system prompt, the policy engine, the container egress rules, the network
// tooling, the tool registry, and the loop. Build calls it once; an engagement
// activation or a /mode teardown calls it again, so the scope summary and the
// egress allowlist are torn down and rebuilt with the mode (§7.3).
func (h *Harness) configure() error {
	h.mu.Lock()
	eng := h.Engagement
	h.mu.Unlock()

	mode := policy.ModeSafe
	if eng != nil {
		mode = policy.ModeEngagement
	}

	prompt, err := agent.BuildSystemPrompt(agent.PromptInput{
		Mode:       mode,
		Engagement: engagementContext(eng),
		Memory:     h.memory,
	})
	if err != nil {
		return err
	}

	// The policy engine: one choke point, scope and ROE from the gate (§6).
	engineOpts := []policy.Option{
		policy.WithProjectRules(h.Config.Rules),
		policy.WithClock(h.now),
	}
	if eng != nil {
		engineOpts = append(engineOpts,
			policy.WithScope(eng.Scope()),
			policy.WithROE(eng.ROE()),
		)
	}
	engine, err := policy.NewEngine(mode, engineOpts...)
	if err != nil {
		return err
	}

	// Exec tools run in a per-session container (§5.2). The manager starts the
	// container lazily, on the first exec, so a session that never runs a
	// command never touches Docker. A mode switch replaces the manager and
	// tears the old session's egress rules down (§7.3).
	var container *containerlayer.Manager
	var exec agent.Executor
	if h.execOverride != nil {
		exec = h.execOverride
	} else {
		container = containerlayer.NewManager(containerlayer.ManagerOptions{
			RuntimeFactory: h.runtimeFactory,
			Image:          h.Config.Container.Image,
			Workspace:      h.WorkDir,
			Allowed:        allowedEgress(eng, h.Config),
			Pins:           namePins(eng),
			Firewall:       h.firewall,
			OnStart: func(info containerlayer.SessionInfo) {
				h.emitIsolation(info)
			},
		})
		exec = container
	}

	fetcher, logFetcher := h.networkTooling(eng)

	baseTools := []agent.Tool{
		agent.ReadFileTool(h.WorkDir),
		agent.WriteFileTool(h.WorkDir),
		agent.EditFileTool(h.WorkDir),
		agent.GlobTool(h.WorkDir),
		agent.GrepTool(h.WorkDir),
		agent.BashTool(exec),
		agent.CodeExecTool(exec),
		agent.WebFetchTool(fetcher),
		agent.SSHLogsTool(logFetcher),
		agent.ProposePlanTool(),
	}

	// The skill tool is exposed only for skills whose frontmatter carries
	// model-invocation metadata (§8.4). No invocable skill means no tool.
	if skillTool, ok := agent.SkillTool(h.skillCatalog); ok {
		baseTools = append(baseTools, skillTool)
	}

	// External capabilities through one gate (§5.5): MCP servers are launched
	// per project, and their tools join the session registry as ordinary
	// descriptors — same validation, same policy engine, same audit. A server
	// that fails to launch is a visible lifecycle event, never a startup
	// refusal: the built-ins keep working.
	//
	// The manager is created once and reused across mode switches: a server's
	// reach is bounded per call by the policy engine, which is rebuilt here,
	// so a mode switch need not tear the connections down and relaunch them.
	mcpManager := h.ensureMCP()
	baseTools = append(baseTools, h.mcpTools(mcpManager)...)

	base, err := agent.NewRegistry(baseTools...)
	if err != nil {
		if container != nil {
			_ = container.Close()
		}
		return err
	}

	// Delegation is a tool (§4.2). The runner draws each subagent's allowlist
	// from the base registry — never the delegation tool — and reuses the
	// session's loop options, so a nested run is governed by the same policy
	// engine, audit trail, operator, and container as the main loop.
	dispatcher := subagent.New(subagent.Config{
		Client:   h.client,
		Registry: base,
		Engine:   engine,
		Audit:    h.audit,
		Options:  h.loopOptions(),
		Emit:     h.emit,
		ExploitAllowed: func() bool {
			_, eng := h.modeAndEngagement()
			return eng != nil && eng.ROE().ExploitAllowed
		},
	})
	dispatchTool := agent.DispatchSubagentTool(dispatcher)
	dispatchTool.Description = subagent.ToolDescription()

	tools, err := agent.NewRegistry(append(append([]agent.Tool(nil), baseTools...), dispatchTool)...)
	if err != nil {
		if container != nil {
			_ = container.Close()
		}
		return err
	}

	old := h.container

	h.mu.Lock()
	h.Mode = mode
	h.Prompt = prompt
	h.Engine = engine
	h.Tools = tools
	h.container = container
	h.Loop = agent.NewLoop(h.client, tools, engine, h.audit, prompt, h.loopOptions()...)
	h.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}
	return nil
}

// ensureMCP returns the session's MCP manager, creating and starting it on
// first use (§5.5). A project that configures no servers gets no manager, so a
// session that uses none never launches a subprocess. It is created once and
// reused: MCP servers are not mode-dependent, so a mode switch must not
// relaunch them.
func (h *Harness) ensureMCP() *mcpclient.Manager {
	servers := h.Config.MCP.Enabled()
	if len(servers) == 0 {
		return nil
	}

	h.mu.Lock()
	if h.mcp != nil {
		manager := h.mcp
		h.mu.Unlock()
		return manager
	}
	h.mu.Unlock()

	opts := []mcpclient.Option{mcpclient.WithEmitter(func(ev mcpclient.Event) {
		h.emit(sessions.Event{
			Kind:   sessions.KindMCP,
			Server: ev.Server,
			Status: string(ev.Status),
			Detail: ev.Detail,
		})
	})}
	if h.mcpConnector != nil {
		opts = append(opts, mcpclient.WithConnector(h.mcpConnector))
	}
	manager := mcpclient.New(opts...)

	configured := make([]mcpclient.Server, 0, len(servers))
	for _, s := range servers {
		configured = append(configured, mcpclient.Server{
			Name:    s.Name,
			Command: s.Command,
			Args:    s.Args,
			Env:     s.Env,
		})
	}
	// The servers are launched against a process-lifetime context, not the
	// build call's: a server session outlives any single request, and its
	// lifetime is bounded by Manager.Close at session end.
	manager.Start(context.Background(), configured)

	h.mu.Lock()
	h.mcp = manager
	h.mu.Unlock()
	return manager
}

// mcpTools adapts the manager's currently-connected tools into agent tools
// (§5.5). A server that has dropped contributes no tools, so a rebuilt
// registry never advertises a dead server's capabilities.
func (h *Harness) mcpTools(manager *mcpclient.Manager) []agent.Tool {
	if manager == nil {
		return nil
	}
	var sources []agent.MCPToolSource
	for _, tool := range manager.Tools() {
		server, name := tool.Server, tool.Name
		sources = append(sources, agent.MCPToolSource{
			Name:        tool.Namespaced(),
			Description: tool.Description,
			Parameters:  tool.Schema,
			Call: func(ctx context.Context, args map[string]any) (string, error) {
				return manager.Call(ctx, server, name, args)
			},
		})
	}
	return agent.MCPTools(sources...)
}

// loopOptions are the loop options shared by every mode's loop.
func (h *Harness) loopOptions() []agent.LoopOption {
	return []agent.LoopOption{
		agent.WithModel(h.Config.Model),
		agent.WithClock(h.now),
		agent.WithEmitter(h.emit),
		agent.WithPrompter(operator{h}),
		agent.WithDiffReviewer(operator{h}),
		agent.WithPlanApprover(operator{h}),
		agent.WithIsolationProvider(func() audit.Isolation { return h.isolation() }),
		agent.WithCompactor(h.compactor),
	}
}

// newCompactor builds the session's context compactor from the merged config
// and the active model's context window (§4.5, §3.1). The compactor is
// stateless, so one instance is shared by the main and subagent loops.
func newCompactor(cfg *config.Config, client model.ModelClient) *agent.Compactor {
	window := 0
	if m, ok := cfg.ModelByID(cfg.Model); ok {
		window = m.ContextWindow
	}
	return agent.NewCompactor(agent.CompactionSettings{
		Mode:          cfg.Compaction.Mode,
		Threshold:     cfg.Compaction.Threshold,
		KeepTurns:     cfg.Compaction.KeepTurns,
		ContextWindow: window,
	}, agent.NewModelSummarizer(client, cfg.Model), nil)
}

// networkTooling returns the scope-checked fetchers for the current mode. The
// production fetcher re-resolves every destination and refuses anything outside
// the engagement's pinned scope; safe mode passes no scope, where the policy
// prompt is the guard.
func (h *Harness) networkTooling(eng *engagement.Engagement) (agent.Fetcher, agent.LogFetcher) {
	if h.fetcher != nil || h.logFetcher != nil {
		return h.fetcher, h.logFetcher
	}
	var scope netfetch.Scope
	if eng != nil {
		scope = eng.Scope()
	}
	f := netfetch.New(netfetch.Options{Scope: scope})
	return f, f
}

// ActivateEngagement runs the in-session door of the engagement gate (§7.2):
// the same validation and refusal as the launch flag. On success it injects the
// scope summary into the system prompt and rebuilds the engine, registry, and
// egress allowlist for engagement mode. It refuses when an engagement is
// already active — return to safe mode with /mode first.
func (h *Harness) ActivateEngagement(ctx context.Context, path string) error {
	h.mu.Lock()
	active := h.Engagement != nil
	h.mu.Unlock()
	if active {
		return errors.New("an engagement is already active; run /mode safe before activating another")
	}

	eng, err := loadEngagement(ctx, path, h.now)
	if err != nil {
		return err
	}

	h.mu.Lock()
	h.Engagement = eng
	h.mu.Unlock()
	if err := h.configure(); err != nil {
		// Roll back to safe mode if the rebuild fails, so the harness never
		// sits in engagement mode with stale enforcement.
		h.mu.Lock()
		h.Engagement = nil
		h.mu.Unlock()
		_ = h.configure()
		return fmt.Errorf("styx: engagement activation failed: %w", err)
	}

	h.mu.Lock()
	h.engagementStart = h.now()
	h.mu.Unlock()
	h.emit(sessions.Event{Kind: sessions.KindEngagement, Engagement: eng.Name()})
	return nil
}

// Deactivate returns the harness to safe mode (§7.3): it appends the
// engagement notes to STYX.md, tears down the scope summary and the container
// egress allowlist, and rebuilds the safe-mode engine. It is a no-op when no
// engagement is active.
func (h *Harness) Deactivate() error {
	h.mu.Lock()
	eng := h.Engagement
	h.Engagement = nil
	h.mu.Unlock()
	if eng == nil {
		return nil
	}

	var errs []error
	if err := h.writeEngagementNotes(eng); err != nil {
		errs = append(errs, err)
	}
	if err := h.configure(); err != nil {
		errs = append(errs, err)
	}
	h.emit(sessions.Event{Kind: sessions.KindEngagement, Detail: "safe mode: engagement " + eng.Name() + " torn down"})
	return errors.Join(errs...)
}

// writeEngagementNotes appends the engagement's structured notes to STYX.md
// once, at engagement end (§7.5, §10.2). The block is assembled from the
// engagement file and the session's own records; the model never authors it.
func (h *Harness) writeEngagementNotes(eng *engagement.Engagement) error {
	h.mu.Lock()
	if h.notesWritten {
		h.mu.Unlock()
		return nil
	}
	h.notesWritten = true
	started := h.engagementStart
	sessionID := ""
	if h.session != nil {
		sessionID = h.session.ID()
	}
	h.mu.Unlock()

	tools, artifacts := h.sessionSummary(sessionID)
	notes := memory.EngagementNotes{
		Name:                 eng.Name(),
		Operator:             eng.Operator(),
		Targets:              eng.Targets(),
		ExploitAllowed:       eng.ROE().ExploitAllowed,
		DestructiveForbidden: eng.ROE().DestructiveForbidden,
		Ended:                h.now().UTC().Format(time.RFC3339),
		Tools:                tools,
		Artifacts:            artifacts,
	}
	if expires, ok := eng.Expires(); ok {
		notes.Expires = expires.UTC().Format(time.RFC3339)
	}
	if !started.IsZero() {
		notes.Started = started.UTC().Format(time.RFC3339)
	}

	_, err := memory.AppendEngagementNotes(h.WorkDir, notes)
	if err != nil {
		// A notes write failed: let a later attempt retry rather than losing
		// the record of the engagement.
		h.mu.Lock()
		h.notesWritten = false
		h.mu.Unlock()
		return err
	}
	return nil
}

// sessionSummary folds the session's events into the notes' tool counts and
// artifact list.
func (h *Harness) sessionSummary(sessionID string) (map[string]int, []string) {
	tools := map[string]int{}
	artifacts := map[string]bool{}
	if strings.TrimSpace(sessionID) == "" {
		return tools, nil
	}
	events, err := h.sessions.Replay(h.WorkDir, sessionID)
	if err != nil {
		return tools, nil
	}
	for _, ev := range events {
		switch ev.Kind {
		case sessions.KindToolCall:
			if ev.Tool != "" {
				tools[ev.Tool]++
			}
		case sessions.KindDiff:
			if ev.Path != "" {
				artifacts[ev.Path] = true
			}
		}
	}
	out := make([]string, 0, len(artifacts))
	for path := range artifacts {
		out = append(out, path)
	}
	sort.Strings(out)
	return tools, out
}

// ListEngagementFiles returns the engagement files discovered under the
// project directory for the /engagement picker, sorted.
func (h *Harness) ListEngagementFiles() []string {
	patterns := []string{
		"*.engagement.yaml", "*.engagement.yml",
		"engagement.yaml", "engagement.yml",
		filepath.Join(".styx", "*.yaml"), filepath.Join(".styx", "*.yml"),
	}
	seen := map[string]bool{}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(h.WorkDir, pattern))
		if err != nil {
			continue
		}
		for _, m := range matches {
			seen[m] = true
		}
	}
	out := make([]string, 0, len(seen))
	for path := range seen {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
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

// allowedEgress is the container egress allowlist (§5.2): the engagement's
// pinned scope plus any operator-configured extra destinations (model
// endpoint, package mirrors).
func allowedEgress(eng *engagement.Engagement, cfg *config.Config) []netip.Prefix {
	var out []netip.Prefix
	if eng != nil {
		for _, ip := range eng.Scope().Pins() {
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
		}
		out = append(out, eng.Scope().Prefixes()...)
	}
	for _, entry := range cfg.Container.EgressAllow {
		s := strings.TrimSpace(entry)
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		if ip, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	return out
}

// namePins maps the engagement's authorized names onto the container layer's
// resolver pins (§5.2): the harness answers exactly these names and nothing
// else.
func namePins(eng *engagement.Engagement) []containerlayer.NamePin {
	if eng == nil {
		return nil
	}
	hosts := eng.Scope().HostPins()
	out := make([]containerlayer.NamePin, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, containerlayer.NamePin{Name: h.Name, Wildcard: h.Wildcard, Addrs: h.Addrs})
	}
	return out
}

// isolation is the container enforcement level for the status bar and the
// audit trail. An unstarted or unavailable container reports "" so nothing
// claims enforced egress it does not have.
func (h *Harness) isolation() audit.Isolation {
	h.mu.Lock()
	container := h.container
	h.mu.Unlock()
	if container == nil {
		return ""
	}
	switch container.Isolation() {
	case containerlayer.IsolationContainer, containerlayer.IsolationDegraded:
		return audit.Isolation(container.Isolation())
	default:
		return ""
	}
}

// modeAndEngagement reads the current mode and engagement together, under the
// lock a concurrent mode switch also takes.
func (h *Harness) modeAndEngagement() (policy.Mode, *engagement.Engagement) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.Mode, h.Engagement
}

// emitIsolation surfaces the session's isolation level once, three ways
// (§5.2, §9.5): the status bar reads it, the stream renders this banner, and
// the audit trail records the level on every subsequent call.
func (h *Harness) emitIsolation(info containerlayer.SessionInfo) {
	detail := "container isolation: egress enforced at the host edge"
	if info.Degraded {
		detail = "degraded isolation: the host firewall could not be programmed; the session container has no external network and egress is limited to pinned scope through the harness proxy"
	}
	h.emit(sessions.Event{Kind: sessions.KindIsolation, Detail: detail, Isolation: string(info.Isolation)})
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
	if w := eng.ROE().TimeWindow; w != nil {
		tz := w.TZ
		if tz == "" {
			tz = "UTC"
		}
		ctx.TimeWindow = fmt.Sprintf("%s–%s %s", w.Start, w.End, tz)
	}
	if expires, ok := eng.Expires(); ok {
		ctx.Expires = expires.UTC().Format(time.RFC3339)
	}
	return ctx
}

// Submit runs one loop turn for a user input and replaces the session
// conversation with the run's result: the loop returns the full post-run
// conversation, already compacted if it crossed the threshold (§4.5).
func (h *Harness) Submit(ctx context.Context, text string) error {
	h.mu.Lock()
	history := append([]model.Message(nil), h.messages...)
	// Capture the loop so a concurrent /mode switch cannot swap it mid-turn.
	loop := h.Loop
	h.mu.Unlock()

	result, err := loop.Run(ctx, history, text)

	// The loop returns the full post-run conversation (post-compaction, §4.5):
	// replace rather than append so a compaction is never undone by the next
	// turn replaying the old history.
	h.mu.Lock()
	h.messages = append([]model.Message(nil), result.Messages...)
	h.mu.Unlock()
	return err
}

// Compact runs the manual /compact override (§4.5): it compacts the session
// conversation now, ignoring the threshold, and honors an optional custom
// instruction. The resulting conversation replaces the session's context and
// the compaction is emitted as a session event.
func (h *Harness) Compact(ctx context.Context, instruction string) (string, error) {
	h.mu.Lock()
	compactor := h.compactor
	conversation := append([]model.Message(nil), h.messages...)
	h.mu.Unlock()

	if compactor == nil {
		return "", errors.New("compaction is not configured")
	}
	if len(conversation) == 0 {
		return "nothing to compact yet", nil
	}

	out, result, err := compactor.Compact(ctx, conversation, instruction)
	if err != nil {
		return "", err
	}
	if result == nil {
		return "nothing to compact (the recent turns are kept verbatim)", nil
	}

	h.mu.Lock()
	h.messages = out
	h.mu.Unlock()
	h.emit(sessions.Event{Kind: sessions.KindCompaction, Detail: result.Detail})
	return result.Detail, nil
}

// CompactionLevel is the current context-window fill fraction, with whether
// the model's context window is known. It feeds the status bar (§9.1).
func (h *Harness) CompactionLevel() (float64, bool) {
	h.mu.Lock()
	compactor := h.compactor
	messages := append([]model.Message(nil), h.messages...)
	h.mu.Unlock()
	if compactor == nil || compactor.Settings().ContextWindow <= 0 {
		return 0, false
	}
	return compactor.Level(messages), true
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

// Close releases the session log and the audit trail. An engagement still
// active at close ends here: its notes are appended to STYX.md before the
// session log is released (§7.5, §10.2).
func (h *Harness) Close() error {
	h.mu.Lock()
	eng := h.Engagement
	h.Engagement = nil
	h.mu.Unlock()

	var errs []error
	if eng != nil {
		errs = append(errs, h.writeEngagementNotes(eng))
	}

	h.mu.Lock()
	session := h.session
	h.session = nil
	container := h.container
	h.container = nil
	mcp := h.mcp
	h.mcp = nil
	h.mu.Unlock()

	if session != nil {
		errs = append(errs, session.Close())
	}
	if mcp != nil {
		errs = append(errs, mcp.Close())
	}
	if container != nil {
		errs = append(errs, container.Close())
	}
	if h.audit != nil {
		errs = append(errs, h.audit.Close())
	}
	return errors.Join(errs...)
}

// MCPServers returns the configured servers' lifecycle states, for the status
// bar and /status (§5.5, §9.1).
func (h *Harness) MCPServers() []mcpclient.ServerStatus {
	h.mu.Lock()
	mcp := h.mcp
	h.mu.Unlock()
	if mcp == nil {
		return nil
	}
	return mcp.Statuses()
}

// setUI installs the live event sink (the TUI). Events are still persisted
// whether or not a UI is attached.
func (h *Harness) setUI(ui func(sessions.Event)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ui = ui
}

// setPromptUI installs the live operator-interaction sink (the TUI's inline
// cards).
func (h *Harness) setPromptUI(ask func(tui.PromptMsg)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ask = ask
}

// setSubmitter installs the live session's turn submitter, so a slash command
// can start a turn without blocking the UI goroutine.
func (h *Harness) setSubmitter(submit func(string)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.submitter = submit
}

// askOperator delivers one card to the TUI and waits for the operator's
// choice. An empty choice means no interactive operator is attached; callers
// then take their safe default. The wait is bounded by ctx.
func (h *Harness) askOperator(ctx context.Context, p tui.Prompt) (string, error) {
	h.mu.Lock()
	ask := h.ask
	h.mu.Unlock()
	if ask == nil {
		return "", nil
	}
	reply := make(chan string, 1)
	ask(tui.PromptMsg{Prompt: p, Reply: func(choice string) {
		select {
		case reply <- choice:
		default:
		}
	}})
	select {
	case choice := <-reply:
		return choice, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// operator adapts the harness's live TUI interaction onto the agent's
// prompter, diff-reviewer, and plan-approver interfaces. It is a distinct type
// because the Harness already has a Prompt field (the system prompt).
type operator struct{ h *Harness }

// Prompt implements agent.Prompter (§6.4, §9.3): it renders an inline
// permission card and maps the operator's choice onto a loop decision.
func (o operator) Prompt(ctx context.Context, req agent.PromptRequest) (agent.Decision, error) {
	choice, err := o.h.askOperator(ctx, tui.Prompt{
		Kind:     tui.PromptPermission,
		Tool:     req.Tool,
		Params:   req.Params,
		Reason:   string(req.Reason),
		Risk:     riskClass(req.Tool),
		Subagent: req.Subagent,
	})
	if err != nil {
		return agent.DecisionDeny, err
	}
	switch choice {
	case tui.ChoiceAllowOnce:
		return agent.DecisionAllowOnce, nil
	case tui.ChoiceAllowSession:
		return agent.DecisionAllowSession, nil
	default:
		return agent.DecisionDeny, nil
	}
}

// Review implements agent.DiffReviewer (§9.2): it renders a staged write's
// diff and maps the operator's choice onto a review decision.
func (o operator) Review(ctx context.Context, req agent.DiffRequest) (agent.DiffDecision, error) {
	choice, err := o.h.askOperator(ctx, tui.Prompt{
		Kind:     tui.PromptDiff,
		Tool:     req.Tool,
		Params:   req.Params,
		Path:     req.Diff.Path,
		Diff:     req.Diff,
		Subagent: req.Subagent,
	})
	if err != nil {
		return agent.DiffReject, err
	}
	switch choice {
	case tui.ChoiceAccept:
		return agent.DiffAccept, nil
	case tui.ChoiceAcceptRest:
		return agent.DiffAcceptRest, nil
	default:
		return agent.DiffReject, nil
	}
}

// Approve implements agent.PlanApprover (§9.2): it renders a plan-approval
// card and reports whether the operator pre-authorized the turn.
func (o operator) Approve(ctx context.Context, plan agent.Plan) (bool, error) {
	steps := make([]sessions.PlanStep, 0, len(plan.Actions))
	for _, a := range plan.Actions {
		steps = append(steps, sessions.PlanStep{Tool: a.Tool, Params: a.Params})
	}
	choice, err := o.h.askOperator(ctx, tui.Prompt{
		Kind:  tui.PromptPlan,
		Steps: steps,
	})
	if err != nil {
		return false, err
	}
	return choice == tui.ChoiceApprove, nil
}

// riskClass names a tool's risk class for the permission card (§9.3).
func riskClass(tool string) string {
	switch tool {
	case "read_file", "glob", "grep":
		return "read"
	case "write_file", "edit_file":
		return "write"
	case "bash", "code_exec":
		return "exec"
	case "web_fetch", "ssh_logs":
		return "network"
	case "dispatch_subagent":
		return "delegation"
	case agent.PlanToolName:
		return "plan"
	default:
		return ""
	}
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
	mode, _ := h.modeAndEngagement()
	return tui.Status{
		Mode:       string(mode),
		Model:      h.Config.Model,
		Session:    shortID(h.SessionID()),
		Isolation:  string(h.isolation()),
		MCP:        mcpStatusText(h.MCPServers()),
		Compaction: h.compactionText(),
		Busy:       busy,
	}
}

// compactionText is the status bar's context-fill readout (§4.5, §9.1).
func (h *Harness) compactionText() string {
	level, ok := h.CompactionLevel()
	if !ok {
		return ""
	}
	return fmt.Sprintf("ctx %.0f%%", level*100)
}

// mcpStatusText summarizes MCP server connectivity for the status bar (§5.5,
// §9.1): "mcp 2/2" when all are ready, "mcp 1/2" when one failed. It is empty
// when the project configures no servers.
func mcpStatusText(statuses []mcpclient.ServerStatus) string {
	if len(statuses) == 0 {
		return ""
	}
	ready := 0
	for _, s := range statuses {
		if s.Status == mcpclient.StatusReady {
			ready++
		}
	}
	return fmt.Sprintf("mcp %d/%d", ready, len(statuses))
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
	mode, eng := h.modeAndEngagement()
	lines := []string{
		fmt.Sprintf("mode:     %s", mode),
		fmt.Sprintf("model:    %s", h.Config.Model),
		fmt.Sprintf("session:  %s", h.SessionID()),
		fmt.Sprintf("project:  %s", h.WorkDir),
	}
	if eng != nil {
		lines = append(lines, fmt.Sprintf("engagement: %s", eng.Name()))
		lines = append(lines, fmt.Sprintf("targets:  %s", strings.Join(eng.Targets(), ", ")))
	}
	if iso := h.isolation(); iso != "" {
		lines = append(lines, fmt.Sprintf("isolation: %s", iso))
	}
	if level, ok := h.CompactionLevel(); ok {
		lines = append(lines, fmt.Sprintf("context:  %.0f%% of the model window", level*100))
	}
	for _, s := range h.MCPServers() {
		lines = append(lines, fmt.Sprintf("mcp:      %s %s (%s)", s.Name, s.Status, s.Detail))
	}
	lines = append(lines, fmt.Sprintf("messages: %d", len(h.Messages())))
	return strings.Join(lines, "\n")
}
