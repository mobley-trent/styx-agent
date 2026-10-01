package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/repair"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// Bounds (§4.1, §3.3). Every one is config-overridable through the loop's
// options; these are the spec defaults.
const (
	// DefaultMaxTurns is the main loop's turn cap.
	DefaultMaxTurns = 200
	// DefaultMaxParallel is the parallel tool-dispatch cap.
	DefaultMaxParallel = 8
	// DefaultMaxRepairs is the repair budget per turn before the turn aborts.
	DefaultMaxRepairs = 2
	// DefaultMaxToolOutput is the per-result capture truncation cap.
	DefaultMaxToolOutput = 64 * 1024
)

// Errors the loop reports. Callers branch on these with errors.Is.
var (
	// ErrTurnCap is a loop that hit its turn bound without a final answer.
	ErrTurnCap = errors.New("agent: turn cap reached")
	// ErrStreamIncomplete is a model stream that ended without either a
	// completion event or an error — the turn's outcome is unknown.
	ErrStreamIncomplete = errors.New("agent: model stream ended without a completion event")
)

// AuditWriter is the loop's audit sink: one record per tool call, written
// before execution. It is fail-closed — a write error denies the call (§6.5).
type AuditWriter interface {
	Append(rec audit.Record) error
}

// Decision is an operator's resolution of a permission prompt (§6.4).
type Decision string

const (
	// DecisionAllowOnce runs this call only.
	DecisionAllowOnce Decision = "allow-once"
	// DecisionAllowSession runs this call and, for the rest of the session,
	// any call it matches.
	DecisionAllowSession Decision = "allow-session"
	// DecisionDeny refuses the call.
	DecisionDeny Decision = "deny"
)

// PromptRequest is one live permission ask (§9.3): enough for the TUI to
// render tool, parameters, and why the engine prompted.
type PromptRequest struct {
	// Tool is the invoked tool's name.
	Tool string
	// Params is the call's verbatim parameter object.
	Params map[string]any
	// Reason is the engine's audit-facing reason (out-of-scope, rule-match,
	// default-table).
	Reason policy.Reason
}

// Prompter resolves a *prompt* verdict. It is the harness's live ask; the
// session-scoped allow decisions it returns are remembered by the loop.
type Prompter interface {
	Prompt(ctx context.Context, req PromptRequest) (Decision, error)
}

// DenyPrompter refuses every prompt. It is the default, and the safe one: a
// loop with no interactive prompter never widens a guarded action on its own.
type DenyPrompter struct{}

// Prompt implements Prompter.
func (DenyPrompter) Prompt(context.Context, PromptRequest) (Decision, error) {
	return DecisionDeny, nil
}

// Result is one completed loop run.
type Result struct {
	// Answer is the model's final answer text.
	Answer string
	// Messages are the messages the run appended after the history it was
	// given: assistant turns and tool results, in order.
	Messages []model.Message
	// Turns is how many model turns the run consumed.
	Turns int
}

// Loop is the single hand-rolled agent cycle (§4.1): system-prompt assembly →
// model call → repair/validation → policy verdicts → audit → dispatch →
// results → repeat, bounded by the turn cap. It is safe for one Run at a time;
// the app owns a session's loop.
type Loop struct {
	client      model.ModelClient
	tools       *Registry
	engine      *policy.Engine
	audit       AuditWriter
	prompt      string
	model       string
	maxTurns    int
	maxParallel int
	maxRepairs  int
	maxOutput   int
	prompter    Prompter
	emit        func(sessions.Event)
	now         func() time.Time

	mu      sync.Mutex
	session map[string]bool
}

// LoopOption configures a Loop at construction.
type LoopOption func(*Loop)

// WithMaxTurns overrides the turn cap.
func WithMaxTurns(n int) LoopOption {
	return func(l *Loop) {
		if n > 0 {
			l.maxTurns = n
		}
	}
}

// WithMaxParallel overrides the parallel-dispatch cap.
func WithMaxParallel(n int) LoopOption {
	return func(l *Loop) {
		if n > 0 {
			l.maxParallel = n
		}
	}
}

// WithMaxRepairs overrides the per-turn repair budget.
func WithMaxRepairs(n int) LoopOption {
	return func(l *Loop) {
		if n >= 0 {
			l.maxRepairs = n
		}
	}
}

// WithMaxToolOutput overrides the per-result truncation cap, in bytes.
func WithMaxToolOutput(n int) LoopOption {
	return func(l *Loop) {
		if n > 0 {
			l.maxOutput = n
		}
	}
}

// WithPrompter sets the permission prompter. Nil keeps the deny-by-default
// prompter.
func WithPrompter(p Prompter) LoopOption {
	return func(l *Loop) {
		if p != nil {
			l.prompter = p
		}
	}
}

// WithEmitter sets the session event bus (§4.3). Every event the loop
// produces — deltas, messages, calls, verdicts, results, errors — is
// published here; the TUI and the session JSONL are both consumers.
func WithEmitter(emit func(sessions.Event)) LoopOption {
	return func(l *Loop) {
		if emit != nil {
			l.emit = emit
		}
	}
}

// WithClock overrides the clock the loop stamps emitted events with.
func WithClock(now func() time.Time) LoopOption {
	return func(l *Loop) {
		if now != nil {
			l.now = now
		}
	}
}

// WithModel overrides the model ID requests name. Empty keeps the client's
// configured default.
func WithModel(id string) LoopOption {
	return func(l *Loop) {
		l.model = id
	}
}

// NewLoop builds a loop. Then systemPrompt is the byte-stable prefix (§3.3);
// the audit writer may be nil, in which case every call is denied — the
// fail-closed reading of "the audit trail could not be written".
func NewLoop(client model.ModelClient, tools *Registry, engine *policy.Engine, aud AuditWriter, systemPrompt string, opts ...LoopOption) *Loop {
	l := &Loop{
		client:      client,
		tools:       tools,
		engine:      engine,
		audit:       aud,
		prompt:      systemPrompt,
		maxTurns:    DefaultMaxTurns,
		maxParallel: DefaultMaxParallel,
		maxRepairs:  DefaultMaxRepairs,
		maxOutput:   DefaultMaxToolOutput,
		prompter:    DenyPrompter{},
		session:     make(map[string]bool),
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// Run executes the loop for one user input against a prior conversation. The
// history is what a resumed session replays (§10.1); the loop prepends the
// system prompt itself and never persists it.
func (l *Loop) Run(ctx context.Context, history []model.Message, input string) (Result, error) {
	messages := make([]model.Message, 0, len(history)+4)
	messages = append(messages, model.Message{Role: model.RoleSystem, Content: l.prompt})
	messages = append(messages, history...)
	messages = append(messages, model.Message{Role: model.RoleUser, Content: input})
	l.emitEvent(sessions.Event{Kind: sessions.KindUser, Text: input})

	// One repair budget per run, not per model turn: a repair spans model
	// turns — the model is told what was wrong and calls again (§4.1).
	repairer := repair.NewRepairer(repair.NewValidator(l.tools.Descriptors()), l.maxRepairs)

	base := 1 + len(history)
	for turn := 1; ; turn++ {
		if turn > l.maxTurns {
			err := fmt.Errorf("%w: %d turns without a final answer", ErrTurnCap, l.maxTurns)
			l.emitEvent(sessions.Event{Kind: sessions.KindError, Turn: turn, Failure: err.Error()})
			return Result{Turns: turn - 1, Messages: messages[base:]}, err
		}

		out, err := l.streamTurn(ctx, messages, turn)
		if err != nil {
			l.emitEvent(sessions.Event{Kind: sessions.KindError, Turn: turn, Failure: err.Error()})
			return Result{Turns: turn, Messages: messages[base:]}, err
		}

		messages = append(messages, model.Message{
			Role:      model.RoleAssistant,
			Content:   out.text,
			Reasoning: out.reasoning,
			ToolCalls: out.calls,
		})
		l.emitEvent(sessions.Event{
			Kind:      sessions.KindAssistant,
			Turn:      turn,
			Text:      out.text,
			Reasoning: out.reasoning,
			Calls:     callRefs(out.calls),
		})

		if len(out.calls) == 0 {
			return Result{Answer: out.text, Turns: turn, Messages: messages[base:]}, nil
		}

		results, err := l.dispatch(ctx, repairer, out.calls, turn)
		messages = append(messages, results...)
		if err != nil {
			l.emitEvent(sessions.Event{Kind: sessions.KindError, Turn: turn, Failure: err.Error()})
			return Result{Turns: turn, Messages: messages[base:]}, err
		}
	}
}

// turnOutput is one streamed model turn, assembled.
type turnOutput struct {
	text      string
	reasoning string
	calls     []model.ToolCall
	usage     *model.Usage
}

// streamTurn consumes one model stream, emitting deltas live and returning the
// assembled turn.
func (l *Loop) streamTurn(ctx context.Context, messages []model.Message, turn int) (turnOutput, error) {
	ch, err := l.client.StreamTurn(ctx, model.ModelRequest{
		Model:    l.model,
		Messages: messages,
		Tools:    l.tools.Descriptors(),
	})
	if err != nil {
		return turnOutput{}, err
	}

	var out turnOutput
	done := false
	for ev := range ch {
		switch ev.Kind {
		case model.EventTextDelta:
			out.text += ev.Text
			l.emitEvent(sessions.Event{Kind: sessions.KindTextDelta, Turn: turn, Text: ev.Text})
		case model.EventReasoningDelta:
			out.reasoning += ev.Reasoning
			l.emitEvent(sessions.Event{Kind: sessions.KindReasoningDelta, Turn: turn, Text: ev.Reasoning})
		case model.EventToolCall:
			if ev.ToolCall != nil {
				out.calls = append(out.calls, *ev.ToolCall)
			}
		case model.EventDone:
			out.usage = ev.Usage
			done = true
		case model.EventError:
			if ev.Err != nil {
				return out, ev.Err
			}
			return out, ErrStreamIncomplete
		}
	}
	if !done {
		return out, ErrStreamIncomplete
	}
	return out, nil
}

// admission is one tool call after validation and the policy gate: either it
// is cleared to execute, or it already has the result text the model will see
// (a validation failure, a denial, or a fail-closed audit error).
type admission struct {
	call     model.ToolCall
	tool     Tool
	params   map[string]any
	exec     bool
	content  string
	resolved bool
}

// message is the tool message this admission contributes to the conversation.
func (a admission) message() model.Message {
	return model.Message{Role: model.RoleTool, ToolCallID: a.call.ID, Content: a.content}
}

// dispatch runs the normative order (§5.3) over one turn's tool calls: schema
// validation → policy verdict → audit write → dispatch, then returns the tool
// messages in call order. Execution is parallel, bounded by the parallel cap.
func (l *Loop) dispatch(ctx context.Context, repairer *repair.Repairer, calls []model.ToolCall, turn int) ([]model.Message, error) {
	admissions := make([]admission, len(calls))
	var toRun []int
	for i, call := range calls {
		adm, err := l.admit(ctx, repairer, call, turn)
		admissions[i] = adm
		if err != nil {
			// The repair budget is spent: the turn aborts, but the calls
			// already resolved still belong to the conversation. Calls
			// admitted but not yet dispatched get an abort result rather
			// than an empty one.
			l.abandon(ctx, admissions, turn)
			return messagesFor(admissions), fmt.Errorf("%w: %w", repair.ErrTurnAborted, err)
		}
		if adm.exec {
			toRun = append(toRun, i)
		}
	}

	l.runAll(ctx, admissions, toRun, turn)

	return messagesFor(admissions), nil
}

// abandon resolves every admitted-but-undispatched call with an abort result,
// so the model always sees an answer for each call it made.
func (l *Loop) abandon(_ context.Context, admissions []admission, turn int) {
	for i := range admissions {
		adm := &admissions[i]
		if !adm.resolved || !adm.exec || adm.content != "" {
			continue
		}
		adm.exec = false
		adm.content = "call not executed: the turn aborted before dispatch"
		l.emitEvent(sessions.Event{Kind: sessions.KindToolResult, Turn: turn, Tool: adm.call.Name, CallID: adm.call.ID, Failure: adm.content})
	}
}

// messagesFor collects the admissions' tool messages in call order. Only
// resolved admissions contribute: a call the dispatch never reached (the turn
// aborted before it) has no result to report, and inventing one would leave
// the model an empty answer to a call it made.
func messagesFor(admissions []admission) []model.Message {
	out := make([]model.Message, 0, len(admissions))
	for _, adm := range admissions {
		if !adm.resolved {
			continue
		}
		out = append(out, adm.message())
	}
	return out
}

// admit validates one call, resolves its verdict, and writes its audit record
// before it may execute. A nil error means "the turn may continue"; a non-nil
// error is fatal to the turn (the repair budget is spent).
func (l *Loop) admit(ctx context.Context, repairer *repair.Repairer, call model.ToolCall, turn int) (admission, error) {
	adm := admission{call: call}

	// 1. Schema validation (repair layer, §4.1). The abort check comes first:
	// the exhausted-budget error wraps the feedback, so a bare errors.As would
	// mistake it for one more repair to feed back.
	if err := repairer.Check(call); err != nil {
		adm.resolved = true
		if errors.Is(err, repair.ErrTurnAborted) {
			// The turn aborts, but the call still gets a result: the
			// conversation must not keep an assistant turn whose tool calls
			// went unanswered, or a resumed session would replay an invalid
			// exchange.
			adm.content = fmt.Sprintf("call not executed: %v", err)
			l.emitEvent(sessions.Event{Kind: sessions.KindToolResult, Turn: turn, Tool: call.Name, CallID: call.ID, Failure: adm.content})
			return adm, err
		}
		var feedback *repair.Feedback
		if errors.As(err, &feedback) {
			adm.content = feedback.Error()
			l.emitEvent(sessions.Event{
				Kind:    sessions.KindToolResult,
				Turn:    turn,
				Tool:    call.Name,
				CallID:  call.ID,
				Failure: adm.content,
			})
			return adm, nil
		}
		return adm, err
	}

	adm.resolved = true
	params, err := call.Params()
	if err != nil {
		// Defense in depth: validation passed, so decoding should not fail.
		adm.content = fmt.Sprintf("invalid arguments for tool %q: %v", call.Name, err)
		l.emitEvent(sessions.Event{Kind: sessions.KindToolResult, Turn: turn, Tool: call.Name, CallID: call.ID, Failure: adm.content})
		return adm, nil
	}
	tool, ok := l.tools.Lookup(call.Name)
	if !ok {
		adm.content = fmt.Sprintf("unknown tool %q: it is not in this session's tool set", call.Name)
		l.emitEvent(sessions.Event{Kind: sessions.KindToolResult, Turn: turn, Tool: call.Name, CallID: call.ID, Failure: adm.content})
		return adm, nil
	}

	// 2. Policy verdict (§6.1).
	verdict := l.engine.Decide(policy.Call{
		Tool:         call.Name,
		Params:       params,
		ScopeTargets: toolTargets(tool, params),
		Destructive:  tool.Destructive,
		ExploitClass: tool.ExploitClass,
	})

	// 3. Resolve a prompt live (§6.4).
	auditVerdict, err := l.resolve(ctx, verdict, call, params)
	if err != nil {
		adm.content = fmt.Sprintf("tool call not executed: %v", err)
		l.emitEvent(sessions.Event{Kind: sessions.KindToolResult, Turn: turn, Tool: call.Name, CallID: call.ID, Failure: adm.content})
		return adm, nil
	}

	// 4. Audit write, before execution. Fail closed (§6.5).
	if err := l.writeAudit(call, params, auditVerdict, verdict.Reason); err != nil {
		adm.content = fmt.Sprintf("tool call denied: the audit trail could not be written (%v)", err)
		l.emitEvent(sessions.Event{Kind: sessions.KindError, Turn: turn, Tool: call.Name, Failure: adm.content})
		l.emitEvent(sessions.Event{Kind: sessions.KindToolResult, Turn: turn, Tool: call.Name, CallID: call.ID, Failure: adm.content})
		return adm, nil
	}

	l.emitEvent(sessions.Event{
		Kind:      sessions.KindToolCall,
		Turn:      turn,
		Tool:      call.Name,
		CallID:    call.ID,
		Params:    params,
		Arguments: call.Arguments,
		Verdict:   string(auditVerdict),
		Reason:    string(verdict.Reason),
	})

	if auditVerdict == audit.VerdictDeny || auditVerdict == audit.VerdictHardDeny {
		adm.content = denialText(call.Name, verdict.Reason)
		l.emitEvent(sessions.Event{Kind: sessions.KindToolResult, Turn: turn, Tool: call.Name, CallID: call.ID, Failure: adm.content})
		return adm, nil
	}

	adm.tool = tool
	adm.params = params
	adm.exec = true
	return adm, nil
}

// resolve turns a policy verdict into the audit verdict, asking the prompter
// when the engine returned a prompt.
func (l *Loop) resolve(ctx context.Context, verdict policy.VerdictResult, call model.ToolCall, params map[string]any) (audit.Verdict, error) {
	switch verdict.Verdict {
	case policy.VerdictDeny:
		return audit.VerdictHardDeny, nil
	case policy.VerdictAllow:
		return audit.VerdictAllow, nil
	}

	key := sessionKey(call.Name, params)
	if l.sessionAllowed(key) {
		return audit.VerdictAllowSession, nil
	}

	decision, err := l.prompter.Prompt(ctx, PromptRequest{
		Tool:   call.Name,
		Params: params,
		Reason: verdict.Reason,
	})
	if err != nil {
		return audit.VerdictDeny, fmt.Errorf("permission prompt for %q: %w", call.Name, err)
	}
	switch decision {
	case DecisionAllowOnce:
		return audit.VerdictAllowOnce, nil
	case DecisionAllowSession:
		l.rememberSession(key)
		return audit.VerdictAllowSession, nil
	default:
		return audit.VerdictDeny, nil
	}
}

// writeAudit appends one decision to the audit trail. A nil writer is a
// fail-closed writer: nothing is recorded, so nothing runs.
func (l *Loop) writeAudit(call model.ToolCall, params map[string]any, verdict audit.Verdict, reason policy.Reason) error {
	if l.audit == nil {
		return errors.New("no audit writer configured")
	}
	return l.audit.Append(audit.Record{
		Mode:    audit.Mode(l.engine.Mode()),
		Tool:    call.Name,
		Params:  params,
		Verdict: verdict,
		Reason:  string(reason),
	})
}

// runAll executes the admitted calls, at most maxParallel at a time, filling
// each admission's result content and emitting its result event.
func (l *Loop) runAll(ctx context.Context, admissions []admission, indexes []int, turn int) {
	limit := l.maxParallel
	if limit < 1 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for _, i := range indexes {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			l.execute(ctx, &admissions[i], turn)
		}(i)
	}
	wg.Wait()
}

// execute runs one admitted call and records its result.
func (l *Loop) execute(ctx context.Context, adm *admission, turn int) {
	result, err := adm.tool.Handler(ctx, adm.params)
	ev := sessions.Event{Kind: sessions.KindToolResult, Turn: turn, Tool: adm.call.Name, CallID: adm.call.ID}
	if err != nil {
		adm.content = fmt.Sprintf("error: %v", err)
		ev.Failure = adm.content
	} else {
		truncated := false
		result, truncated = truncateOutput(result, l.maxOutput)
		adm.content = result
		ev.Result = result
		ev.Truncated = truncated
	}
	l.emitEvent(ev)
}

// toolTargets maps a call's arguments onto its scope targets, tolerating a
// tool that declares none.
func toolTargets(t Tool, params map[string]any) []policy.Target {
	if t.Targets == nil {
		return nil
	}
	return t.Targets(params)
}

// denialText is the model-facing explanation of a refusal.
func denialText(tool string, reason policy.Reason) string {
	switch reason {
	case policy.ReasonROE:
		return fmt.Sprintf("tool call %q was hard-denied by the engagement's rules of engagement; this refusal is not promptable", tool)
	case policy.ReasonOutOfScope:
		return fmt.Sprintf("tool call %q was denied: the target is outside the engagement scope", tool)
	default:
		return fmt.Sprintf("tool call %q was denied by the permission policy (%s)", tool, reason)
	}
}

// sessionKey identifies a prompt decision within a session: the tool plus its
// verbatim parameters (JSON object keys are marshaled in sorted order, so equal
// parameters produce equal keys).
func sessionKey(tool string, params map[string]any) string {
	b, err := json.Marshal(params)
	if err != nil {
		b = []byte(fmt.Sprintf("%v", params))
	}
	return tool + "|" + string(b)
}

func (l *Loop) sessionAllowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.session[key]
}

func (l *Loop) rememberSession(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.session[key] = true
}

// emitEvent publishes one event on the session bus.
func (l *Loop) emitEvent(ev sessions.Event) {
	if l.emit == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = l.now()
	}
	l.emit(ev)
}

// truncateOutput caps a tool result at capture (§4.5). The first line always
// survives — later eviction summaries depend on it — and the marker states
// exactly how much was cut.
func truncateOutput(s string, limit int) (string, bool) {
	if limit <= 0 || len(s) <= limit {
		return s, false
	}
	keep := limit
	if nl := strings.IndexByte(s, '\n'); nl >= 0 && nl < limit {
		keep = nl + 1
	}
	head := s[:keep]
	if !strings.HasSuffix(head, "\n") {
		head += "\n"
	}
	return fmt.Sprintf("%s[agent: output truncated at %d bytes; %d bytes cut]", head, keep, len(s)-keep), true
}
