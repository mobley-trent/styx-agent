package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/mobley-trent/styx-agent/internal/agent"
	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/budget"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// errInterrupted ends a headless run that a signal canceled. It is a broken run
// (exit 1), not a scan verdict: the turn never reached its own answer
// (docs/headless-ci.md §7).
var errInterrupted = errors.New("turn interrupted")

// notifyHeadlessSignals installs the run's signal handler. It is a seam so the
// interrupt path is exercised without signalling the test process.
var notifyHeadlessSignals = func() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	return ch, func() { signal.Stop(ch) }
}

// runHeadless runs one task in one turn with no terminal (docs/headless-ci.md).
//
// It attaches a line printer to the same event bus the TUI renders from and
// nothing else: no prompt sink is installed, so every promptable verdict
// resolves to a deny carrying no-operator (§3), and stdin is never read (§2.1).
// stdout carries the answer, stderr the transcript and the end summary (§6.1).
//
// Run closes the harness after the runner returns, which is the engagement
// teardown `/mode safe` performs: notes appended, store closed and its lock
// released, egress rules down (§5.3).
func runHeadless(ctx context.Context, h *Harness) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	printer := newHeadlessPrinter(h.errWriter())
	h.setUI(printer.event)
	defer h.setUI(nil)

	signals, stopSignals := notifyHeadlessSignals()
	defer stopSignals()

	done := make(chan struct{})
	defer close(done)
	var interrupted atomic.Bool
	go func() {
		select {
		case <-signals:
			// The first signal is a cancel, not a kill: the in-flight turn
			// stops through the same path Escape uses, so the state store
			// closes, its lock releases, and teardown still runs.
			interrupted.Store(true)
			cancel()
		case <-done:
			return
		}
		// The second signal exits immediately, with no further cleanup (§7).
		select {
		case <-signals:
			os.Exit(1)
		case <-done:
		}
	}()

	h.printIdentity()
	h.printBudgetCap()
	result, err := h.SubmitResult(runCtx, h.task)

	if interrupted.Load() {
		printer.refusal("interrupted")
	}
	// stdout is the answer and nothing else, so `styx -n "…" > report.md` is
	// correct by construction (§6.1).
	if answer := strings.TrimSpace(result.Answer); answer != "" {
		_, _ = fmt.Fprintln(h.out, answer)
	}
	// The export is written before the run's exit status is decided
	// (docs/findings-export.md §5): the gate reads the same snapshot, so no
	// verdict ever needs the file. A failed write fails the run (§5).
	if exportErr := h.emitFindingsExport(printer); exportErr != nil {
		err = exportErr
	}
	// The gate runs after the export write has succeeded and before teardown,
	// over the same snapshot (§8.5). A broken run, an interrupted turn, or a
	// failed export gets no verdict: §8.1 puts broken first.
	var gateErr error
	if err == nil && !interrupted.Load() {
		gateErr = h.evaluateSeverityGate(printer)
	}
	h.printSummary(result, printer.denials())

	if interrupted.Load() && (err == nil || errors.Is(err, context.Canceled)) {
		err = errInterrupted
	}
	// Precedence: broken > gate failed > not clean > clean (§8.1). A finished
	// turn that denied a prompt is a verdict, not a failure: its answer is on
	// stdout and the summary already says the run was not clean.
	switch {
	case err != nil:
		return err
	case gateErr != nil:
		return gateErr
	case printer.denials() > 0:
		return &NotClean{Denied: printer.denials()}
	}
	return nil
}

// printIdentity writes the run's one-line identity (§6.2). It never claims
// provider health it has not checked: fail-on-demand puts that at the first
// turn (§5.1).
func (h *Harness) printIdentity() {
	_, eng := h.modeAndEngagement()
	where := "safe mode"
	if eng != nil {
		// The level rides the identity line: a run that can exploit is legible
		// as one from its own output, without reading the engagement file
		// (docs/exploitation-phase.md §6).
		where = fmt.Sprintf("engagement %s · exploit %s", eng.Name(), eng.ROE().AutonomyLevel())
	}
	_, _ = fmt.Fprintf(h.errWriter(), "styx: %s · %s · session %s\n",
		h.Version, where, shortID(h.SessionID()))
}

// printBudgetCap announces the run's ceiling, one `styx: ` line after the
// identity line (docs/budget-cap.md §7): a run that will stop early says so
// before it starts.
func (h *Harness) printBudgetCap() {
	ceiling := h.budgetCap()
	if ceiling <= 0 {
		return
	}
	_, _ = fmt.Fprintf(h.errWriter(), "styx: budget cap %s\n", budget.USD(ceiling))
}

// printSummary writes the four-line end summary (§6.3) on every exit path the
// runner can reach. The denial count is authoritative: zero means nothing was
// blocked, and anything else says the run did not do all of what it was asked.
func (h *Harness) printSummary(result agent.Result, denied int) {
	w := h.errWriter()
	usage, cost := h.Usage(), h.Cost()

	_, _ = fmt.Fprintf(w, "styx: done — %d %s\n", result.Turns, plural(result.Turns, "turn", "turns"))
	// A budgeted run names its ceiling on the same line, so the summary stays
	// four lines (docs/budget-cap.md §7, docs/headless-ci.md §6.3).
	if ceiling := h.budgetCap(); ceiling > 0 {
		_, _ = fmt.Fprintf(w, "styx: usage %s tokens · %s\n",
			thousands(usage.TotalTokens), budget.Spend{Spent: cost, Cap: ceiling})
	} else {
		_, _ = fmt.Fprintf(w, "styx: usage %s tokens · $%.4f\n", thousands(usage.TotalTokens), cost)
	}
	if denied > 0 {
		_, _ = fmt.Fprintf(w, "styx: denied %d %s (run not clean)\n", denied, plural(denied, "prompt", "prompts"))
	} else {
		_, _ = fmt.Fprintln(w, "styx: denied 0 prompts")
	}
	if name := h.auditFileName(); name != "" {
		_, _ = fmt.Fprintf(w, "styx: session %s (audit %s)\n", shortID(h.SessionID()), name)
	} else {
		_, _ = fmt.Fprintf(w, "styx: session %s\n", shortID(h.SessionID()))
	}
}

// auditFileName is the run's audit file, the forensic record the summary
// points at (§6.3).
func (h *Harness) auditFileName() string {
	h.mu.Lock()
	writer := h.audit
	h.mu.Unlock()
	if writer == nil {
		return ""
	}
	return filepath.Base(writer.Path())
}

// headlessPrinter renders the event bus onto stderr. It decides only where
// each kind goes — nothing new is emitted (§6) — and counts the denials the
// summary reports. Deltas and reasoning are never printed: the assembled answer
// carries the text and the session log carries the reasoning (§6.1).
type headlessPrinter struct {
	out    io.Writer
	denied int
	// deniedCalls are the calls already reported as denied. Their tool result
	// restates the same refusal for the model, so the transcript does not print
	// it twice.
	deniedCalls map[string]bool
}

func newHeadlessPrinter(out io.Writer) *headlessPrinter {
	return &headlessPrinter{out: out, deniedCalls: make(map[string]bool)}
}

// denials is how many prompts the run resolved with no operator attached.
func (p *headlessPrinter) denials() int { return p.denied }

// event renders one session event.
func (p *headlessPrinter) event(ev sessions.Event) {
	switch ev.Kind {
	case sessions.KindToolCall:
		p.toolCall(ev)
	case sessions.KindToolResult:
		if ev.Failure != "" {
			if p.reportedDenial(ev.CallID) {
				return
			}
			p.refusal(strings.TrimPrefix(ev.Failure, "error: "))
			return
		}
		p.body(ev.Result)
	case sessions.KindError:
		p.refusal(ev.Failure)
	case sessions.KindIsolation:
		p.body(ev.Detail)
	case sessions.KindEngagement:
		p.write("styx: " + engagementLine(ev))
	case sessions.KindMCP:
		if ev.Status == "failed" {
			p.refusal("mcp " + ev.Server + ": " + ev.Detail)
		}
	case sessions.KindBudget:
		p.budget(ev)
	}
}

// budget renders a graduated warning in the harness's own voice
// (docs/budget-cap.md §5), so a headless reader watches the wall approach. The
// exhausted level prints nothing here: its stop is the `! ` line the loop's
// typed error already produced.
func (p *headlessPrinter) budget(ev sessions.Event) {
	sp := budget.Spend{Spent: ev.Spent, Cap: ev.Cap}
	if sp.Exhausted() {
		return
	}
	p.write(fmt.Sprintf("styx: budget %d%% used (%s)", sp.Percent(), sp))
}

// toolCall renders a call: an operation beginning, or the refusal that stopped
// it. A headless denial carries no-operator, and it is counted here (§3).
func (p *headlessPrinter) toolCall(ev sessions.Event) {
	switch audit.Verdict(ev.Verdict) {
	case audit.VerdictDeny, audit.VerdictHardDeny:
		p.deniedCalls[ev.CallID] = true
		if ev.Reason == string(policy.ReasonNoOperator) {
			p.denied++
			p.refusal(fmt.Sprintf("deny %s (no operator: not permitted non-interactively)", ev.Tool))
			return
		}
		p.refusal(fmt.Sprintf("deny %s (%s)", ev.Tool, ev.Reason))
	default:
		p.write("> " + operationLabel(ev) + formatParams(ev.Params))
	}
}

// reportedDenial reports whether this call's refusal was already printed as a
// denial line, consuming the marker either way.
func (p *headlessPrinter) reportedDenial(callID string) bool {
	if callID == "" || !p.deniedCalls[callID] {
		return false
	}
	delete(p.deniedCalls, callID)
	return true
}

// operationLabel names the operation, with its subagent role when the call came
// from a nested run, so a headless log never mistakes one for the main stream's.
func operationLabel(ev sessions.Event) string {
	if ev.Subagent == "" {
		return ev.Tool
	}
	return "[" + ev.Subagent + "] " + ev.Tool
}

// headlessParamWidth bounds one parameter's rendering: the transcript names the
// operation, it does not become a second copy of the payload.
const headlessParamWidth = 120

// formatParams renders a call's parameters on one line, bounded per value. A
// bare `command` reads the way an operator would type it (§6.2).
func formatParams(params map[string]any) string {
	if len(params) == 0 {
		return ""
	}
	if command, ok := params["command"].(string); ok && len(params) == 1 {
		return " " + oneLine(command)
	}
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value, ok := params[key].(string)
		if !ok {
			encoded, err := json.Marshal(params[key])
			if err != nil {
				continue
			}
			value = string(encoded)
		}
		parts = append(parts, key+"="+oneLine(value))
	}
	return " " + strings.Join(parts, " ")
}

// oneLine flattens and bounds a value for the transcript.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", `\n`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	if len(s) > headlessParamWidth {
		return s[:headlessParamWidth] + "…"
	}
	return s
}

// body renders the body of the previous operation. It prints in full up to the
// capture truncation the loop already applied: there is no live region to
// expand later, so the pipe is the pager (§6.1).
func (p *headlessPrinter) body(text string) {
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return
	}
	for _, line := range strings.Split(text, "\n") {
		p.write("  " + line)
	}
}

// refusal renders something refused, failed, or interrupted.
func (p *headlessPrinter) refusal(text string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	p.write("! " + text)
}

// write emits one line. Nothing is printed that is not an event (§6.1).
func (p *headlessPrinter) write(line string) {
	_, _ = fmt.Fprintln(p.out, line)
}

// engagementLine is the `styx: ` rendering of an engagement activation or
// teardown event.
func engagementLine(ev sessions.Event) string {
	if ev.Detail != "" {
		return ev.Detail
	}
	if ev.Engagement != "" {
		return "engagement " + ev.Engagement + " active"
	}
	return "engagement mode changed"
}

// plural picks the singular or plural noun for a count.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// thousands groups an integer with commas, as the summary's token count reads.
func thousands(n int) string {
	digits := strconv.Itoa(n)
	sign := ""
	if strings.HasPrefix(digits, "-") {
		sign, digits = "-", digits[1:]
	}
	var b strings.Builder
	for i, r := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return sign + b.String()
}
