package agent

import (
	"errors"
	"fmt"

	"github.com/mobley-trent/styx-agent/internal/budget"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// BudgetReader reports the run's measured model spend and the ceiling it is
// measured against (docs/budget-cap.md §4). The app supplies it from the
// session's own accounting — the accumulator every usage event already folds
// into — so the loop compares a number it did not compute and never prices a
// turn itself.
type BudgetReader interface {
	// Spend returns the run's accumulated model spend in USD and the run's
	// ceiling. A non-positive ceiling means the run is not budgeted.
	Spend() (spent, ceiling float64)
}

// WithBudget installs the run's spend reader. Nil leaves the run unbudgeted:
// the between-turns seam then appends nothing and refuses nothing, so a run
// without --max-budget is byte-for-byte unaffected. Subagent loops are built
// from the same options, so every loop in the run checks the same ceiling
// (docs/budget-cap.md §4).
func WithBudget(r BudgetReader) LoopOption {
	return func(l *Loop) {
		if r != nil {
			l.budget = r
		}
	}
}

// ErrBudgetExhausted is the loop's typed budget stop (docs/budget-cap.md §7).
// It carries the measurement that stopped the run, so the caller reports the
// overshoot rather than hiding the soft edge. It is a broken run — exit 1
// through the harness's generic error path — never a scan verdict, and the
// severity gate is never consulted for it.
type ErrBudgetExhausted struct {
	// Spent is the run's spend when the next model call was refused, in USD.
	Spent float64
	// Cap is the ceiling it was measured against.
	Cap float64
	// Turns is how many model turns the run completed.
	Turns int
}

// Error implements error. The message is the run's `! ` stop line.
func (e *ErrBudgetExhausted) Error() string {
	turns := fmt.Sprintf("%d model turns", e.Turns)
	if e.Turns == 1 {
		turns = "1 model turn"
	}
	return fmt.Sprintf("budget exhausted: %s after %s", budget.Spend{Spent: e.Spent, Cap: e.Cap}, turns)
}

// ErrBudgetUnmeasured is a completed model turn whose provider reported no
// usage, in a run that therefore cannot measure its ceiling
// (docs/budget-cap.md §6). A cap that cannot be measured is not a cap, so the
// run ends rather than continue while claiming one.
var ErrBudgetUnmeasured = errors.New("budget cannot be enforced: the provider reported no usage")

// budgetNotePrefix marks the harness-appended budget note inside a
// conversation, the way digestPrefix marks the engagement-state digest. It is
// what identifies a note, so the loop can tell whether the one it announced is
// still there after compaction evicted it (docs/budget-cap.md §5).
const budgetNotePrefix = "[budget]"

// budgetNote renders one threshold's note: how much of the ceiling is spent
// and what the model should do about it. It is ordinary transcript content —
// tail-appended at the seam, never part of the byte-stable system prompt.
func budgetNote(level budget.Level, sp budget.Spend) string {
	advice := "half the budget is spent; prefer to narrow the remaining work"
	if level >= budget.LevelWrapUp {
		advice = "finish the current line of work, record what you have, and return a final answer; further model turns stop at the ceiling"
	}
	return fmt.Sprintf("%s %d%% of the %s budget is spent (%s)\n%s",
		budgetNotePrefix, sp.Percent(), budget.USD(sp.Cap), budget.USD(sp.Spent), advice)
}

// hasBudgetNote reports whether the conversation still carries exactly this
// note, i.e. that no compaction has evicted it.
func hasBudgetNote(messages []model.Message, note string) bool {
	for _, m := range messages {
		if m.Content == note {
			return true
		}
	}
	return false
}

// checkBudget is the budget half of the between-turns seam (docs/budget-cap.md
// §4, §5). It reads the run's accumulated spend — already folded, since the
// crossing turn completed and its usage event was published — and either ends
// the run because the cap is spent, or tail-appends the graduated note the run
// has reached. A run with no reader returns its conversation untouched.
func (l *Loop) checkBudget(messages []model.Message, turn int) ([]model.Message, error) {
	if l.budget == nil {
		return messages, nil
	}
	spent, ceiling := l.budget.Spend()
	sp := budget.Spend{Spent: spent, Cap: ceiling}

	if sp.Exhausted() {
		l.emitBudgetEvent(sp, budget.LevelExhausted, turn)
		err := &ErrBudgetExhausted{Spent: sp.Spent, Cap: sp.Cap, Turns: turn - 1}
		l.emitEvent(sessions.Event{Kind: sessions.KindError, Turn: turn, Failure: err.Error()})
		return messages, err
	}

	level := sp.Level()
	if level == budget.LevelNone {
		return messages, nil
	}
	note := budgetNote(level, sp)
	if l.budgetNote == note && hasBudgetNote(messages, note) {
		return messages, nil
	}
	// Announced once per level, and re-appended at the next seam when a
	// compaction has evicted it while the run is still past that threshold: a
	// model that just lost the note also lost the instruction to wrap up.
	l.budgetNote = note
	l.emitBudgetEvent(sp, level, turn)
	return append(messages, model.Message{Role: model.RoleSystem, Content: note}), nil
}

// emitBudgetEvent publishes the measurement, so the spend curve is in the
// session JSONL and the operator's warning line is rendered from an event.
func (l *Loop) emitBudgetEvent(sp budget.Spend, level budget.Level, turn int) {
	l.emitEvent(sessions.Event{
		Kind:  sessions.KindBudget,
		Turn:  turn,
		Spent: sp.Spent,
		Cap:   sp.Cap,
		Level: level.String(),
	})
}

// stopUnmeasured ends a budgeted run whose completed turn arrived without
// usage (docs/budget-cap.md §6): the ceiling cannot be measured, so the run
// stops rather than claim one it is not enforcing.
func (l *Loop) stopUnmeasured(turn int, messages []model.Message) (Result, error) {
	l.emitEvent(sessions.Event{Kind: sessions.KindError, Turn: turn, Failure: ErrBudgetUnmeasured.Error()})
	return Result{Turns: turn, Messages: conversation(messages)}, ErrBudgetUnmeasured
}
