// Package budget implements the USD budget cap's arithmetic: a run's spend
// measured against its ceiling, the graduated warning level that measurement
// has reached, and the four-decimal formatting the harness's stderr lines use.
//
// Boundary rule: pure arithmetic. No clock, no store, no I/O, and no price — a
// turn's dollars come from internal/model's Pricing at the moment the turn
// arrived. This package only compares a number the session already accumulated
// with the ceiling the operator named, so the thresholds are testable in
// isolation (docs/budget-cap.md §5, §11; ADR-0010).
package budget

import (
	"fmt"
	"math"
)

// The graduated thresholds a spend/cap pair is placed at (docs/budget-cap.md
// §5). They are ordered: a level is reached only when every lower one is.
const (
	// halfAt is the share of the cap that asks the model to narrow its work.
	halfAt = 0.5
	// wrapUpAt is the share of the cap that asks the model to finish.
	wrapUpAt = 0.8
)

// ratioEpsilon absorbs floating-point error at a threshold boundary, so a
// spend of exactly 50% or 80% of the cap lands in the higher level rather than
// one ulp below it. It is a billionth of the cap — far below the four decimals
// a cap can name — so it never moves a real measurement.
const ratioEpsilon = 1e-9

// Level is the graduated warning level a measurement has reached.
type Level int

const (
	// LevelNone is a run below half the cap.
	LevelNone Level = iota
	// LevelHalf is a run at or past half the cap.
	LevelHalf
	// LevelWrapUp is a run at or past 80% of the cap.
	LevelWrapUp
	// LevelExhausted is a run that has spent the cap: no further model call.
	LevelExhausted
)

// String names the level the way the session's budget event records it.
func (l Level) String() string {
	switch l {
	case LevelHalf:
		return "half"
	case LevelWrapUp:
		return "wrap-up"
	case LevelExhausted:
		return "exhausted"
	default:
		return "none"
	}
}

// Spend is one measurement: the dollars a run has spent against its ceiling.
type Spend struct {
	// Spent is the run's accumulated model spend in USD.
	Spent float64
	// Cap is the run's USD ceiling. A non-positive cap means no budget.
	Cap float64
}

// Level is the highest threshold the measurement has reached. A measurement
// without a cap is LevelNone: an unbudgeted run has no wall.
func (s Spend) Level() Level {
	switch {
	case s.Cap <= 0:
		return LevelNone
	case s.reaches(1):
		return LevelExhausted
	case s.reaches(wrapUpAt):
		return LevelWrapUp
	case s.reaches(halfAt):
		return LevelHalf
	default:
		return LevelNone
	}
}

// Exhausted reports whether the run has spent its cap and so may not make
// another model call (docs/budget-cap.md §4).
func (s Spend) Exhausted() bool { return s.Level() == LevelExhausted }

// Percent is the share of the cap spent, rounded to a whole percentage for the
// operator's warning line.
func (s Spend) Percent() int {
	if s.Cap <= 0 {
		return 0
	}
	return int(math.Round(s.Spent / s.Cap * 100))
}

// String renders the measurement as "$0.0518 of $0.0500".
func (s Spend) String() string { return USD(s.Spent) + " of " + USD(s.Cap) }

// reaches reports whether the spend is at or past fraction of the cap.
func (s Spend) reaches(fraction float64) bool {
	return s.Spent >= fraction*s.Cap*(1-ratioEpsilon)
}

// USD formats a dollar amount with four fractional digits. A cent is too
// coarse for a small run, where one turn can cost $0.004, and beyond four
// decimals the amount would express fractions no usage report measures
// (docs/budget-cap.md §8).
func USD(v float64) string { return fmt.Sprintf("$%.4f", v) }
