package budget

import "testing"

// The level ladder (docs/budget-cap.md §5): none below half, half at 50%,
// wrap-up at 80%, exhausted at 100%. The boundary cases are exactly what the
// cap turns on, so they are pinned rather than approached.
func TestLevelLadder(t *testing.T) {
	tests := []struct {
		name  string
		spend Spend
		want  Level
	}{
		{"nothing spent", Spend{Spent: 0, Cap: 1}, LevelNone},
		{"just below half", Spend{Spent: 0.4999, Cap: 1}, LevelNone},
		{"exactly half", Spend{Spent: 0.5, Cap: 1}, LevelHalf},
		{"past half", Spend{Spent: 0.6, Cap: 1}, LevelHalf},
		{"just below wrap-up", Spend{Spent: 0.7999, Cap: 1}, LevelHalf},
		{"exactly wrap-up", Spend{Spent: 0.8, Cap: 1}, LevelWrapUp},
		{"past wrap-up", Spend{Spent: 0.9, Cap: 1}, LevelWrapUp},
		{"just below the cap", Spend{Spent: 0.9999, Cap: 1}, LevelWrapUp},
		{"exactly the cap", Spend{Spent: 1, Cap: 1}, LevelExhausted},
		{"over the cap", Spend{Spent: 1.036, Cap: 1}, LevelExhausted},
		{"boundaries on a small cap", Spend{Spent: 0.04, Cap: 0.05}, LevelWrapUp},
		{"half on a small cap", Spend{Spent: 0.025, Cap: 0.05}, LevelHalf},
		{"no cap", Spend{Spent: 5, Cap: 0}, LevelNone},
		{"negative cap", Spend{Spent: 5, Cap: -1}, LevelNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.spend.Level(); got != tc.want {
				t.Errorf("Level() = %v, want %v", got, tc.want)
			}
			if got := tc.spend.Exhausted(); got != (tc.want == LevelExhausted) {
				t.Errorf("Exhausted() = %v, want %v", got, tc.want == LevelExhausted)
			}
		})
	}
}

func TestPercent(t *testing.T) {
	tests := []struct {
		spend Spend
		want  int
	}{
		{Spend{Spent: 0, Cap: 0.05}, 0},
		{Spend{Spent: 0.025, Cap: 0.05}, 50},
		{Spend{Spent: 0.041, Cap: 0.05}, 82},
		{Spend{Spent: 0.0518, Cap: 0.05}, 104},
		{Spend{Spent: 0.4, Cap: 0}, 0},
	}
	for _, tc := range tests {
		if got := tc.spend.Percent(); got != tc.want {
			t.Errorf("Spend{%v, %v}.Percent() = %d, want %d", tc.spend.Spent, tc.spend.Cap, got, tc.want)
		}
	}
}

// The stderr lines use four decimals, never more and never fewer.
func TestUSD(t *testing.T) {
	tests := map[float64]string{
		0:      "$0.0000",
		0.05:   "$0.0500",
		0.0025: "$0.0025",
		2.5:    "$2.5000",
		0.0518: "$0.0518",
	}
	for in, want := range tests {
		if got := USD(in); got != want {
			t.Errorf("USD(%v) = %q, want %q", in, got, want)
		}
	}
	if got, want := (Spend{Spent: 0.0518, Cap: 0.05}).String(), "$0.0518 of $0.0500"; got != want {
		t.Errorf("Spend.String() = %q, want %q", got, want)
	}
}

func TestLevelString(t *testing.T) {
	tests := map[Level]string{
		LevelNone:      "none",
		LevelHalf:      "half",
		LevelWrapUp:    "wrap-up",
		LevelExhausted: "exhausted",
	}
	for level, want := range tests {
		if got := level.String(); got != want {
			t.Errorf("Level(%d).String() = %q, want %q", level, got, want)
		}
	}
}
