package model

import (
	"testing"
	"time"
)

func TestIsPeak(t *testing.T) {
	tests := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"monday 02:00 UTC", time.Date(2026, 9, 28, 2, 0, 0, 0, time.UTC), true},
		{"monday 08:30 UTC", time.Date(2026, 9, 28, 8, 30, 0, 0, time.UTC), true},
		{"monday 04:00 UTC (window end)", time.Date(2026, 9, 28, 4, 0, 0, 0, time.UTC), false},
		{"monday 05:00 UTC (between windows)", time.Date(2026, 9, 28, 5, 0, 0, 0, time.UTC), false},
		{"monday 10:00 UTC (window end)", time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC), false},
		{"saturday 02:00 UTC", time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC), false},
		{"sunday 08:00 UTC", time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPeak(tt.at); got != tt.want {
				t.Errorf("IsPeak(%s) = %v, want %v", tt.at, got, tt.want)
			}
		})
	}
}

func TestPricingCost(t *testing.T) {
	p := Pricing{InputPerMillion: 1.00, OutputPerMillion: 4.00, CacheHitPerMillion: 0.10}
	u := Usage{PromptTokens: 1000, CompletionTokens: 1000, CacheHitTokens: 800, CacheMissTokens: 200}

	peakAt := time.Date(2026, 9, 28, 2, 0, 0, 0, time.UTC) // Monday, peak
	offAt := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC) // Monday, off-peak

	// peak: 800*0.10/1e6 + 200*1.00/1e6 + 1000*4.00/1e6 = 0.00428
	peak := p.Cost(u, peakAt)
	if want := 0.00428; !closeEnough(peak, want) {
		t.Errorf("peak cost = %v, want %v", peak, want)
	}
	if want := peak / 2; !closeEnough(p.Cost(u, offAt), want) {
		t.Errorf("off-peak cost = %v, want half of %v", p.Cost(u, offAt), peak)
	}

	// No cache split reported: every prompt token bills as a miss.
	noSplit := Usage{PromptTokens: 1000, CompletionTokens: 0}
	if got, want := p.Cost(noSplit, peakAt), 0.001; !closeEnough(got, want) {
		t.Errorf("no-split cost = %v, want %v", got, want)
	}
}

func closeEnough(got, want float64) bool {
	diff := got - want
	if diff < 0 {
		diff = -diff
	}
	return diff < 1e-9
}
