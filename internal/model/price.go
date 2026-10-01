package model

import "time"

// Pricing is a model's per-million-token rates at peak, in US dollars, plus
// the cache-hit input rate (§3.1). The rates are the published peak prices;
// off-peak billing is half (See Cost).
type Pricing struct {
	// InputPerMillion is the cache-miss prompt rate at peak.
	InputPerMillion float64
	// OutputPerMillion is the completion (including reasoning) rate at peak.
	OutputPerMillion float64
	// CacheHitPerMillion is the cached-prompt input rate at peak.
	CacheHitPerMillion float64
}

// Cost reports the dollar cost of a turn's usage at a moment in time. Prompt
// tokens are priced as cache hits or misses from the usage's own split; when
// the provider reported no split, every prompt token is billed at the
// cache-miss rate. Output tokens include reasoning tokens, which bill as
// output. Off-peak turns bill at half the peak rate.
func (p Pricing) Cost(u Usage, at time.Time) float64 {
	hit := u.CacheHitTokens
	miss := u.CacheMissTokens
	if hit == 0 && miss == 0 {
		miss = u.PromptTokens
	}

	costPerToken := func(perMillion float64) float64 { return perMillion / 1_000_000 }
	total := float64(hit)*costPerToken(p.CacheHitPerMillion) +
		float64(miss)*costPerToken(p.InputPerMillion) +
		float64(u.CompletionTokens)*costPerToken(p.OutputPerMillion)
	if !IsPeak(at) {
		total /= 2
	}
	return total
}

// peakWindows are the provider's peak billing windows in UTC, as
// [start, end) hour pairs on weekdays.
var peakWindows = [][2]int{{1, 4}, {6, 10}}

// IsPeak reports whether a moment falls in a published peak billing window:
// 01:00–04:00 or 06:00–10:00 UTC on weekdays (excluding provider holidays,
// which the harness does not model). Everything else bills at half.
func IsPeak(at time.Time) bool {
	utc := at.UTC()
	switch utc.Weekday() {
	case time.Saturday, time.Sunday:
		return false
	}
	hour := utc.Hour()
	for _, w := range peakWindows {
		if hour >= w[0] && hour < w[1] {
			return true
		}
	}
	return false
}
