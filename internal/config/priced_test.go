package config

import "testing"

// Priced is the predicate the budget cap reads (docs/budget-cap.md §2.1): a
// model setting any one of its three rates has a price to bill, and a model
// setting none has no price the harness may invent.
func TestModelPriced(t *testing.T) {
	tests := []struct {
		name  string
		model Model
		want  bool
	}{
		{"no rates", Model{ID: "free", ContextWindow: 8192}, false},
		{"input only", Model{ID: "in", InputPerMillion: 0.30}, true},
		{"output only", Model{ID: "out", OutputPerMillion: 1.20}, true},
		{"cache-hit only", Model{ID: "hit", CacheHitPerMillion: 0.006}, true},
		{"all three", Model{ID: "all", InputPerMillion: 0.3, OutputPerMillion: 1.2, CacheHitPerMillion: 0.006}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.model.Priced(); got != tc.want {
				t.Errorf("Priced() = %v, want %v", got, tc.want)
			}
		})
	}
}
