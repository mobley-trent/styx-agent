package naming

import (
	"reflect"
	"testing"
)

func TestTokens(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"target", []string{"target"}},
		{"targetHost", []string{"target", "host"}},
		{"ip_address", []string{"ip", "address"}},
		{"IPAddress", []string{"ip", "address"}},
		{"recipient", []string{"recipient"}},
		{"target-ip", []string{"target", "ip"}},
		{"GhidraMCP", []string{"ghidra", "mcp"}},
	}
	for _, tt := range tests {
		if got := Tokens(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Tokens(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
