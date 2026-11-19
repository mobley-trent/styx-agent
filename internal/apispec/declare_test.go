package apispec_test

import (
	"context"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/apispec"
)

// TestFormatKey covers the cheap candidacy test diff scope uses
// (docs/api-spec-targets.md §5.1): only a document that names a format is a
// declaration, and a broken one still names it.
func TestFormatKey(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"openapi yaml", "openapi: 3.1.0\ninfo:\n  title: Acme\n", true},
		{"swagger yaml", "swagger: \"2.0\"\nhost: api.acme.example\n", true},
		{"openapi json", `{"openapi": "3.0.0", "info": {"title": "Acme"}}`, true},
		{"postman collection", `{"info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}}`, true},
		{"broken declaration", "openapi: 3.0.0\ninfo:\n  title: Acme\n paths: oops\n", true},
		{"workflow yaml", "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n", false},
		{"description mentions openapi", "info:\n  description: our openapi docs\n", false},
		{"nested key only", `{"a": {"openapi": "3.0.0"}}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apispec.FormatKey([]byte(tt.body)); got != tt.want {
				t.Fatalf("FormatKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDeclareReportsTheSurfaceWithoutWriting pins the harness-side read diff
// scope uses: the same classification as a load, and nothing to write.
func TestDeclareReportsTheSurfaceWithoutWriting(t *testing.T) {
	decl, err := apispec.Declare(context.Background(), apispec.DeclareRequest{
		Artifact: "openapi.yaml",
		Data:     []byte(openAPIDoc),
		Scope:    cidrScope("10.1.0.0/24"),
		Resolver: acmeResolver,
		Pool:     []string{"10.1.0.0/24"},
	})
	if err != nil {
		t.Fatalf("Declare() = %v", err)
	}
	if decl.Format != "openapi-3.1" {
		t.Errorf("format = %q, want openapi-3.1", decl.Format)
	}
	usable := decl.Usable()
	if len(usable) != 1 || usable[0].Host != "api.acme.example" {
		t.Fatalf("usable = %+v, want api.acme.example", usable)
	}
	if len(usable[0].Addresses) != 1 || usable[0].Addresses[0].String() != "10.1.0.5" {
		t.Errorf("addresses = %v, want [10.1.0.5]", usable[0].Addresses)
	}
	if len(decl.Operations) != 2 {
		t.Fatalf("operations = %d, want 2", len(decl.Operations))
	}
	for _, op := range decl.Operations {
		if !op.Available || op.Server != "https://api.acme.example/v1" {
			t.Errorf("operation %+v, want available on the declared server", op)
		}
		if op.Fingerprint == "" {
			t.Errorf("operation %s %s has no fingerprint", op.Method, op.Path)
		}
	}
	if decl.Unavailable() != 0 {
		t.Errorf("unavailable = %d, want 0", decl.Unavailable())
	}
}

// TestDeclareClassifiesRefusedServers keeps the refusal contract: a server
// outside the pool is refused whole and its operations are unavailable, so a
// reader never sees half a document without knowing which half.
func TestDeclareClassifiesRefusedServers(t *testing.T) {
	doc := `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://api.acme.example/v1
  - url: https://edge.other.example/v1
paths:
  /users:
    get: {}
  /edge:
    servers:
      - url: https://edge.other.example/v1
    get: {}
`
	decl, err := apispec.Declare(context.Background(), apispec.DeclareRequest{
		Artifact: "openapi.yaml",
		Data:     []byte(doc),
		Scope:    cidrScope("10.1.0.0/24"),
		Resolver: acmeResolver,
		Pool:     []string{"10.1.0.0/24"},
	})
	if err != nil {
		t.Fatalf("Declare() = %v", err)
	}
	if usable := decl.Usable(); len(usable) != 1 || usable[0].Host != "api.acme.example" {
		t.Fatalf("usable = %+v, want one in-scope server", usable)
	}
	refused := decl.Refused()
	if len(refused) != 1 || refused[0].Host != "edge.other.example" {
		t.Fatalf("refused = %+v, want edge.other.example", refused)
	}
	if !strings.Contains(refused[0].Reason, "outside engagement targets") {
		t.Errorf("refusal reason = %q, want the pool it missed", refused[0].Reason)
	}
	if decl.Unavailable() != 1 {
		t.Errorf("unavailable = %d, want the refused server's one operation", decl.Unavailable())
	}
}

// TestDeclareFingerprintsTrackTheOperation is what lets a diff tell a changed
// operation from an untouched one.
func TestDeclareFingerprintsTrackTheOperation(t *testing.T) {
	read := func(getSummary, extra string) map[string]string {
		t.Helper()
		doc := `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://api.acme.example/v1
paths:
  /users:
    get:
      summary: ` + getSummary + "\n" + extra
		decl, err := apispec.Declare(context.Background(), apispec.DeclareRequest{
			Artifact: "openapi.yaml",
			Data:     []byte(doc),
			Scope:    cidrScope("10.1.0.0/24"),
			Resolver: acmeResolver,
			Pool:     []string{"10.1.0.0/24"},
		})
		if err != nil {
			t.Fatalf("Declare() = %v", err)
		}
		out := map[string]string{}
		for _, op := range decl.Operations {
			out[op.Method+" "+op.Path] = op.Fingerprint
		}
		return out
	}

	base := read("list users", "")
	same := read("list users", "")
	if base["GET /users"] != same["GET /users"] {
		t.Errorf("an unchanged operation changed fingerprint: %q vs %q", base["GET /users"], same["GET /users"])
	}
	// A sibling operation is not a change to this one: the fingerprint is per
	// operation, which is what keeps a diff's context aimed at the change.
	sibling := read("list users", "    post:\n      summary: create a user\n")
	if sibling["GET /users"] != base["GET /users"] {
		t.Error("adding a sibling operation changed an untouched operation's fingerprint")
	}
	if _, ok := sibling["POST /users"]; !ok {
		t.Error("the added operation is missing from the declaration")
	}
	edited := read("list every user", "")
	if base["GET /users"] == edited["GET /users"] {
		t.Error("an edited operation kept its fingerprint")
	}
}
