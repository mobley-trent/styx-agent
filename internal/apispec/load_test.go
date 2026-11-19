package apispec_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/apispec"
	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// testScope is a deterministic authorization pool: CIDR containment plus exact
// addresses.
type testScope struct {
	prefixes []netip.Prefix
	addrs    map[string]bool
}

// InScope reports membership for an address literal.
func (s testScope) InScope(dest string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(dest))
	if err != nil {
		return false
	}
	for _, prefix := range s.prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return s.addrs[ip.String()]
}

// testResolver is a deterministic DNS table.
type testResolver map[string][]string

// LookupHost answers from the table, NXDOMAIN otherwise.
func (r testResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if addrs, ok := r[host]; ok {
		return addrs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// cidrScope authorizes one /24.
func cidrScope(cidr string) testScope {
	return testScope{prefixes: []netip.Prefix{netip.MustParsePrefix(cidr)}}
}

// acmeResolver maps the fixtures' names.
var acmeResolver = testResolver{
	"api.acme.example":   {"10.1.0.5"},
	"edge.other.example": {"203.0.113.9"},
	"evil.other.example": {"203.0.113.10"},
	"10.1.0.5":           {"10.1.0.5"},
}

// newStore opens an engagement-state store rooted in a temporary directory.
func newStore(t *testing.T) *engagementstate.Store {
	t.Helper()
	store, err := engagementstate.Open("/work/acme", "acme-q4", engagementstate.WithRoot(t.TempDir()))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// writeDoc writes one fixture and returns its absolute path.
func writeDoc(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// loadFixture runs one load over a fixture written into workspace.
func loadFixture(t *testing.T, workspace, name, content string, opts ...func(*apispec.Request)) (apispec.Receipt, error) {
	t.Helper()
	store := newStore(t)
	req := apispec.Request{
		Artifact:  name,
		Path:      writeDoc(t, name, content),
		Workspace: workspace,
		Store:     store,
		Scope:     cidrScope("10.1.0.0/24"),
		Resolver:  acmeResolver,
		Pool:      []string{"10.1.0.0/24"},
		Origin:    engagementstate.Origin{Tool: apispec.ToolName},
	}
	for _, opt := range opts {
		opt(&req)
	}
	return apispec.Load(context.Background(), req)
}

const openAPIDoc = `openapi: 3.1.0
info:
  title: Acme
  version: "1"
servers:
  - url: https://api.acme.example/v1
paths:
  /users:
    get:
      operationId: listUsers
    post:
      operationId: createUser
`

const swaggerDoc = `swagger: "2.0"
info:
  title: Acme
  version: "1"
host: api.acme.example
basePath: /v1
schemes: [https]
paths:
  /users:
    get: {}
`

const postmanDoc = `{
  "info": {
    "name": "Acme",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "variable": [{"key": "baseUrl", "value": "https://api.acme.example/v1"}],
  "item": [
    {"name": "Users", "request": {"method": "GET", "url": "{{baseUrl}}/users"}}
  ]
}`

func TestLoadsAllThreeFormats(t *testing.T) {
	tests := []struct {
		name   string
		file   string
		doc    string
		format string
		server string
		path   string
	}{
		{name: "openapi-3.1", file: "openapi.yaml", doc: openAPIDoc, format: "openapi-3.1",
			server: "https://api.acme.example/v1", path: "/users"},
		{name: "openapi-3.0-json", file: "openapi.json", doc: `{
  "openapi": "3.0.3",
  "info": {"title": "Acme", "version": "1"},
  "servers": [{"url": "https://api.acme.example/v1"}],
  "paths": {"/users": {"get": {}}}
}`, format: "openapi-3.0", server: "https://api.acme.example/v1", path: "/users"},
		{name: "swagger-2.0", file: "swagger.yaml", doc: swaggerDoc, format: "swagger-2.0",
			server: "https://api.acme.example/v1", path: "/users"},
		// A Postman request's URL is absolute, so its server is the origin and
		// its path carries the base path the variable held.
		{name: "postman-2.1", file: "collection.json", doc: postmanDoc, format: "postman-2.1",
			server: "https://api.acme.example", path: "/v1/users"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workspace := t.TempDir()
			receipt, err := loadFixture(t, workspace, tt.file, tt.doc)
			if err != nil {
				t.Fatalf("Load() = %v", err)
			}
			if !receipt.OK {
				t.Errorf("OK = false, want true")
			}
			if receipt.Format != tt.format {
				t.Errorf("format = %q, want %q", receipt.Format, tt.format)
			}
			if receipt.Servers.Usable != 1 || receipt.Servers.Refused != 0 || receipt.Servers.Declared != 1 {
				t.Errorf("servers = %+v, want one declared and usable", receipt.Servers)
			}
			if receipt.Hosts.New != 1 {
				t.Errorf("hosts = %+v, want one new host", receipt.Hosts)
			}
			if receipt.Operations.Total == 0 {
				t.Errorf("operations = %+v, want at least one", receipt.Operations)
			}
			if receipt.Inventory == "" {
				t.Fatalf("inventory path is empty")
			}
			inventory := readInventory(t, workspace, receipt.Inventory)
			if inventory.Format != tt.format {
				t.Errorf("inventory format = %q, want %q", inventory.Format, tt.format)
			}
			if len(inventory.Servers) != 1 || inventory.Servers[0].URL != tt.server {
				t.Errorf("inventory servers = %+v, want %q", inventory.Servers, tt.server)
			}
			if len(inventory.Operations) != receipt.Operations.Total {
				t.Errorf("inventory operations = %d, receipt total = %d", len(inventory.Operations), receipt.Operations.Total)
			}
			if inventory.Operations[0].Method != "GET" || inventory.Operations[0].Path != tt.path {
				t.Errorf("first operation = %+v, want GET %s", inventory.Operations[0], tt.path)
			}
		})
	}
}

// readInventory reads a receipt's inventory artifact.
func readInventory(t *testing.T, workspace, relative string) apispec.Inventory {
	t.Helper()
	//nolint:gosec // the path is the loader's own artifact under the workspace.
	data, err := os.ReadFile(filepath.Join(workspace, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	var inventory apispec.Inventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	return inventory
}

func TestOutOfScopeServerRefusedByName(t *testing.T) {
	doc := `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://api.acme.example/v1
  - url: https://edge.other.example/v1
paths:
  /users:
    get: {}
`
	workspace := t.TempDir()
	store := newStore(t)
	path := writeDoc(t, "openapi.yaml", doc)
	receipt, err := apispec.Load(context.Background(), apispec.Request{
		Artifact:  "openapi.yaml",
		Path:      path,
		Workspace: workspace,
		Store:     store,
		Scope:     cidrScope("10.1.0.0/24"),
		Resolver:  acmeResolver,
		Pool:      []string{"10.1.0.0/24"},
	})
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if receipt.Servers.Declared != 2 || receipt.Servers.Usable != 1 || receipt.Servers.Refused != 1 {
		t.Errorf("servers = %+v, want 2 declared, 1 usable, 1 refused", receipt.Servers)
	}
	if len(receipt.Refused) != 1 {
		t.Fatalf("refused = %+v, want one row", receipt.Refused)
	}
	refused := receipt.Refused[0]
	if refused.Host != "edge.other.example" {
		t.Errorf("refused host = %q, want edge.other.example", refused.Host)
	}
	if !strings.Contains(refused.Reason, "outside engagement targets") || !strings.Contains(refused.Reason, "10.1.0.0/24") {
		t.Errorf("refused reason = %q, want the host and the pool it missed", refused.Reason)
	}

	// Only the in-scope sibling reached state.
	hosts := mustHosts(t, store)
	if len(hosts) != 1 || hosts[0].Hostname != "api.acme.example" {
		t.Fatalf("hosts = %+v, want only the in-scope server", hosts)
	}
	if len(hosts[0].Tags) != 1 || hosts[0].Tags[0] != "declared" {
		t.Errorf("host tags = %v, want [declared]", hosts[0].Tags)
	}
}

func TestMixedResolutionRefusesTheWholeServer(t *testing.T) {
	doc := `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://mixed.acme.example/v1
  - url: https://api.acme.example/v1
paths:
  /users:
    get: {}
`
	resolver := testResolver{
		"mixed.acme.example": {"10.1.0.5", "203.0.113.9"},
		"api.acme.example":   {"10.1.0.5"},
	}
	receipt, err := loadFixture(t, t.TempDir(), "openapi.yaml", doc, func(req *apispec.Request) {
		req.Resolver = resolver
	})
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(receipt.Refused) != 1 || receipt.Refused[0].Host != "mixed.acme.example" {
		t.Fatalf("refused = %+v, want the mixed-answer server", receipt.Refused)
	}
	if !strings.Contains(receipt.Refused[0].Reason, "203.0.113.9") {
		t.Errorf("reason = %q, want the out-of-scope address named", receipt.Refused[0].Reason)
	}
}

func TestNestedOperationServerRefusesOnlyItsOperations(t *testing.T) {
	doc := `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://api.acme.example/v1
paths:
  /users:
    get: {}
  /admin:
    get:
      servers:
        - url: https://evil.other.example/v1
`
	workspace := t.TempDir()
	receipt, err := loadFixture(t, workspace, "openapi.yaml", doc)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if receipt.Operations.Total != 2 || receipt.Operations.Unavailable != 1 {
		t.Errorf("operations = %+v, want two total, one unavailable", receipt.Operations)
	}
	inventory := readInventory(t, workspace, receipt.Inventory)
	byPath := map[string]apispec.InventoryOperation{}
	for _, op := range inventory.Operations {
		byPath[op.Path] = op
	}
	if !byPath["/users"].Available {
		t.Errorf("/users = %+v, want available", byPath["/users"])
	}
	if byPath["/admin"].Available {
		t.Errorf("/admin = %+v, want unavailable", byPath["/admin"])
	}
	if !strings.Contains(byPath["/admin"].Reason, "outside engagement targets") {
		t.Errorf("/admin reason = %q, want the refusal reason", byPath["/admin"].Reason)
	}
}

func TestPostmanUndefinedVariableIsRefusedByName(t *testing.T) {
	doc := `{
  "info": {
    "name": "Acme",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {"name": "Users", "request": {"method": "GET", "url": "{{baseUrl}}/v2/users"}}
  ]
}`
	_, err := loadFixture(t, t.TempDir(), "collection.json", doc)
	if err == nil {
		t.Fatalf("Load() = nil error, want a refusal naming {{baseUrl}}")
	}
	if !strings.Contains(err.Error(), "{{baseUrl}}") {
		t.Errorf("error = %q, want the undefined variable named", err)
	}
}

func TestPostmanFolderVariableShadowsCollection(t *testing.T) {
	doc := `{
  "info": {
    "name": "Acme",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "variable": [{"key": "baseUrl", "value": "https://edge.other.example"}],
  "item": [
    {
      "name": "Users",
      "variable": [{"key": "baseUrl", "value": "https://api.acme.example/v2"}],
      "item": [
        {"name": "List", "request": {"method": "GET", "url": "{{baseUrl}}/users"}}
      ]
    }
  ]
}`
	workspace := t.TempDir()
	receipt, err := loadFixture(t, workspace, "collection.json", doc)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if receipt.Servers.Usable != 1 || receipt.Servers.Refused != 0 {
		t.Errorf("servers = %+v, want the folder's in-scope shadow", receipt.Servers)
	}
	inventory := readInventory(t, workspace, receipt.Inventory)
	if inventory.Operations[0].Path != "/v2/users" {
		t.Errorf("operation path = %q, want /v2/users (the folder's base URL)", inventory.Operations[0].Path)
	}
	if inventory.Servers[0].URL != "https://api.acme.example" {
		t.Errorf("server = %q, want the folder's base URL origin", inventory.Servers[0].URL)
	}
}

func TestLiteralTokenIsCountedNeverEchoed(t *testing.T) {
	const token = "sk-live-abc123"
	doc := `{
  "info": {
    "name": "Acme",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "variable": [{"key": "baseUrl", "value": "https://api.acme.example/v1"}],
  "item": [
    {
      "name": "Users",
      "request": {
        "method": "GET",
        "url": "{{baseUrl}}/users?api_key=sk-live-abc123",
        "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "sk-live-abc123", "type": "string"}]}
      }
    }
  ]
}`
	workspace := t.TempDir()
	receipt, err := loadFixture(t, workspace, "collection.json", doc)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if receipt.Redacted != 1 {
		t.Errorf("redacted = %d, want 1", receipt.Redacted)
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	if strings.Contains(string(encoded), token) {
		t.Errorf("the receipt carries the literal token: %s", encoded)
	}
	//nolint:gosec // the path is the loader's own artifact under the workspace.
	inventoryData, err := os.ReadFile(filepath.Join(workspace, filepath.FromSlash(receipt.Inventory)))
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	if strings.Contains(string(inventoryData), token) {
		t.Errorf("the inventory carries the literal token: %s", inventoryData)
	}
	if receipt.Auth[0].Scheme != "bearer" || receipt.Auth[0].In != "header" || receipt.Auth[0].Name != "Authorization" {
		t.Errorf("auth = %+v, want the bearer requirement only", receipt.Auth)
	}
}

func TestRelativeOnlySwaggerRefuses(t *testing.T) {
	doc := `swagger: "2.0"
info: {title: Acme, version: "1"}
basePath: /v1
paths:
  /users:
    get: {}
`
	_, err := loadFixture(t, t.TempDir(), "swagger.yaml", doc)
	if err == nil {
		t.Fatalf("Load() = nil error, want a relative-only refusal")
	}
	if !strings.Contains(err.Error(), "relative-only") {
		t.Errorf("error = %q, want the relative-only reason", err)
	}
}

func TestReloadReusesHostIDs(t *testing.T) {
	workspace := t.TempDir()
	store := newStore(t)
	path := writeDoc(t, "openapi.yaml", openAPIDoc)
	request := apispec.Request{
		Artifact:  "openapi.yaml",
		Path:      path,
		Workspace: workspace,
		Store:     store,
		Scope:     cidrScope("10.1.0.0/24"),
		Resolver:  acmeResolver,
		Pool:      []string{"10.1.0.0/24"},
	}
	first, err := apispec.Load(context.Background(), request)
	if err != nil {
		t.Fatalf("first Load() = %v", err)
	}
	if first.Hosts.New != 1 {
		t.Fatalf("first hosts = %+v, want one new", first.Hosts)
	}
	hosts := mustHosts(t, store)
	firstID := hosts[0].ID

	second, err := apispec.Load(context.Background(), request)
	if err != nil {
		t.Fatalf("second Load() = %v", err)
	}
	if second.Hosts.Updated != 1 || second.Hosts.New != 0 {
		t.Errorf("second hosts = %+v, want the record updated in place", second.Hosts)
	}
	hosts = mustHosts(t, store)
	if len(hosts) != 1 {
		t.Fatalf("hosts = %+v, want one record after two loads", hosts)
	}
	if hosts[0].ID != firstID {
		t.Errorf("host id = %q, want the reused %q", hosts[0].ID, firstID)
	}
	if second.Inventory != first.Inventory {
		t.Errorf("inventory = %q then %q, want the same artifact rewritten", first.Inventory, second.Inventory)
	}
}

func TestUnsupportedFormatsAreNamed(t *testing.T) {
	tests := []struct{ name, doc, want string }{
		{"raml", "#%RAML 1.0\ntitle: Acme\n/users:\n  get:\n", "RAML"},
		{"api-blueprint", "FORMAT: 1A\n# Acme\n", "API Blueprint"},
		{"graphql", "type Query {\n  users: [User]\n}\n", "GraphQL SDL"},
		{"generic", `{"name": "not a spec", "items": []}`, "top-level keys"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadFixture(t, t.TempDir(), "doc.yaml", tt.doc)
			if err == nil {
				t.Fatalf("Load() = nil error, want a refusal")
			}
			if !errors.Is(err, apispec.ErrNotDeclaration) {
				t.Errorf("error = %v, want ErrNotDeclaration", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want %q", err, tt.want)
			}
		})
	}
}

func TestNonHTTPSchemeRefused(t *testing.T) {
	doc := `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: wss://api.acme.example/socket
  - url: https://api.acme.example/v1
paths:
  /users:
    get: {}
`
	receipt, err := loadFixture(t, t.TempDir(), "openapi.yaml", doc)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(receipt.Refused) != 1 || !strings.Contains(receipt.Refused[0].Reason, "non-HTTP scheme") {
		t.Errorf("refused = %+v, want the websocket scheme named", receipt.Refused)
	}
}

func TestAllRefusedIsAToolError(t *testing.T) {
	doc := `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://edge.other.example/v1
paths:
  /users:
    get: {}
`
	_, err := loadFixture(t, t.TempDir(), "openapi.yaml", doc)
	if err == nil {
		t.Fatalf("Load() = nil error, want nothing-usable refusal")
	}
	if !strings.Contains(err.Error(), "nothing usable was declared") {
		t.Errorf("error = %q, want the nothing-usable reason", err)
	}
}

func TestEmptyButValidDocumentLoads(t *testing.T) {
	doc := `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://api.acme.example/v1
paths: {}
`
	receipt, err := loadFixture(t, t.TempDir(), "openapi.yaml", doc)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if receipt.Operations.Total != 0 || receipt.Operations.Unavailable != 0 {
		t.Errorf("operations = %+v, want zero", receipt.Operations)
	}
	if receipt.Hosts.New != 1 {
		t.Errorf("hosts = %+v, want the declared server recorded", receipt.Hosts)
	}
}

func TestMalformedOperationIsSkippedWithReason(t *testing.T) {
	doc := `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://api.acme.example/v1
paths:
  users:
    get: {}
  /ok:
    get: {}
`
	receipt, err := loadFixture(t, t.TempDir(), "openapi.yaml", doc)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(receipt.Skipped) != 1 || receipt.Skipped[0].Record != "users" {
		t.Errorf("skipped = %+v, want the malformed path row", receipt.Skipped)
	}
	if receipt.Operations.Total != 1 {
		t.Errorf("operations = %+v, want the one valid operation", receipt.Operations)
	}
}

func TestOpenAPIUndefinedServerVariableRefused(t *testing.T) {
	doc := `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://{region}.acme.example/v1
paths:
  /users:
    get: {}
`
	_, err := loadFixture(t, t.TempDir(), "openapi.yaml", doc)
	if err == nil {
		t.Fatalf("Load() = nil error, want a refusal naming {region}")
	}
	if !strings.Contains(err.Error(), "{region}") {
		t.Errorf("error = %q, want the variable named", err)
	}
}

// mustHosts reads the store's host entities.
func mustHosts(t *testing.T, store *engagementstate.Store) []engagementstate.Entity {
	t.Helper()
	snapshot, err := store.Query(engagementstate.Query{Kind: engagementstate.KindHost, IncludeInactive: true})
	if err != nil {
		t.Fatalf("query hosts: %v", err)
	}
	return snapshot.Entities
}
