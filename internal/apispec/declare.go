package apispec

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// FormatKey reports whether a document's bytes carry one of the format keys
// §2.1 sniffs, without loading the document. Diff scope uses it as the content
// half of "is this changed file a declaration?" (docs/api-spec-targets.md
// §5.1): extension alone would admit every YAML in the tree, and content alone
// would decode every changed file.
//
// A document that decodes is judged by its top-level keys, exactly as the
// loader sniffs it. One that does not decode is judged leniently — a broken
// declaration still names its format, and a diff that breaks a spec must be
// refused rather than skipped (§5.2) — so the fallback reads the top-level
// key lines and the compact `"openapi":` form. It never decides a format, only
// whether a load is owed.
func FormatKey(data []byte) bool {
	var root any
	if err := yaml.Unmarshal(data, &root); err == nil {
		if doc := asMap(root); doc != nil {
			return hasFormatKey(doc)
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Only an unindented key is a document key: a description that
		// mentions openapi is not a declaration.
		if line == trimmed {
			name, value, ok := strings.Cut(trimmed, ":")
			if !ok {
				continue
			}
			switch strings.Trim(strings.TrimSpace(name), `"'`) {
			case "openapi", "swagger":
				if strings.TrimSpace(value) != "" {
					return true
				}
			}
		}
		if strings.Contains(trimmed, "schema.getpostman.com") {
			return true
		}
	}
	// A JSON document whose braces do not balance decodes as nothing, so the
	// key is still worth finding on one line.
	compact := strings.Join(strings.Fields(string(data)), " ")
	return strings.Contains(compact, `"openapi":`) || strings.Contains(compact, `"swagger":`)
}

// hasFormatKey reads the distinguishing keys out of a decoded document.
func hasFormatKey(doc map[string]any) bool {
	if strings.TrimSpace(getString(doc, "openapi")) != "" {
		return true
	}
	if strings.TrimSpace(getString(doc, "swagger")) != "" {
		return true
	}
	info := getMap(doc, "info")
	if info == nil {
		return false
	}
	return strings.Contains(strings.TrimSpace(getString(info, "schema")), "schema.getpostman.com")
}

// DeclareRequest is a harness-side declaration read: one document's bytes, the
// engagement's pool, and nothing to write. It is what diff scope uses
// (docs/api-spec-targets.md §5.1): the scope is computed before the first turn,
// and a CI run may exit without ever taking one, so a scope calculation must
// not write state or an inventory.
type DeclareRequest struct {
	// Artifact is the document as the caller names it, used in refusals.
	Artifact string
	// Data is the document's bytes.
	Data []byte
	// Scope is the engagement's pool, as the loader checks it.
	Scope Scope
	// Resolver pins declared hostnames. Nil means the host resolver.
	Resolver Resolver
	// Pool is the engagement's targets as declared, for refusal reasons.
	Pool []string
}

// DeclaredServer is one declared server after the load-time scope check.
type DeclaredServer struct {
	// URL is the rendered absolute URL, empty when rendering failed.
	URL string
	// Host is the resolved hostname or IP literal, empty when unresolved.
	Host string
	// Addresses are the addresses the server resolved to.
	Addresses []netip.Addr
	// Usable is true when every address falls inside the pool.
	Usable bool
	// Reason is why the server is unusable, empty when it is usable.
	Reason string
	// Variable names the undefined variable that stopped rendering, empty
	// when the declaration rendered.
	Variable string
}

// Declaration is the surface one document declares: its servers after the
// scope check, every operation with its effective server, and the limiting
// facts the receipt reports. Nothing here is written anywhere.
type Declaration struct {
	Artifact   string
	Format     string
	Servers    []DeclaredServer
	Operations []InventoryOperation
	Auth       []AuthRequirement
	Redacted   int
	Skipped    []Skipped
	Warnings   []string
	// NoServer explains a document that declares no server at all (§7). It is
	// the refusal a load reports and the "declares nothing" a diff scope
	// ignores.
	NoServer string
}

// Usable returns the declared servers the pool authorizes, in document order.
func (d Declaration) Usable() []DeclaredServer {
	var out []DeclaredServer
	for _, server := range d.Servers {
		if server.Usable {
			out = append(out, server)
		}
	}
	return out
}

// Refused returns every declared server that could not be used, in document
// order.
func (d Declaration) Refused() []DeclaredServer {
	var out []DeclaredServer
	for _, server := range d.Servers {
		if !server.Usable {
			out = append(out, server)
		}
	}
	return out
}

// Unavailable counts the operations no usable server is in force for.
func (d Declaration) Unavailable() int {
	count := 0
	for _, op := range d.Operations {
		if !op.Available {
			count++
		}
	}
	return count
}

// Declare reads one document's bytes and checks every declared server against
// the engagement's pool, writing nothing: no host entity, no inventory, no pin,
// no audit. It is the loader's extraction half, shared with the tool so the two
// can never disagree about what a document declares.
func Declare(ctx context.Context, req DeclareRequest) (Declaration, error) {
	if req.Scope == nil {
		return Declaration{}, fmt.Errorf("%s: no engagement scope is active, so a declaration has no pool to check", ToolName)
	}
	ctx, cancel := context.WithTimeout(ctx, LoadTimeout)
	defer cancel()

	doc, err := parseDocument(req.Artifact, req.Data)
	if err != nil {
		return Declaration{}, err
	}
	out := Declaration{
		Artifact: req.Artifact,
		Format:   doc.format,
		Auth:     doc.auth,
		Redacted: doc.redacted,
		Skipped:  doc.skipped,
		Warnings: doc.warnings,
		NoServer: doc.noServer,
	}
	if len(doc.servers) == 0 {
		if out.NoServer == "" {
			out.NoServer = "declares no server at all: with no base URL there is nothing to authorize"
		}
		return out, nil
	}

	l := &loader{
		ctx:      ctx,
		scope:    req.Scope,
		pool:     req.Pool,
		resolver: req.Resolver,
		hosts:    map[string]hostLookup{},
	}
	if l.resolver == nil {
		l.resolver = defaultResolver{}
	}

	order, resolutions := l.classify(doc.servers)
	for _, key := range order {
		r := resolutions[key]
		url := r.url
		if url == "" {
			url = r.decl.raw
		}
		out.Servers = append(out.Servers, DeclaredServer{
			URL:       url,
			Host:      r.host,
			Addresses: append([]netip.Addr(nil), r.addrs...),
			Usable:    r.usable,
			Reason:    r.reason,
			Variable:  r.decl.variable,
		})
	}
	out.Operations, _ = inventoryOperations(doc, resolutions)
	return out, nil
}

// classify resolves each distinct declaration once, in document order, and
// checks it against the pool.
func (l *loader) classify(servers []serverDecl) ([]string, map[string]*resolution) {
	var order []string
	resolutions := map[string]*resolution{}
	for _, decl := range servers {
		key := declKey(decl)
		if _, seen := resolutions[key]; seen {
			continue
		}
		order = append(order, key)
		resolutions[key] = l.resolve(decl)
	}
	return order, resolutions
}

// refusals renders refused servers as receipt rows.
func refusals(servers []DeclaredServer) []Refusal {
	out := make([]Refusal, 0, len(servers))
	for _, server := range servers {
		out = append(out, Refusal{Server: server.URL, Host: server.Host, Reason: server.Reason})
	}
	return out
}

// unresolvedOf renders the undefined-variable declarations, once per variable.
func unresolvedOf(servers []DeclaredServer) []Unresolved {
	var out []Unresolved
	seen := map[string]bool{}
	for _, server := range servers {
		if server.Variable == "" || seen[server.Variable] {
			continue
		}
		seen[server.Variable] = true
		out = append(out, Unresolved{Variable: server.Variable, Server: server.URL, Reason: server.Reason})
	}
	return out
}

// addressesOf collects every address the declared servers resolved to, usable
// and refused alike, deduplicated and sorted.
func addressesOf(servers []DeclaredServer) []string {
	seen := map[netip.Addr]bool{}
	out := []string{}
	for _, server := range servers {
		for _, addr := range server.Addresses {
			if seen[addr] {
				continue
			}
			seen[addr] = true
			out = append(out, addr.String())
		}
	}
	sort.Strings(out)
	return out
}
