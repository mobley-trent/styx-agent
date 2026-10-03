package mcpclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolPrefix namespaces every MCP-provided tool, so an external tool can never
// shadow a built-in and the policy rule table can target the whole family
// ("mcp__*") or one server ("mcp__nmap__*").
const ToolPrefix = "mcp__"

// NamespacedName is the tool name an MCP tool is exposed under:
// mcp__<server>__<tool>.
func NamespacedName(server, tool string) string {
	return ToolPrefix + server + "__" + tool
}

// SplitName reverses NamespacedName, reporting whether the name is an
// MCP-namespaced tool and returning its server and tool parts.
func SplitName(name string) (server, tool string, ok bool) {
	rest, found := strings.CutPrefix(name, ToolPrefix)
	if !found {
		return "", "", false
	}
	server, tool, found = strings.Cut(rest, "__")
	if !found || server == "" || tool == "" {
		return "", "", false
	}
	return server, tool, true
}

// Tool is one tool discovered from a connected server, in the shape the agent
// registry needs. The schema is the server's own input schema, carried
// verbatim: the harness validates against exactly what the server advertised.
type Tool struct {
	// Server is the configured server's name.
	Server string
	// Name is the server's own tool name, un-namespaced.
	Name string
	// Description is the server's model-facing description.
	Description string
	// Schema is the tool's input schema as raw JSON, normalized to a JSON
	// Schema object so the repair layer can always validate against it.
	Schema json.RawMessage
}

// Namespaced is the tool's name in the session registry.
func (t Tool) Namespaced() string { return NamespacedName(t.Server, t.Name) }

// Server is one configured MCP server to launch (§5.5). It mirrors the
// operator's config block without importing it: app maps config onto this
// shape, keeping this package independent of the config layer.
type Server struct {
	// Name identifies the server and namespaces its tools.
	Name string
	// Command is the executable to launch.
	Command string
	// Args are the command's arguments.
	Args []string
	// Env is extra environment entries (KEY=VALUE) for the process.
	Env []string
}

// Status is one server's connection lifecycle (§5.5, §9.1).
type Status string

const (
	// StatusConnecting is a server being launched and initialized.
	StatusConnecting Status = "connecting"
	// StatusReady is a connected server whose tools are registered.
	StatusReady Status = "ready"
	// StatusFailed is a server that could not launch, or whose connection
	// dropped. Its tools are not available.
	StatusFailed Status = "failed"
	// StatusClosed is a server the harness shut down cleanly.
	StatusClosed Status = "closed"
)

// ServerStatus is one server's lifecycle, as the TUI and the status line
// render it.
type ServerStatus struct {
	// Name is the configured server's name.
	Name string
	// Status is its lifecycle state.
	Status Status
	// Detail is a human-readable note: the launch failure, the disconnect, or
	// the tool count.
	Detail string
	// Tools is how many tools the server contributes.
	Tools int
}

// Event reports one lifecycle transition. It is what the harness forwards onto
// the session event bus, so a connection, a failure, or a disconnect is never
// silent (§4.3, §5.5).
type Event struct {
	// Server is the configured server's name.
	Server string
	// Status is the new state.
	Status Status
	// Detail is a human-readable note.
	Detail string
	// Tools is how many tools the server contributes, for a ready transition.
	Tools int
}

// Connector connects one configured server and returns its initialized
// session. It is the seam that keeps the manager testable: production launches
// a subprocess over stdio, while tests (and the harness's test options)
// substitute an in-memory server. It is also the seam that keeps the SDK type
// out of the app layer's option struct.
type Connector func(ctx context.Context, srv Server) (*mcp.ClientSession, error)

// Manager owns the session's MCP servers: it launches them over stdio,
// discovers their tools, exposes them to the agent, and reports their
// lifecycle. It is safe for concurrent use.
//
// A server that fails to launch or drops mid-session is a lifecycle event and
// a tool-level error, never a harness crash: the rest of the session keeps
// working.
type Manager struct {
	mu       sync.Mutex
	order    []string
	sessions map[string]*mcp.ClientSession
	statuses map[string]ServerStatus
	tools    []Tool
	closing  map[string]bool

	emit      func(Event)
	connector Connector
}

// Option configures a Manager.
type Option func(*Manager)

// WithEmitter sets the lifecycle sink. Nil drops lifecycle events.
func WithEmitter(emit func(Event)) Option {
	return func(m *Manager) {
		if emit != nil {
			m.emit = emit
		}
	}
}

// WithConnector replaces how a server is connected. It is the seam tests use
// to substitute an in-memory server for a launched subprocess. Nil keeps the
// stdio launch.
func WithConnector(c Connector) Option {
	return func(m *Manager) {
		if c != nil {
			m.connector = c
		}
	}
}

// New builds a Manager.
func New(opts ...Option) *Manager {
	m := &Manager{
		sessions: map[string]*mcp.ClientSession{},
		statuses: map[string]ServerStatus{},
		closing:  map[string]bool{},
		emit:     func(Event) {},
	}
	for _, opt := range opts {
		opt(m)
	}
	if m.connector == nil {
		m.connector = StdioConnector
	}
	return m
}

// StdioConnector launches a server as a subprocess and speaks MCP over its
// stdin/stdout (§5.5). The command is operator-configured by design, which is
// exactly why the harness gates the resulting tools through the policy engine.
func StdioConnector(ctx context.Context, srv Server) (*mcp.ClientSession, error) {
	//nolint:gosec // the command is operator-configured by design (§5.5, §10.3).
	cmd := exec.CommandContext(ctx, srv.Command, srv.Args...)
	if len(srv.Env) > 0 {
		cmd.Env = append(cmd.Environ(), srv.Env...)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "styx", Version: "1"}, nil)
	return client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
}

// Start connects every server, in order, discovering its tools. A server that
// fails is recorded as failed and reported; it never aborts the others, and it
// never aborts the session. Start is idempotent per server: a server already
// connected is left alone.
func (m *Manager) Start(ctx context.Context, servers []Server) {
	for _, srv := range servers {
		m.startOne(ctx, srv)
	}
}

// startOne connects one server and records its lifecycle. A server already
// connected is left alone, so Start is safe to call again.
func (m *Manager) startOne(ctx context.Context, srv Server) {
	m.mu.Lock()
	_, connected := m.sessions[srv.Name]
	m.mu.Unlock()
	if connected {
		return
	}

	m.setStatus(srv.Name, ServerStatus{Name: srv.Name, Status: StatusConnecting})

	session, err := m.connector(ctx, srv)
	if err != nil {
		m.fail(srv.Name, fmt.Sprintf("launch failed: %v", err))
		return
	}

	tools, err := discover(ctx, srv.Name, session)
	if err != nil {
		_ = session.Close()
		m.fail(srv.Name, fmt.Sprintf("tool discovery failed: %v", err))
		return
	}

	m.mu.Lock()
	m.sessions[srv.Name] = session
	m.order = append(m.order, srv.Name)
	m.tools = append(m.tools, tools...)
	m.statuses[srv.Name] = ServerStatus{
		Name:   srv.Name,
		Status: StatusReady,
		Detail: fmt.Sprintf("%d tool(s)", len(tools)),
		Tools:  len(tools),
	}
	m.mu.Unlock()

	m.emitEvent(Event{Server: srv.Name, Status: StatusReady, Detail: fmt.Sprintf("%d tool(s)", len(tools)), Tools: len(tools)})

	// Watch for an unexpected termination, so a crash surfaces in the TUI even
	// when no call is in flight (§5.5).
	go m.watch(srv.Name, session)
}

// discover lists a server's tools and normalizes each schema.
func discover(ctx context.Context, server string, session *mcp.ClientSession) ([]Tool, error) {
	var out []Tool
	params := &mcp.ListToolsParams{}
	for {
		res, err := session.ListTools(ctx, params)
		if err != nil {
			return nil, err
		}
		for _, t := range res.Tools {
			out = append(out, Tool{
				Server:      server,
				Name:        t.Name,
				Description: t.Description,
				Schema:      normalizeSchema(t.InputSchema),
			})
		}
		if res.NextCursor == "" {
			break
		}
		params.Cursor = res.NextCursor
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// normalizeSchema renders a server's input schema as a JSON Schema object.
// A server that advertises no schema, or an unparseable one, gets the empty
// object schema: the harness still validates against it (and an empty schema
// accepts any object), rather than trusting the server's strictness.
func normalizeSchema(schema any) json.RawMessage {
	if schema == nil {
		return json.RawMessage(`{"type":"object","properties":{}}`)
	}
	b, err := json.Marshal(schema)
	if err != nil {
		return json.RawMessage(`{"type":"object","properties":{}}`)
	}
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil || obj == nil {
		return json.RawMessage(`{"type":"object","properties":{}}`)
	}
	return b
}

// watch reports a session that ended without the harness closing it.
func (m *Manager) watch(server string, session *mcp.ClientSession) {
	err := session.Wait()

	m.mu.Lock()
	if m.closing[server] {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	detail := "the server disconnected"
	if err != nil {
		detail = fmt.Sprintf("the server disconnected: %v", err)
	}
	m.fail(server, detail)
}

// fail records a server as failed and reports it once.
func (m *Manager) fail(server, detail string) {
	m.mu.Lock()
	if m.statuses[server].Status == StatusFailed {
		m.mu.Unlock()
		return
	}
	m.statuses[server] = ServerStatus{Name: server, Status: StatusFailed, Detail: detail}
	m.tools = removeServerTools(m.tools, server)
	m.mu.Unlock()

	m.emitEvent(Event{Server: server, Status: StatusFailed, Detail: detail})
}

// setStatus records a transient lifecycle state.
func (m *Manager) setStatus(server string, st ServerStatus) {
	m.mu.Lock()
	m.statuses[server] = st
	m.mu.Unlock()
	m.emitEvent(Event{Server: server, Status: st.Status, Detail: st.Detail, Tools: st.Tools})
}

// emitEvent publishes one lifecycle event.
func (m *Manager) emitEvent(ev Event) {
	if m.emit != nil {
		m.emit(ev)
	}
}

// Tools returns the discovered tools of every ready server, in a stable order.
func (m *Manager) Tools() []Tool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Tool(nil), m.tools...)
}

// Statuses returns every server's lifecycle, in connection order followed by
// any that never connected, sorted by name within that grouping.
func (m *Manager) Statuses() []ServerStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ServerStatus, 0, len(m.statuses))
	for _, name := range m.order {
		if st, ok := m.statuses[name]; ok {
			out = append(out, st)
		}
	}
	rest := make([]string, 0, len(m.statuses))
	for name := range m.statuses {
		if _, connected := m.sessions[name]; !connected {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	for _, name := range rest {
		out = append(out, m.statuses[name])
	}
	return out
}

// Call invokes a tool on its server and returns its rendered result. A server
// that is not connected, or that fails or drops during the call, is a
// tool-level error the model sees — never a harness crash (§5.5).
func (m *Manager) Call(ctx context.Context, server, tool string, args map[string]any) (string, error) {
	m.mu.Lock()
	session, ok := m.sessions[server]
	m.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("mcp server %q is not connected", server)
	}
	if args == nil {
		args = map[string]any{}
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		if errors.Is(err, mcp.ErrConnectionClosed) {
			m.fail(server, fmt.Sprintf("the server disconnected during %s", tool))
			return "", fmt.Errorf("mcp server %q is no longer connected (it crashed or disconnected); its tools are unavailable", server)
		}
		return "", fmt.Errorf("mcp tool %s failed: %w", NamespacedName(server, tool), err)
	}

	text := renderResult(res)
	if res.IsError {
		return "", fmt.Errorf("mcp tool %s reported an error: %s", NamespacedName(server, tool), text)
	}
	return text, nil
}

// renderResult flattens a tool result's content into text. Text content is
// concatenated; any other content type is rendered as its JSON encoding, so
// nothing the server returned is silently dropped.
func renderResult(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
			if !strings.HasSuffix(tc.Text, "\n") {
				b.WriteByte('\n')
			}
			continue
		}
		if encoded, err := json.Marshal(c); err == nil {
			b.Write(encoded)
			b.WriteByte('\n')
		}
	}
	if res.StructuredContent != nil {
		if encoded, err := json.Marshal(res.StructuredContent); err == nil {
			b.Write(encoded)
			b.WriteByte('\n')
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// Close shuts every connected server down cleanly and records the transitions.
func (m *Manager) Close() error {
	m.mu.Lock()
	names := append([]string(nil), m.order...)
	sessions := make(map[string]*mcp.ClientSession, len(m.sessions))
	for k, v := range m.sessions {
		sessions[k] = v
	}
	m.sessions = map[string]*mcp.ClientSession{}
	for _, name := range names {
		m.closing[name] = true
	}
	m.mu.Unlock()

	var errs []error
	for _, name := range names {
		if err := sessions[name].Close(); err != nil {
			errs = append(errs, fmt.Errorf("mcp server %s: %w", name, err))
		}
		m.mu.Lock()
		// A server that already failed keeps its failure as the visible
		// state: "closed" would erase the reason the operator needs.
		if m.statuses[name].Status != StatusFailed {
			m.statuses[name] = ServerStatus{Name: name, Status: StatusClosed, Detail: "closed"}
			m.mu.Unlock()
			m.emitEvent(Event{Server: name, Status: StatusClosed, Detail: "closed"})
			continue
		}
		m.mu.Unlock()
	}
	return errors.Join(errs...)
}

// removeServerTools drops one server's tools from a tool slice. It copies
// rather than filtering in place: the slice's backing array must not be
// mutated under a caller that read it earlier.
func removeServerTools(tools []Tool, server string) []Tool {
	out := make([]Tool, 0, len(tools))
	for _, t := range tools {
		if t.Server != server {
			out = append(out, t)
		}
	}
	return out
}
