// Package fakeserver is an in-process, per-test-scriptable MCP server
// (docs/spec.md §5.5, §11.2). It speaks the real protocol over an in-memory
// transport — real discovery, real tool calls, real disconnect semantics — so
// lifecycle and normative-order tests never launch a subprocess or touch the
// network.
//
// Boundary rule: this package depends on the official MCP SDK and on
// internal/mcpclient's connector shape only. It contains no policy logic.
package fakeserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mobley-trent/styx-agent/internal/mcpclient"
)

// Handler serves one tool call. Returning an error is a server-side tool
// error; returning a result with isError is an in-band error result.
type Handler func(ctx context.Context, tool string, args map[string]any) (string, error)

// Server is one scripted MCP server.
type Server struct {
	// Name is the server's identity in the MCP handshake.
	Name string

	mu       sync.Mutex
	tools    map[string]*mcp.Tool
	handler  Handler
	sessions []*mcp.ServerSession
}

// New builds an empty fake server. Register tools with AddTool; a call with no
// handler returns an empty result.
func New(name string) *Server {
	return &Server{Name: name, tools: map[string]*mcp.Tool{}}
}

// AddTool registers one tool with the given input schema.
func (s *Server) AddTool(name, description string, schema any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools[name] = &mcp.Tool{Name: name, Description: description, InputSchema: schema}
}

// SetHandler installs the tool-call handler.
func (s *Server) SetHandler(h Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = h
}

// Connector returns a mcpclient.Connector that serves this fake server over an
// in-memory transport. Every call gets a fresh session, so each connection is
// independent.
func (s *Server) Connector() mcpclient.Connector {
	return func(ctx context.Context, _ mcpclient.Server) (*mcp.ClientSession, error) {
		server := mcp.NewServer(&mcp.Implementation{Name: s.Name, Version: "1"}, nil)
		s.mu.Lock()
		tools := make([]*mcp.Tool, 0, len(s.tools))
		for _, t := range s.tools {
			tools = append(tools, t)
		}
		handler := s.handler
		s.mu.Unlock()
		for _, tool := range tools {
			server.AddTool(tool, s.toolHandler(handler))
		}

		serverTransport, clientTransport := mcp.NewInMemoryTransports()
		serverSession, err := server.Connect(ctx, serverTransport, nil)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.sessions = append(s.sessions, serverSession)
		s.mu.Unlock()

		client := mcp.NewClient(&mcp.Implementation{Name: "styx-test", Version: "1"}, nil)
		return client.Connect(ctx, clientTransport, nil)
	}
}

// Disconnect closes every server-side session, simulating a server that
// crashed or was killed mid-session. The connected client observes a dropped
// connection.
func (s *Server) Disconnect() {
	s.mu.Lock()
	sessions := s.sessions
	s.sessions = nil
	s.mu.Unlock()
	for _, session := range sessions {
		_ = session.Close()
	}
}

// toolHandler adapts the scripted handler to the SDK's handler shape.
func (s *Server) toolHandler(handler Handler) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := map[string]any{}
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
				return nil, fmt.Errorf("fakeserver: arguments are not a JSON object: %w", err)
			}
		}
		if handler == nil {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: ""}}}, nil
		}
		text, err := handler(ctx, req.Params.Name, args)
		if err != nil {
			return nil, err
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil
	}
}

// ErrNoConnector is returned by a Connector that is scripted to fail, so a
// launch-failure test can assert the visible error without a subprocess.
var ErrNoConnector = errors.New("fakeserver: connection refused")

// FailingConnector is a connector that always fails to connect, for launch
// failure tests.
func FailingConnector(err error) mcpclient.Connector {
	if err == nil {
		err = ErrNoConnector
	}
	return func(context.Context, mcpclient.Server) (*mcp.ClientSession, error) {
		return nil, err
	}
}
