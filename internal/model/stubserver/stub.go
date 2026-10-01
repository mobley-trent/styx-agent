package stubserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// DefaultModels is the model list the stub advertises when none is configured.
var DefaultModels = []string{"deepseek-flash", "deepseek-v4-pro"}

// Request is a decoded request the stub received, recorded for assertions.
type Request struct {
	// Model is the requested model ID.
	Model string
	// Messages is the conversation, with the fields the stub understands.
	Messages []Message
	// Tools is the requested tool set.
	Tools []Tool
	// ToolChoice mirrors the wire's tool_choice, when present.
	ToolChoice string
	// Stream mirrors the wire's stream flag.
	Stream bool
	// MaxTokens is the requested bound, zero when unset.
	MaxTokens int
	// Authorization is the incoming Authorization header, for auth assertions.
	Authorization string
	// Path is the request path ("/chat/completions" or "/beta/chat/completions").
	Path string
}

// Message is the subset of a request message the stub records and replays.
type Message struct {
	Role       string `json:"role"`
	Content    string `json:"content"`
	ToolCallID string `json:"tool_call_id,omitempty"`
}

// Tool is the subset of a request tool the stub records.
type Tool struct {
	Name        string
	Strict      bool
	Description string
}

// Server is a running stub server. Call Close when done (it is a no-op for
// servers used purely as handlers).
type Server struct {
	ts *httptest.Server
	h  *handler
}

// Option configures the stub's handler.
type Option func(*handler)

// WithScript sets the scripted turns, consumed one per chat request.
func WithScript(turns ...Turn) Option {
	return func(h *handler) { h.turns = append([]Turn(nil), turns...) }
}

// WithRepeatLast replays the final scripted turn once the script is exhausted.
// It lets tests that only care about one behavior keep serving.
func WithRepeatLast(repeat bool) Option {
	return func(h *handler) { h.repeatLast = repeat }
}

// WithStrictEnforcement makes the stub behave like a strict-mode provider: a
// scripted tool call must name a strict tool and carry valid JSON arguments,
// or the request is rejected with a structured 400 instead of streamed.
func WithStrictEnforcement(enforce bool) Option {
	return func(h *handler) { h.strict = enforce }
}

// WithModels sets the IDs advertised by GET /models.
func WithModels(ids ...string) Option {
	return func(h *handler) { h.models = append([]string(nil), ids...) }
}

// New starts a stub server on an ephemeral localhost port.
func New(opts ...Option) *Server {
	h := &handler{
		models:  append([]string(nil), DefaultModels...),
		created: time.Now().Unix(),
	}
	for _, opt := range opts {
		opt(h)
	}
	if len(h.turns) == 0 {
		h.turns = []Turn{{Text: []string{"ok"}}}
	}
	s := &Server{h: h}
	s.ts = httptest.NewServer(h)
	return s
}

// URL is the server's base URL.
func (s *Server) URL() string { return s.ts.URL }

// Client is the server's configured HTTP client.
func (s *Server) Client() *http.Client { return s.ts.Client() }

// Close shuts the server down.
func (s *Server) Close() { s.ts.Close() }

// Handler returns the stub's HTTP handler, so a caller can mount it on their
// own server.
func (s *Server) Handler() http.Handler { return s.h }

// ListenAndServe is the standalone path: it serves the stub on addr with a
// real listener (no httptest). It blocks until the server fails.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: s.h, ReadHeaderTimeout: 5 * time.Second}
	return srv.Serve(ln)
}

// Calls reports how many chat requests the stub has served.
func (s *Server) Calls() int { return s.h.calls() }

// Requests returns a copy of every chat request received, in order.
func (s *Server) Requests() []Request { return s.h.recorded() }

// LastRequest returns the most recent request and whether any was served.
func (s *Server) LastRequest() (Request, bool) { return s.h.last() }

// handler is the stub's state and HTTP behavior.
type handler struct {
	mu         sync.Mutex
	turns      []Turn
	next       int
	repeatLast bool
	strict     bool
	models     []string
	created    int64
	requests   []Request
	count      int
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/models":
		h.serveModels(w)
	case r.Method == http.MethodPost &&
		(r.URL.Path == "/chat/completions" || r.URL.Path == "/beta/chat/completions"):
		h.serveChat(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveModels answers GET /models with the advertised model list.
func (h *handler) serveModels(w http.ResponseWriter) {
	h.mu.Lock()
	models := append([]string(nil), h.models...)
	created := h.created
	h.mu.Unlock()

	data := make([]map[string]any, 0, len(models))
	for _, id := range models {
		data = append(data, map[string]any{
			"id":       id,
			"object":   "model",
			"created":  created,
			"owned_by": "stub",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

// serveChat records the request, pops the next scripted turn, and either
// streams it or returns its injected fault.
func (h *handler) serveChat(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorObject("invalid_request_error", "read request body: "+err.Error(), "invalid_body"))
		return
	}
	var wire wireRequest
	if err := json.Unmarshal(body, &wire); err != nil {
		writeJSON(w, http.StatusBadRequest, errorObject("invalid_request_error", "malformed JSON body: "+err.Error(), "invalid_json"))
		return
	}

	turn := h.record(r, wire)

	if turn.Fault != 0 {
		h.serveFault(w, turn)
		return
	}
	if h.strict {
		if msg := strictViolation(wire, turn); msg != "" {
			writeJSON(w, http.StatusBadRequest, errorObject("invalid_request_error", msg, "strict_violation"))
			return
		}
	}
	h.serveStream(w, wire, turn)
}

// record appends the request and pops the next turn under one lock.
func (h *handler) record(r *http.Request, wire wireRequest) Turn {
	h.mu.Lock()
	defer h.mu.Unlock()

	req := Request{
		Model:         wire.Model,
		Stream:        wire.Stream,
		MaxTokens:     wire.MaxTokens,
		Authorization: r.Header.Get("Authorization"),
		Path:          r.URL.Path,
	}
	for _, m := range wire.Messages {
		req.Messages = append(req.Messages, Message(m))
	}
	for _, t := range wire.Tools {
		req.Tools = append(req.Tools, Tool{Name: t.Function.Name, Strict: t.Function.Strict, Description: t.Function.Description})
	}
	if wire.ToolChoice != nil {
		switch {
		case wire.ToolChoice.Function.Name != "":
			req.ToolChoice = wire.ToolChoice.Function.Name
		default:
			req.ToolChoice = wire.ToolChoice.Type
		}
	}
	h.requests = append(h.requests, req)
	h.count++

	switch {
	case h.next < len(h.turns):
		turn := h.turns[h.next]
		h.next++
		return turn
	case h.repeatLast && len(h.turns) > 0:
		return h.turns[len(h.turns)-1]
	default:
		return Turn{Text: []string{"stub: script exhausted"}}
	}
}

func (h *handler) calls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

func (h *handler) recorded() []Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Request(nil), h.requests...)
}

func (h *handler) last() (Request, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.requests) == 0 {
		return Request{}, false
	}
	return h.requests[len(h.requests)-1], true
}

// serveFault writes an OpenAI-style error response for the scripted status.
func (h *handler) serveFault(w http.ResponseWriter, turn Turn) {
	kind, code := "server_error", "server_error"
	switch turn.Fault {
	case http.StatusTooManyRequests:
		kind, code = "rate_limit_error", "rate_limit_exceeded"
	case http.StatusUnauthorized:
		kind, code = "authentication_error", "invalid_api_key"
	case http.StatusBadRequest:
		kind, code = "invalid_request_error", "invalid_request"
	}
	msg := turn.FaultMessage
	if msg == "" {
		msg = fmt.Sprintf("scripted fault: HTTP %d", turn.Fault)
	}
	writeJSON(w, turn.Fault, errorObject(kind, msg, code))
}

// strictViolation reports why a scripted turn is not strict-conformant, or ""
// when it is. It is the stub's analogue of provider-side strict enforcement.
func strictViolation(wire wireRequest, turn Turn) string {
	if len(turn.ToolCalls) == 0 {
		return ""
	}
	strictTools := make(map[string]bool)
	for _, t := range wire.Tools {
		if t.Function.Strict {
			strictTools[t.Function.Name] = true
		}
	}
	for _, call := range turn.ToolCalls {
		if !strictTools[call.Name] {
			return fmt.Sprintf("tool %q is not declared with strict:true", call.Name)
		}
		var args any
		if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
			return fmt.Sprintf("arguments for strict tool %q are not valid JSON: %v", call.Name, err)
		}
	}
	return ""
}

// --- wire types ---

type wireRequest struct {
	Model      string          `json:"model"`
	Messages   []wireMessage   `json:"messages"`
	Tools      []wireTool      `json:"tools"`
	ToolChoice *wireToolChoice `json:"tool_choice"`
	Stream     bool            `json:"stream"`
	MaxTokens  int             `json:"max_tokens"`
}

type wireMessage struct {
	Role       string `json:"role"`
	Content    string `json:"content"`
	ToolCallID string `json:"tool_call_id"`
}

type wireTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Strict      bool           `json:"strict"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

type wireToolChoice struct {
	Type     string `json:"type"`
	Function struct {
		Name string `json:"name"`
	} `json:"function"`
}

func (c *wireToolChoice) UnmarshalJSON(data []byte) error {
	// tool_choice is either a string ("auto") or an object; keep it as text.
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		c.Type = s
		return nil
	}
	type alias wireToolChoice
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*c = wireToolChoice(a)
	return nil
}

// chunk is one SSE data frame.
type chunk struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Created int64         `json:"created"`
	Model   string        `json:"model"`
	Choices []chunkChoice `json:"choices"`
	Usage   *chunkUsage   `json:"usage,omitempty"`
}

type chunkChoice struct {
	Index        int        `json:"index"`
	Delta        chunkDelta `json:"delta"`
	FinishReason *string    `json:"finish_reason"`
}

type chunkDelta struct {
	Role             string          `json:"role,omitempty"`
	Content          string          `json:"content,omitempty"`
	ReasoningContent string          `json:"reasoning_content,omitempty"`
	ToolCalls        []chunkToolCall `json:"tool_calls,omitempty"`
}

type chunkToolCall struct {
	Index    int                `json:"index"`
	ID       string             `json:"id,omitempty"`
	Type     string             `json:"type,omitempty"`
	Function chunkToolCallParam `json:"function"`
}

type chunkToolCallParam struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

type chunkUsage struct {
	PromptTokens          int  `json:"prompt_tokens"`
	CompletionTokens      int  `json:"completion_tokens"`
	TotalTokens           int  `json:"total_tokens"`
	PromptCacheHitTokens  int  `json:"prompt_cache_hit_tokens,omitempty"`
	PromptCacheMissTokens int  `json:"prompt_cache_miss_tokens,omitempty"`
	ReasoningTokens       *int `json:"-"`
}

// MarshalJSON flattens the usage into the provider's shape, including the
// cache fields and the reasoning breakdown when set.
func (u chunkUsage) MarshalJSON() ([]byte, error) {
	out := map[string]any{
		"prompt_tokens":     u.PromptTokens,
		"completion_tokens": u.CompletionTokens,
		"total_tokens":      u.TotalTokens,
	}
	if u.PromptCacheHitTokens != 0 {
		out["prompt_cache_hit_tokens"] = u.PromptCacheHitTokens
	}
	if u.PromptCacheMissTokens != 0 {
		out["prompt_cache_miss_tokens"] = u.PromptCacheMissTokens
	}
	if u.ReasoningTokens != nil {
		out["completion_tokens_details"] = map[string]any{"reasoning_tokens": *u.ReasoningTokens}
	}
	return json.Marshal(out)
}

// writeJSON writes a JSON response with a status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// errorObject builds an OpenAI-style error body.
func errorObject(kind, message, code string) map[string]any {
	return map[string]any{"error": map[string]any{
		"message": message,
		"type":    kind,
		"param":   nil,
		"code":    code,
	}}
}

// splitArgs splits a tool call's arguments into two streamed fragments, as the
// provider does, so clients must assemble them.
func splitArgs(args string) (string, string) {
	if len(args) < 2 {
		return args, ""
	}
	mid := len(args) / 2
	return args[:mid], args[mid:]
}
