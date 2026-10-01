package model

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/packages/param"
	"github.com/openai/openai-go/packages/ssestream"
)

// Provider defaults (§3.1–§3.3).
const (
	// DefaultDeepSeekBaseURL is the OpenAI-compatible base URL.
	DefaultDeepSeekBaseURL = "https://api.deepseek.com"
	// DefaultBetaPath is the strict-mode endpoint prefix (§3.3). Strict tool
	// calls go to `<base>/beta/chat/completions`.
	DefaultBetaPath = "beta"
	// DefaultModelID is the default pinned model (§3.1).
	DefaultModelID = "deepseek-flash"
	// DefaultMaxRetries is the retry ceiling: 5 attempts total (§3.3).
	DefaultMaxRetries = 5
)

// Info is one pinned model's configuration. Model IDs are configuration,
// never aliases, and carry the context-window size the compaction trigger
// rescales from (§3.1).
type Info struct {
	// ID is the pinned API model ID, e.g. "deepseek-flash".
	ID string
	// ContextWindow is the model's context size in tokens.
	ContextWindow int
	// Pricing is the model's peak per-million-token rates.
	Pricing Pricing
}

// DeepSeekConfig configures the concrete DeepSeek client.
type DeepSeekConfig struct {
	// APIKey is the DeepSeek credential. It is env-only in the harness
	// (DEEPSEEK_API_KEY, §10.5) and never persisted.
	APIKey string
	// BaseURL is the OpenAI-compatible base; empty means the DeepSeek default.
	BaseURL string
	// Models is the pinned model set. Non-empty; validated against GET /models
	// at startup (§3.1).
	Models []Info
	// DefaultModel is the model StreamTurn uses when a request names none.
	DefaultModel string
	// HTTPClient overrides the default client (tests inject one). Nil keeps the
	// SDK default.
	HTTPClient *http.Client
}

// DeepSeekClient is the concrete ModelClient for the DeepSeek API, built on
// openai-go (§2, §3.2). It owns its own retry loop — the SDK's built-in
// retries are disabled so the §3.3 policy (jittered exponential backoff, max 5
// attempts) is the only one in force and is fully testable.
type DeepSeekClient struct {
	cfg   DeepSeekConfig
	beta  string
	byID  map[string]Info
	inner openai.Client
	retry retryPolicy
	now   func() time.Time
}

var _ ModelClient = (*DeepSeekClient)(nil)

// DeepSeekOption configures a DeepSeekClient at construction.
type DeepSeekOption func(*DeepSeekClient)

// WithDeepSeekBackoff overrides the backoff schedule: it returns the delay
// before the given 1-based retry attempt. Tests pin it to a fixed schedule.
func WithDeepSeekBackoff(fn func(attempt int) time.Duration) DeepSeekOption {
	return func(c *DeepSeekClient) {
		if fn != nil {
			c.retry.backoff = fn
		}
	}
}

// WithDeepSeekSleeper overrides how the client waits between attempts. Tests
// inject a recorder that never actually sleeps.
func WithDeepSeekSleeper(fn func(context.Context, time.Duration) error) DeepSeekOption {
	return func(c *DeepSeekClient) {
		if fn != nil {
			c.retry.sleep = fn
		}
	}
}

// WithDeepSeekClock overrides the clock the client stamps events with.
func WithDeepSeekClock(now func() time.Time) DeepSeekOption {
	return func(c *DeepSeekClient) {
		if now != nil {
			c.now = now
		}
	}
}

// NewDeepSeek builds the DeepSeek client. It does not touch the network —
// call Validate for the startup check against GET /models — so it is safe to
// construct in tests and wire before any I/O.
func NewDeepSeek(cfg DeepSeekConfig, opts ...DeepSeekOption) (*DeepSeekClient, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("model: DeepSeek API key is required")
	}
	if len(cfg.Models) == 0 {
		return nil, errors.New("model: at least one pinned model is required")
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		base = DefaultDeepSeekBaseURL
	}

	c := &DeepSeekClient{
		cfg:  cfg,
		beta: base + "/" + DefaultBetaPath,
		byID: make(map[string]Info, len(cfg.Models)),
		retry: retryPolicy{
			maxAttempts: DefaultMaxRetries,
			backoff:     jitteredExponential,
			sleep:       sleepCtx,
		},
		now: time.Now,
	}
	for _, info := range cfg.Models {
		if strings.TrimSpace(info.ID) == "" {
			return nil, errors.New("model: a pinned model has an empty ID")
		}
		c.byID[info.ID] = info
	}
	if cfg.DefaultModel != "" {
		if _, ok := c.byID[cfg.DefaultModel]; !ok {
			return nil, fmt.Errorf("%w: default %q is not in the pinned set", ErrUnknownModel, cfg.DefaultModel)
		}
	}
	for _, opt := range opts {
		opt(c)
	}

	sdkOpts := []option.RequestOption{
		option.WithAPIKey(cfg.APIKey),
		option.WithBaseURL(base),
		// The §3.3 retry policy is ours; two retriers would fight.
		option.WithMaxRetries(0),
	}
	if cfg.HTTPClient != nil {
		sdkOpts = append(sdkOpts, option.WithHTTPClient(cfg.HTTPClient))
	}
	c.inner = openai.NewClient(sdkOpts...)
	return c, nil
}

// Models returns the configured pinned model set, in declaration order.
func (c *DeepSeekClient) Models() []Info {
	return append([]Info(nil), c.cfg.Models...)
}

// Validate performs the §3.1 startup check: every configured pinned model ID
// must appear in GET /models. An unknown ID is fatal — the harness never
// starts pointed at a model the provider does not serve.
func (c *DeepSeekClient) Validate(ctx context.Context) error {
	page, err := c.inner.Models.List(ctx)
	if err != nil {
		return fmt.Errorf("model: validate pinned IDs: %w", err)
	}
	available := make(map[string]bool, len(page.Data))
	for _, m := range page.Data {
		available[m.ID] = true
	}
	var missing []string
	for _, info := range c.cfg.Models {
		if !available[info.ID] {
			missing = append(missing, info.ID)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: not offered by the provider: %s", ErrUnknownModel, strings.Join(missing, ", "))
	}
	return nil
}

// StreamTurn maps the request to the wire, performs the retry policy on the
// initial request, and then streams events until the provider is done. A
// failure before the stream is established is returned from this call; a
// failure after it arrives as a terminal EventError.
func (c *DeepSeekClient) StreamTurn(ctx context.Context, req ModelRequest) (<-chan StreamEvent, error) {
	// Resolve the model before validating: an empty request model means the
	// configured default, which validateRequest then sees as required.
	if req.Model == "" {
		req.Model = c.cfg.DefaultModel
		if req.Model == "" {
			return nil, fmt.Errorf("%w: no model in the request and no default configured", ErrUnknownModel)
		}
	}
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	if _, ok := c.byID[req.Model]; !ok {
		return nil, fmt.Errorf("%w: %q is not in the pinned set", ErrUnknownModel, req.Model)
	}

	params, opts, err := c.wireParams(req)
	if err != nil {
		return nil, err
	}

	var stream *ssestream.Stream[openai.ChatCompletionChunk]
	var lastErr error
	for attempt := 1; attempt <= c.retry.maxAttempts; attempt++ {
		stream = c.inner.Chat.Completions.NewStreaming(ctx, params, opts...)
		if err := stream.Err(); err != nil {
			lastErr = err
			if !retryable(err) || attempt == c.retry.maxAttempts {
				break
			}
			if err := c.retry.sleep(ctx, c.retry.backoff(attempt)); err != nil {
				return nil, err
			}
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		if retryable(lastErr) {
			return nil, fmt.Errorf("%w: %w", ErrRetryExhausted, lastErr)
		}
		return nil, fmt.Errorf("model: stream turn: %w", lastErr)
	}

	ch := make(chan StreamEvent, 8)
	go c.pump(ctx, stream, ch)
	return ch, nil
}

// wireParams translates a ModelRequest into openai-go parameters, and selects
// the strict-mode endpoint when any tool is strict (§3.3).
func (c *DeepSeekClient) wireParams(req ModelRequest) (openai.ChatCompletionNewParams, []option.RequestOption, error) {
	messages, err := wireMessages(req.Messages)
	if err != nil {
		return openai.ChatCompletionNewParams{}, nil, err
	}
	params := openai.ChatCompletionNewParams{
		Model:    req.Model,
		Messages: messages,
		// DeepSeek returns usage only when asked (§3.1: cache-token fields).
		StreamOptions: openai.ChatCompletionStreamOptionsParam{IncludeUsage: param.NewOpt(true)},
	}
	if req.MaxTokens > 0 {
		params.MaxTokens = param.NewOpt(int64(req.MaxTokens))
	}
	if req.Temperature != nil {
		params.Temperature = param.NewOpt(*req.Temperature)
	}

	strict := false
	for _, t := range req.Tools {
		tool, err := wireTool(t)
		if err != nil {
			return openai.ChatCompletionNewParams{}, nil, err
		}
		if t.Strict {
			strict = true
		}
		params.Tools = append(params.Tools, tool)
	}

	var opts []option.RequestOption
	if strict {
		opts = append(opts, option.WithBaseURL(c.beta))
	}
	return params, opts, nil
}

// wireMessages maps the harness messages onto the SDK's union type. Assistant
// reasoning is intentionally dropped: providers reject echoed reasoning.
func wireMessages(msgs []Message) ([]openai.ChatCompletionMessageParamUnion, error) {
	out := make([]openai.ChatCompletionMessageParamUnion, 0, len(msgs))
	for _, m := range msgs {
		switch m.Role {
		case RoleSystem:
			out = append(out, openai.SystemMessage(m.Content))
		case RoleUser:
			out = append(out, openai.UserMessage(m.Content))
		case RoleTool:
			out = append(out, openai.ToolMessage(m.Content, m.ToolCallID))
		case RoleAssistant:
			assistant := openai.ChatCompletionAssistantMessageParam{}
			if m.Content != "" {
				assistant.Content.OfString = param.NewOpt(m.Content)
			}
			for _, tc := range m.ToolCalls {
				assistant.ToolCalls = append(assistant.ToolCalls, openai.ChatCompletionMessageToolCallParam{
					ID: tc.ID,
					Function: openai.ChatCompletionMessageToolCallFunctionParam{
						Name:      tc.Name,
						Arguments: tc.Arguments,
					},
				})
			}
			out = append(out, openai.ChatCompletionMessageParamUnion{OfAssistant: &assistant})
		default:
			return nil, fmt.Errorf("model: cannot encode role %q", m.Role)
		}
	}
	return out, nil
}

// wireTool maps a tool descriptor, decoding its raw JSON Schema.
func wireTool(t Tool) (openai.ChatCompletionToolParam, error) {
	fn := openai.FunctionDefinitionParam{
		Name:        t.Name,
		Description: param.NewOpt(t.Description),
	}
	fn.Strict = param.NewOpt(t.Strict)
	if len(t.Parameters) > 0 {
		var schema map[string]any
		if err := json.Unmarshal(t.Parameters, &schema); err != nil {
			return openai.ChatCompletionToolParam{}, fmt.Errorf("model: tool %q: invalid parameter schema: %w", t.Name, err)
		}
		fn.Parameters = openai.FunctionParameters(schema)
	}
	return openai.ChatCompletionToolParam{Function: fn}, nil
}

// pump consumes the SDK stream and re-emits it as StreamEvents. It assembles
// tool-call fragments (the provider streams arguments piecewise) and surfaces
// reasoning separately from text (§3.2, §3.3).
func (c *DeepSeekClient) pump(ctx context.Context, stream *ssestream.Stream[openai.ChatCompletionChunk], ch chan<- StreamEvent) {
	defer close(ch)
	defer func() { _ = stream.Close() }()

	acc := newToolCallAccumulator()
	var usage *Usage

	for stream.Next() {
		if err := ctx.Err(); err != nil {
			c.emit(ctx, ch, StreamEvent{Kind: EventError, Err: err, At: c.now()})
			return
		}
		chunk := stream.Current()

		for _, choice := range chunk.Choices {
			if reasoning := reasoningDelta(choice.Delta); reasoning != "" {
				if !c.emit(ctx, ch, StreamEvent{Kind: EventReasoningDelta, Reasoning: reasoning, At: c.now()}) {
					return
				}
			}
			if choice.Delta.Content != "" {
				if !c.emit(ctx, ch, StreamEvent{Kind: EventTextDelta, Text: choice.Delta.Content, At: c.now()}) {
					return
				}
			}
			for _, tc := range choice.Delta.ToolCalls {
				acc.add(tc)
			}
			if choice.FinishReason == "tool_calls" {
				for _, call := range acc.flush() {
					if !c.emit(ctx, ch, StreamEvent{Kind: EventToolCall, ToolCall: &call, At: c.now()}) {
						return
					}
				}
			}
		}

		if u := chunkUsage(chunk); u != nil {
			usage = u
		}
	}

	if err := stream.Err(); err != nil {
		c.emit(ctx, ch, StreamEvent{Kind: EventError, Err: fmt.Errorf("%w: %w", ErrStream, err), At: c.now()})
		return
	}
	// A provider that ended without a tool_calls finish reason can still have
	// left calls in flight; emit them rather than dropping them.
	for _, call := range acc.flush() {
		if !c.emit(ctx, ch, StreamEvent{Kind: EventToolCall, ToolCall: &call, At: c.now()}) {
			return
		}
	}
	c.emit(ctx, ch, StreamEvent{Kind: EventDone, Usage: usage, At: c.now()})
}

// emit delivers one event, or reports false when the consumer stopped reading
// and the context is gone.
func (c *DeepSeekClient) emit(ctx context.Context, ch chan<- StreamEvent, ev StreamEvent) bool {
	select {
	case ch <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

// reasoningDelta extracts DeepSeek's `reasoning_content` from a chunk delta.
// The field is provider-specific and therefore not in the OpenAI schema; it is
// recovered from the delta's raw JSON.
func reasoningDelta(delta openai.ChatCompletionChunkChoiceDelta) string {
	raw := delta.RawJSON()
	if raw == "" {
		return ""
	}
	var v struct {
		ReasoningContent string `json:"reasoning_content"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return ""
	}
	return v.ReasoningContent
}

// chunkUsage maps a chunk's usage payload, including DeepSeek's
// `prompt_cache_hit_tokens` / `prompt_cache_miss_tokens` cache fields (§3.1).
func chunkUsage(chunk openai.ChatCompletionChunk) *Usage {
	if !chunk.JSON.Usage.Valid() {
		return nil
	}
	u := &Usage{
		PromptTokens:     int(chunk.Usage.PromptTokens),
		CompletionTokens: int(chunk.Usage.CompletionTokens),
		TotalTokens:      int(chunk.Usage.TotalTokens),
		ReasoningTokens:  int(chunk.Usage.CompletionTokensDetails.ReasoningTokens),
	}
	if raw := chunk.Usage.RawJSON(); raw != "" {
		var extra struct {
			PromptCacheHitTokens  int `json:"prompt_cache_hit_tokens"`
			PromptCacheMissTokens int `json:"prompt_cache_miss_tokens"`
		}
		if err := json.Unmarshal([]byte(raw), &extra); err == nil {
			u.CacheHitTokens = extra.PromptCacheHitTokens
			u.CacheMissTokens = extra.PromptCacheMissTokens
		}
	}
	return u
}

// toolCallAccumulator assembles streamed tool-call fragments by index. The
// first fragment carries the call's ID and name; later fragments extend the
// arguments string.
type toolCallAccumulator struct {
	order []int64
	calls map[int64]*ToolCall
}

func newToolCallAccumulator() *toolCallAccumulator {
	return &toolCallAccumulator{calls: make(map[int64]*ToolCall)}
}

func (a *toolCallAccumulator) add(frag openai.ChatCompletionChunkChoiceDeltaToolCall) {
	call, ok := a.calls[frag.Index]
	if !ok {
		call = &ToolCall{}
		a.calls[frag.Index] = call
		a.order = append(a.order, frag.Index)
	}
	if frag.ID != "" {
		call.ID = frag.ID
	}
	if frag.Function.Name != "" {
		call.Name = frag.Function.Name
	}
	call.Arguments += frag.Function.Arguments
}

// flush returns the assembled calls in stream order and clears the
// accumulator.
func (a *toolCallAccumulator) flush() []ToolCall {
	if len(a.order) == 0 {
		return nil
	}
	calls := make([]ToolCall, 0, len(a.order))
	for _, idx := range a.order {
		calls = append(calls, *a.calls[idx])
	}
	a.order = nil
	a.calls = make(map[int64]*ToolCall)
	return calls
}

// retryPolicy is the §3.3 retry behavior: jittered exponential backoff, a
// fixed attempt ceiling, and injectable seams for tests.
type retryPolicy struct {
	maxAttempts int
	backoff     func(attempt int) time.Duration
	sleep       func(context.Context, time.Duration) error
}

// jitteredExponential is exponential backoff with full jitter: attempt n waits
// a random duration in [0, base*2^(n-1)), capped. Full jitter is what keeps
// concurrent clients from retrying in lockstep.
func jitteredExponential(attempt int) time.Duration {
	const (
		base       = 500 * time.Millisecond
		maxBackoff = 8 * time.Second
	)
	d := base << (attempt - 1)
	if d > maxBackoff || d <= 0 {
		d = maxBackoff
	}
	//nolint:gosec // backoff jitter is scheduling, not a security decision.
	return time.Duration(rand.Int64N(int64(d) + 1))
}

// sleepCtx waits for a duration or the context, whichever comes first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryable reports whether a failed attempt is worth retrying: 429, any 5xx,
// and transport failures. Other 4xx are deterministic and fail fast.
func retryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var apiErr *openai.Error
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500
	}
	return true
}
