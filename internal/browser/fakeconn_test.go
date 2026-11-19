package browser

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// fakeCall is one recorded CDP command.
type fakeCall struct {
	Session string
	Method  string
	Params  map[string]any
}

// fakeConn is a recording CDP connection: it answers from a reply function and
// never touches a browser. It is what lets the page and manager tests pin the
// driver's method vocabulary, handle behavior, and artifacts hermetically.
type fakeConn struct {
	mu    sync.Mutex
	calls []fakeCall
	subs  map[string]map[int]chan json.RawMessage
	next  int
	reply func(method string, params map[string]any) (any, error)
	close func()
}

func newFakeConn() *fakeConn {
	return &fakeConn{subs: map[string]map[int]chan json.RawMessage{}}
}

// Call implements Conn.
func (c *fakeConn) Call(ctx context.Context, session, method string, params any, out any) error {
	parsed, _ := params.(map[string]any)
	c.mu.Lock()
	c.calls = append(c.calls, fakeCall{Session: session, Method: method, Params: parsed})
	reply := c.reply
	c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if reply == nil {
		return nil
	}
	result, err := reply(method, parsed)
	if err != nil {
		return err
	}
	if out != nil && result != nil {
		data, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			return marshalErr
		}
		return json.Unmarshal(data, out)
	}
	return nil
}

// Subscribe implements Conn.
func (c *fakeConn) Subscribe(method string) (<-chan json.RawMessage, func()) {
	ch := make(chan json.RawMessage, 16)
	c.mu.Lock()
	c.next++
	id := c.next
	if c.subs[method] == nil {
		c.subs[method] = map[int]chan json.RawMessage{}
	}
	c.subs[method][id] = ch
	c.mu.Unlock()
	return ch, func() {
		c.mu.Lock()
		if group, ok := c.subs[method]; ok {
			delete(group, id)
		}
		c.mu.Unlock()
	}
}

// Close implements Conn.
func (c *fakeConn) Close() error {
	c.mu.Lock()
	closeFn := c.close
	c.close = nil
	c.mu.Unlock()
	if closeFn != nil {
		closeFn()
	}
	return nil
}

// emit delivers an event to every subscriber of a method.
func (c *fakeConn) emit(method string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ch := range c.subs[method] {
		select {
		case ch <- data:
		default:
		}
		_ = id
	}
}

// methods returns every command method the driver issued, in order.
func (c *fakeConn) methods() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.calls))
	for _, call := range c.calls {
		out = append(out, call.Method)
	}
	return out
}

// expressions returns every page-side expression the driver evaluated.
func (c *fakeConn) expressions() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, call := range c.calls {
		if call.Method != "Runtime.evaluate" {
			continue
		}
		if expression, ok := call.Params["expression"].(string); ok {
			out = append(out, expression)
		}
	}
	return out
}

// mustNotMention fails when any recorded method or expression names a
// credential surface the browser must never read (§3.6).
func (c *fakeConn) mustNotMention(t *testing.T) {
	t.Helper()
	forbidden := []string{
		"Network.getCookies", "Network.getAllCookies", "Storage.getCookies",
		"Storage.getStorageKeyForFrame", "DOMStorage",
		"document.cookie", "localStorage", "sessionStorage", "indexedDB",
	}
	for _, method := range c.methods() {
		for _, banned := range forbidden {
			if strings.Contains(method, banned) {
				t.Errorf("the driver issued %q; no tool may read cookie or storage values", method)
			}
		}
	}
	for _, expression := range c.expressions() {
		for _, banned := range forbidden {
			if strings.Contains(expression, banned) {
				t.Errorf("the driver evaluated an expression naming %q; reads are DOM text, never storage values", banned)
			}
		}
	}
}

// onPage installs a page-protocol base over a custom reply: attach and target
// discovery always work, so a test only writes the commands it cares about.
func (c *fakeConn) onPage(reply func(method string, params map[string]any) (any, error)) {
	c.reply = func(method string, params map[string]any) (any, error) {
		switch method {
		case "Target.getTargets":
			return map[string]any{"targetInfos": []any{map[string]any{"targetId": "page-1", "type": "page"}}}, nil
		case "Target.attachToTarget":
			return map[string]any{"sessionId": "session-1"}, nil
		case "Page.enable", "Runtime.enable", "Emulation.setDeviceMetricsOverride":
			return nil, nil
		}
		return reply(method, params)
	}
}

// pageConn builds a fake connection that answers the page protocol with one
// canned snapshot. page carries the URL, title, and nodes a read reports.
func pageConn(t *testing.T, page map[string]any) *fakeConn {
	t.Helper()
	conn := newFakeConn()
	conn.onPage(func(method string, params map[string]any) (any, error) {
		switch method {
		case "Runtime.evaluate":
			expression, _ := params["expression"].(string)
			switch {
			case strings.Contains(expression, "styx:state"):
				return map[string]any{"result": map[string]any{"value": mustJSON(t, map[string]any{
					"url": page["url"], "title": page["title"], "width": 1280, "height": 900,
				})}}, nil
			case strings.Contains(expression, "styx:action"):
				conn.emit("Page.loadEventFired", map[string]any{"timestamp": 1})
				return map[string]any{"result": map[string]any{"value": `{"ok":true}`}}, nil
			case strings.Contains(expression, "styx:read"):
				return map[string]any{"result": map[string]any{"value": mustJSON(t, map[string]any{
					"url": page["url"], "title": page["title"], "nodes": page["nodes"],
				})}}, nil
			default:
				return map[string]any{"result": map[string]any{"value": `{}`}}, nil
			}
		case "Page.navigate":
			conn.emit("Page.loadEventFired", map[string]any{"timestamp": 1})
			return map[string]any{"frameId": "frame-1"}, nil
		case "Page.captureScreenshot":
			return map[string]any{"data": "iVBORw0KGgo="}, nil
		}
		return nil, nil
	})
	return conn
}

// mustJSON renders a value as JSON text.
func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(data)
}
