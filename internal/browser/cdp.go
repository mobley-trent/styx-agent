package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"
)

// Conn is the CDP seam: a request/response connection that also delivers
// browser events. The production implementation speaks WebSocket to Chromium
// through the gate; tests substitute a recording fake, which is how the driver's
// method vocabulary and results are pinned without a browser.
type Conn interface {
	// Call sends one CDP command and decodes its result into out (when
	// non-nil). session is the flattened target session, empty for
	// browser-level commands.
	Call(ctx context.Context, session, method string, params any, out any) error
	// Subscribe delivers events for one method. The returned cancel function
	// stops delivery and is safe to call more than once.
	Subscribe(method string) (<-chan json.RawMessage, func())
	// Close tears the connection down.
	Close() error
}

// Dialer opens a CDP connection. It is the transport seam.
type Dialer interface {
	// Dial connects to a gate URL. The URL's query carries the per-launch
	// token; the query is stripped before the WebSocket handshake.
	Dial(ctx context.Context, wsURL string) (Conn, error)
}

// wsDialer is the production Dialer.
type wsDialer struct{}

// Dial opens the token-gated WebSocket. The gate consumes the token line, then
// splices the handshake to the browser's own loopback listener.
func (wsDialer) Dial(ctx context.Context, wsURL string) (Conn, error) {
	parsed, err := url.Parse(wsURL)
	if err != nil {
		return nil, fmt.Errorf("%w: parse the CDP URL %q: %w", ErrTransport, wsURL, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: parse the CDP URL %q: no host", ErrTransport, wsURL)
	}
	token := parsed.Query().Get("token")
	parsed.RawQuery = ""

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", parsed.Host)
	if err != nil {
		return nil, fmt.Errorf("%w: dial the CDP gate: %w", ErrTransport, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetWriteDeadline(deadline)
	} else {
		_ = raw.SetWriteDeadline(time.Now().Add(10 * time.Second))
	}
	if _, err := fmt.Fprintf(raw, "%s\n", token); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("%w: admit to the CDP gate: %w", ErrTransport, err)
	}
	_ = raw.SetWriteDeadline(time.Time{})

	ws, err := upgradeWS(ctx, raw, parsed)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return newCDPConn(ws), nil
}

// cdpMessage is one CDP frame: either a response (ID set) or an event (Method
// set).
type cdpMessage struct {
	ID        int             `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *cdpError       `json:"error,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
}

// cdpError is a protocol-level refusal from Chromium, distinct from a broken
// transport.
type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// cdpConn is the WebSocket connection: one reader dispatches responses to
// waiting calls and events to subscribers.
type cdpConn struct {
	ws     *wsConn
	write  sync.Mutex
	mu     sync.Mutex
	next   int
	closed bool
	fault  error
	done   chan struct{}

	waiting map[int]chan cdpMessage
	subs    map[string]map[int]chan json.RawMessage
	nextSub int
}

// newCDPConn starts the reader for a connected WebSocket.
func newCDPConn(ws *wsConn) *cdpConn {
	c := &cdpConn{
		ws:      ws,
		done:    make(chan struct{}),
		waiting: map[int]chan cdpMessage{},
		subs:    map[string]map[int]chan json.RawMessage{},
	}
	go c.read()
	return c
}

// read dispatches every frame until the socket fails.
func (c *cdpConn) read() {
	for {
		data, err := c.ws.ReadText()
		if err != nil {
			c.fail(err)
			return
		}
		var msg cdpMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			// A frame the harness cannot parse is a transport fault: continuing
			// would leave a call waiting forever for a response we damaged.
			c.fail(err)
			return
		}
		if msg.ID != 0 {
			c.mu.Lock()
			ch := c.waiting[msg.ID]
			delete(c.waiting, msg.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- msg
			}
			continue
		}
		if msg.Method == "" {
			continue
		}
		c.mu.Lock()
		for _, ch := range c.subs[msg.Method] {
			select {
			case ch <- msg.Params:
			default:
				// A subscriber that is not reading loses this event; downloads
				// subscribe before the click that starts them, so the event
				// they need is never dropped for lack of a reader.
			}
		}
		c.mu.Unlock()
	}
}

// fail closes the connection state and wakes every waiter.
func (c *cdpConn) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.fault = err
	close(c.done)
	for id, ch := range c.waiting {
		close(ch)
		delete(c.waiting, id)
	}
	c.mu.Unlock()
	_ = c.ws.Close()
}

// Call implements Conn.
func (c *cdpConn) Call(ctx context.Context, session, method string, params any, out any) error {
	c.mu.Lock()
	if c.closed {
		err := c.fault
		c.mu.Unlock()
		if err == nil {
			err = errors.New("connection closed")
		}
		return fmt.Errorf("%w: %w", ErrTransport, err)
	}
	c.next++
	id := c.next
	ch := make(chan cdpMessage, 1)
	c.waiting[id] = ch
	c.mu.Unlock()

	request := struct {
		ID        int    `json:"id"`
		Method    string `json:"method"`
		Params    any    `json:"params,omitempty"`
		SessionID string `json:"sessionId,omitempty"`
	}{ID: id, Method: method, Params: params, SessionID: session}
	encoded, err := json.Marshal(request)
	if err != nil {
		c.mu.Lock()
		delete(c.waiting, id)
		c.mu.Unlock()
		return fmt.Errorf("browser: encode %s: %w", method, err)
	}

	c.write.Lock()
	err = c.ws.WriteText(encoded)
	c.write.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.waiting, id)
		c.mu.Unlock()
		return fmt.Errorf("%w: send %s: %w", ErrTransport, method, err)
	}

	select {
	case reply, ok := <-ch:
		if !ok {
			c.mu.Lock()
			fault := c.fault
			c.mu.Unlock()
			if fault == nil {
				fault = errors.New("connection closed")
			}
			return fmt.Errorf("%w: %s: %w", ErrTransport, method, fault)
		}
		if reply.Error != nil {
			detail := reply.Error.Message
			if reply.Error.Data != "" {
				detail += ": " + reply.Error.Data
			}
			return fmt.Errorf("browser: %s: %s", method, detail)
		}
		if out != nil && len(reply.Result) > 0 {
			if err := json.Unmarshal(reply.Result, out); err != nil {
				return fmt.Errorf("browser: decode %s result: %w", method, err)
			}
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.waiting, id)
		c.mu.Unlock()
		return fmt.Errorf("%w: %s: %w", ErrTransport, method, ctx.Err())
	}
}

// Subscribe implements Conn.
func (c *cdpConn) Subscribe(method string) (<-chan json.RawMessage, func()) {
	ch := make(chan json.RawMessage, 16)
	c.mu.Lock()
	c.nextSub++
	id := c.nextSub
	if c.subs[method] == nil {
		c.subs[method] = map[int]chan json.RawMessage{}
	}
	c.subs[method][id] = ch
	c.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			c.mu.Lock()
			if group, ok := c.subs[method]; ok {
				delete(group, id)
				if len(group) == 0 {
					delete(c.subs, method)
				}
			}
			c.mu.Unlock()
		})
	}
	return ch, cancel
}

// Close implements Conn.
func (c *cdpConn) Close() error {
	c.fail(errors.New("connection closed by the harness"))
	return nil
}
