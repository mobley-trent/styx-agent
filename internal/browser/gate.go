package browser

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// gateTimeout bounds one gate admission: the client's token line, the token
// comparison, and the dial to the browser's own loopback port.
const gateTimeout = 10 * time.Second

// gate is the CDP admission point (§3.1). Chromium listens on a random loopback
// port that is never placed on its command line; the harness dials this
// listener instead, proves it knows the per-launch token, and the gate splices
// the connection through. The port is bound to 127.0.0.1 and the token is
// generated per launch, so a local process that has not been handed the token
// cannot attach to the session's CDP.
type gate struct {
	ln    net.Listener
	token string

	mu     sync.Mutex
	target string
	closed bool

	done chan struct{}
	wg   sync.WaitGroup
}

// newGate binds the gate on an ephemeral loopback port and mints its token. The
// target is set once the browser reports its own port.
func newGate() (*gate, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("browser: bind the CDP gate: %w", err)
	}
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("browser: mint the CDP token: %w", err)
	}
	g := &gate{ln: ln, token: hex.EncodeToString(buf[:]), done: make(chan struct{})}
	g.wg.Add(1)
	go g.serve()
	return g, nil
}

// Addr is the gate's loopback address.
func (g *gate) Addr() string { return g.ln.Addr().String() }

// Token is the per-launch admission secret. It never leaves the harness.
func (g *gate) Token() string { return g.token }

// SetTarget points the gate at the browser's own CDP listener.
func (g *gate) SetTarget(addr string) {
	g.mu.Lock()
	g.target = addr
	g.mu.Unlock()
}

// serve accepts admissions until the gate closes.
func (g *gate) serve() {
	defer g.wg.Done()
	for {
		conn, err := g.ln.Accept()
		if err != nil {
			select {
			case <-g.done:
				return
			default:
			}
			continue
		}
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			g.admit(conn)
		}()
	}
}

// admit validates one connection's token and splices it to the browser.
func (g *gate) admit(client net.Conn) {
	defer func() { _ = client.Close() }()

	if err := client.SetDeadline(time.Now().Add(gateTimeout)); err != nil {
		return
	}
	// The token is the first line the client writes, before the WebSocket
	// handshake. Read it byte-wise so no handshake bytes are consumed: a
	// buffered reader could pull the GET in with the token.
	token, err := readLine(client, 256)
	if err != nil {
		return
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(g.token)) != 1 {
		return
	}

	g.mu.Lock()
	target := g.target
	g.mu.Unlock()
	if target == "" {
		return
	}

	upstream, err := net.DialTimeout("tcp", target, gateTimeout)
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()
	if err := client.SetDeadline(time.Time{}); err != nil {
		return
	}
	if err := upstream.SetDeadline(time.Time{}); err != nil {
		return
	}

	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = client.Close()
			_ = upstream.Close()
		})
	}
	var copies sync.WaitGroup
	copies.Add(2)
	go func() {
		defer copies.Done()
		_, _ = io.Copy(upstream, client)
		closeBoth()
	}()
	go func() {
		defer copies.Done()
		_, _ = io.Copy(client, upstream)
		closeBoth()
	}()
	copies.Wait()
}

// readLine reads one newline-terminated line without reading past it.
func readLine(conn net.Conn, limit int) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for len(line) < limit {
		n, err := conn.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return string(line), nil
			}
			line = append(line, buf[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return "", io.ErrUnexpectedEOF
			}
			return "", err
		}
	}
	return "", errors.New("browser: the CDP gate read an overlong admission line")
}

// Close stops the listener and waits for in-flight admissions.
func (g *gate) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	g.mu.Unlock()

	close(g.done)
	err := g.ln.Close()
	g.wg.Wait()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// lockRecord is the profile lockfile's content, the same shape the state store
// writes (docs/engagement-state.md §1): who holds the profile, and when.
type lockRecord struct {
	PID     int       `json:"pid"`
	Session string    `json:"session,omitempty"`
	At      time.Time `json:"at"`
}

// encodeLock renders a lock record.
func encodeLock(record lockRecord) ([]byte, error) {
	return json.Marshal(record)
}
