package browser

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6455 mandates SHA-1 for the handshake accept key.
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RFC 6455 constants. The harness needs text frames and nothing else: CDP is
// JSON text, fragment reassembly, and ping/pong.
const (
	wsGUID           = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsHandshakeLimit = 32 << 10
	maxWSMessage     = 64 << 20

	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xa
)

// wsConn is a minimal WebSocket client. It deliberately sends no Origin
// header: Chromium's DevTools endpoint refuses a WebSocket that presents one it
// was not told to allow, and the harness has no reason to present an origin at
// all — admission is the gate's per-launch token.
type wsConn struct {
	conn  net.Conn
	read  *bufio.Reader
	write sync.Mutex
	once  sync.Once
}

// upgradeWS performs the client handshake over an admitted connection and
// verifies the server's accept key.
func upgradeWS(ctx context.Context, conn net.Conn, location *url.URL) (*wsConn, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("%w: mint the WebSocket key: %w", ErrTransport, err)
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		location.RequestURI(), location.Host, key)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	} else {
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	}
	if _, err := io.WriteString(conn, request); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: CDP handshake write: %w", ErrTransport, err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReaderSize(conn, 4096)
	status, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: CDP handshake read: %w", ErrTransport, err)
	}
	if !strings.Contains(status, " 101 ") {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: CDP handshake refused: %s", ErrTransport, strings.TrimSpace(status))
	}
	headers := map[string]string{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: CDP handshake headers: %w", ErrTransport, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if len(headers) > 200 {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: CDP handshake sent too many headers", ErrTransport)
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		headers[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
	}
	_ = conn.SetReadDeadline(time.Time{})

	sum := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec // RFC 6455 mandates SHA-1 here.
	want := base64.StdEncoding.EncodeToString(sum[:])
	if headers["sec-websocket-accept"] != want {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: CDP handshake accept key mismatch", ErrTransport)
	}
	return &wsConn{conn: conn, read: reader}, nil
}

// ReadText returns the next complete text message, answering ping frames and
// treating close as end of stream.
func (c *wsConn) ReadText() ([]byte, error) {
	var message []byte
	for {
		fin, opcode, payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		switch opcode {
		case wsOpClose:
			return nil, io.EOF
		case wsOpPing:
			if err := c.writeFrame(wsOpPong, payload); err != nil {
				return nil, err
			}
			continue
		case wsOpPong:
			continue
		case wsOpText, wsOpBinary, wsOpContinuation:
			message = append(message, payload...)
			if len(message) > maxWSMessage {
				return nil, fmt.Errorf("browser: CDP message exceeds %d bytes", maxWSMessage)
			}
		default:
			return nil, fmt.Errorf("browser: unsupported WebSocket opcode %d", opcode)
		}
		if fin {
			return message, nil
		}
	}
}

// readFrame reads one frame, unmasking it when the server masked it.
func (c *wsConn) readFrame() (bool, byte, []byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(c.read, head[:]); err != nil {
		return false, 0, nil, err
	}
	fin := head[0]&0x80 != 0
	if head[0]&0x70 != 0 {
		return false, 0, nil, errors.New("browser: CDP set unsupported WebSocket extension bits")
	}
	opcode := head[0] & 0x0f
	masked := head[1]&0x80 != 0
	length := int64(head[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(c.read, extended[:]); err != nil {
			return false, 0, nil, err
		}
		length = int64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(c.read, extended[:]); err != nil {
			return false, 0, nil, err
		}
		unsigned := binary.BigEndian.Uint64(extended[:])
		if unsigned > maxWSMessage {
			return false, 0, nil, fmt.Errorf("browser: CDP frame exceeds %d bytes", maxWSMessage)
		}
		length = int64(unsigned)
	}
	if length > maxWSMessage {
		return false, 0, nil, fmt.Errorf("browser: CDP frame exceeds %d bytes", maxWSMessage)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.read, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.read, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, opcode, payload, nil
}

// WriteText sends one masked text message.
func (c *wsConn) WriteText(payload []byte) error { return c.writeFrame(wsOpText, payload) }

// writeFrame sends one masked, unfragmented frame.
func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.write.Lock()
	defer c.write.Unlock()

	header := make([]byte, 0, 14)
	header = append(header, 0x80|opcode)
	switch n := len(payload); {
	case n < 126:
		header = append(header, 0x80|byte(n)) //nolint:gosec // n < 126 here.
	case n <= 65535:
		header = append(header, 0x80|126, byte(n>>8), byte(n)) //nolint:gosec // n <= 65535 here.
	default:
		header = append(header, 0x80|127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n)) //nolint:gosec // n is bounded by maxWSMessage.
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	header = append(header, mask[:]...)

	frame := make([]byte, len(header)+len(payload))
	copy(frame, header)
	for i, b := range payload {
		frame[len(header)+i] = b ^ mask[i%4]
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := c.conn.Write(frame)
	_ = c.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	return nil
}

// Close closes the underlying connection.
func (c *wsConn) Close() error {
	var err error
	c.once.Do(func() { err = c.conn.Close() })
	return err
}
