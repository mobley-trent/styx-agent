package browser

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// echoServer accepts connections and echoes what it reads.
func echoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func TestGateSplicesAfterTheToken(t *testing.T) {
	target, stop := echoServer(t)
	defer stop()

	g, err := newGate()
	if err != nil {
		t.Fatalf("newGate() = %v", err)
	}
	defer func() { _ = g.Close() }()
	g.SetTarget(target)

	conn, err := net.DialTimeout("tcp", g.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial gate: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, g.Token()+"\nhello-cdp\n"); err != nil {
		t.Fatalf("admit: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, len("hello-cdp\n"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read spliced bytes: %v", err)
	}
	if string(buf) != "hello-cdp\n" {
		t.Errorf("echoed %q, want the bytes after the token line", buf)
	}
	if g.Token() == "" || strings.Contains(g.Token(), "\n") {
		t.Errorf("token %q is not a single line", g.Token())
	}
}

func TestGateRefusesAWrongToken(t *testing.T) {
	target, stop := echoServer(t)
	defer stop()

	g, err := newGate()
	if err != nil {
		t.Fatalf("newGate() = %v", err)
	}
	defer func() { _ = g.Close() }()
	g.SetTarget(target)

	conn, err := net.DialTimeout("tcp", g.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial gate: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "wrong-token\nhello\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 8)
	if n, err := conn.Read(buf); err == nil || n > 0 {
		t.Errorf("the gate forwarded %q for a wrong token", buf[:n])
	}
}

func TestGateRefusesBeforeATarget(t *testing.T) {
	g, err := newGate()
	if err != nil {
		t.Fatalf("newGate() = %v", err)
	}
	defer func() { _ = g.Close() }()

	conn, err := net.DialTimeout("tcp", g.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial gate: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, g.Token()+"\nhello\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 8)
	if n, err := conn.Read(buf); err == nil || n > 0 {
		t.Errorf("the gate forwarded %q before a target was set", buf[:n])
	}
}
