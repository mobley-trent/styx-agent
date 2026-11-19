package browser

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loginNodes is the canned page the fake browser exposes.
func loginNodes() []any {
	return []any{
		map[string]any{"parent": -1, "role": "heading", "name": "Welcome", "level": 1},
		map[string]any{"parent": -1, "role": "link", "name": "Home", "interactive": true, "index": 0},
		map[string]any{"parent": -1, "role": "textbox", "name": "Email", "interactive": true, "index": 1},
		map[string]any{"parent": -1, "role": "button", "name": "Sign In", "interactive": true, "index": 2},
	}
}

// attachedPage attaches a Page over a fake connection.
func attachedPage(t *testing.T, conn *fakeConn) *Page {
	t.Helper()
	page, err := Attach(context.Background(), conn)
	if err != nil {
		t.Fatalf("Attach() = %v", err)
	}
	return page
}

func TestPageReadMintsHandlesThatClickUses(t *testing.T) {
	conn := pageConn(t, map[string]any{"url": "http://10.0.0.5/login", "title": "Sign in", "nodes": loginNodes()})
	page := attachedPage(t, conn)

	text, err := page.Read(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("Read() = %v", err)
	}
	for _, want := range []string{`[1] link "Home"`, `[2] textbox "Email"`, `[3] button "Sign In"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("Read() = %q, want %q", text, want)
		}
	}

	state, err := page.Click(context.Background(), "1")
	if err != nil {
		t.Fatalf("Click(1) = %v", err)
	}
	if state.URL != "http://10.0.0.5/login" {
		t.Errorf("Click(1) state = %+v", state)
	}
	var clicked string
	for _, expression := range conn.expressions() {
		if strings.Contains(expression, "styx:action") {
			clicked = expression
		}
	}
	if !strings.Contains(clicked, `data-styx-index="0"`) {
		t.Errorf("the link's click used %q, want the snapshot's marker for the first interactive node", clicked)
	}
}

func TestPageReadsOneElementSubtree(t *testing.T) {
	conn := pageConn(t, map[string]any{"url": "http://10.0.0.5/", "nodes": loginNodes()})
	page := attachedPage(t, conn)
	if _, err := page.Read(context.Background(), "", 0); err != nil {
		t.Fatalf("Read() = %v", err)
	}
	text, err := page.Read(context.Background(), "2", 0)
	if err != nil {
		t.Fatalf("Read(2) = %v", err)
	}
	if !strings.HasPrefix(text, `[2] textbox "Email"`) {
		t.Errorf("Read(2) = %q, want the textbox subtree", text)
	}
}

func TestPageRefusesAnUnknownHandle(t *testing.T) {
	conn := pageConn(t, map[string]any{"url": "http://10.0.0.5/", "nodes": loginNodes()})
	page := attachedPage(t, conn)
	if _, err := page.Read(context.Background(), "", 0); err != nil {
		t.Fatalf("Read() = %v", err)
	}
	_, err := page.Click(context.Background(), "9")
	if !errors.Is(err, ErrStaleHandle) {
		t.Fatalf("Click(9) = %v, want ErrStaleHandle", err)
	}
	if !strings.Contains(err.Error(), "take a fresh snapshot") {
		t.Errorf("error = %v, want the fresh-snapshot instruction", err)
	}
}

func TestPageRefusesAStaleElement(t *testing.T) {
	conn := pageConn(t, map[string]any{"url": "http://10.0.0.5/", "nodes": loginNodes()})
	conn.onPage(func(method string, params map[string]any) (any, error) {
		if method != "Runtime.evaluate" {
			return nil, nil
		}
		expression, _ := params["expression"].(string)
		switch {
		case strings.Contains(expression, "styx:action"):
			return map[string]any{"result": map[string]any{"value": `{"ok":false,"missing":true}`}}, nil
		case strings.Contains(expression, "styx:state"):
			return map[string]any{"result": map[string]any{"value": `{"url":"http://10.0.0.5/","title":"","width":1280,"height":900}`}}, nil
		default:
			return map[string]any{"result": map[string]any{"value": mustJSON(t, map[string]any{
				"url": "http://10.0.0.5/", "nodes": loginNodes(),
			})}}, nil
		}
	})
	page := attachedPage(t, conn)
	if _, err := page.Read(context.Background(), "", 0); err != nil {
		t.Fatalf("Read() = %v", err)
	}
	_, err := page.Click(context.Background(), "1")
	if !errors.Is(err, ErrStaleHandle) {
		t.Fatalf("Click() after the element vanished = %v, want ErrStaleHandle", err)
	}
}

func TestPageTypesWithoutEchoingTheText(t *testing.T) {
	conn := pageConn(t, map[string]any{"url": "http://10.0.0.5/", "nodes": loginNodes()})
	page := attachedPage(t, conn)
	if _, err := page.Read(context.Background(), "", 0); err != nil {
		t.Fatalf("Read() = %v", err)
	}
	state, err := page.TypeText(context.Background(), "2", "hunter2", false)
	if err != nil {
		t.Fatalf("TypeText() = %v", err)
	}
	if strings.Contains(state.URL+state.Title, "hunter2") {
		t.Errorf("TypeText() state = %+v carries the typed text", state)
	}
	typed := false
	for _, call := range conn.calls {
		if call.Method == "Input.insertText" && call.Params["text"] == "hunter2" {
			typed = true
		}
	}
	if !typed {
		t.Error("TypeText() never inserted the text")
	}
}

func TestPageScreenshotWritesAnArtifact(t *testing.T) {
	conn := pageConn(t, map[string]any{"url": "http://10.0.0.5/", "title": "Sign in", "nodes": loginNodes()})
	page := attachedPage(t, conn)
	path := filepath.Join(t.TempDir(), "shot-1.png")

	artifact, err := page.Screenshot(context.Background(), path, false)
	if err != nil {
		t.Fatalf("Screenshot() = %v", err)
	}
	if artifact.Path != path || artifact.Bytes <= 0 {
		t.Errorf("Screenshot() = %+v, want the written path and size", artifact)
	}
	if artifact.URL != "http://10.0.0.5/" || artifact.Title != "Sign in" {
		t.Errorf("Screenshot() metadata = %+v", artifact)
	}
	if artifact.Width != 1280 || artifact.Height != 900 {
		t.Errorf("Screenshot() viewport = %dx%d, want 1280x900", artifact.Width, artifact.Height)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the screenshot was announced but not written: %v", err)
	}
	if strings.Contains(artifact.Path, "data:") {
		t.Error("Screenshot() returned inline data")
	}
}

// downloadConn answers the page protocol and starts one events-enabled
// download, Chromium-style, named after its GUID.
func downloadConn(t *testing.T, dir, guid, suggested, state string, body []byte) *fakeConn {
	t.Helper()
	conn := pageConn(t, map[string]any{"url": "http://10.0.0.5/", "nodes": loginNodes()})
	conn.onPage(func(method string, params map[string]any) (any, error) {
		if method != "Runtime.evaluate" {
			return nil, nil
		}
		expression, _ := params["expression"].(string)
		switch {
		case strings.Contains(expression, "styx:action"):
			if err := os.WriteFile(filepath.Join(dir, guid), body, 0o600); err != nil {
				t.Errorf("write download: %v", err)
			}
			conn.emit("Browser.downloadWillBegin", map[string]any{
				"guid": guid, "suggestedFilename": suggested, "url": "http://10.0.0.5/export",
			})
			conn.emit("Browser.downloadProgress", map[string]any{"guid": guid, "state": state})
			return map[string]any{"result": map[string]any{"value": `{"ok":true}`}}, nil
		case strings.Contains(expression, "styx:state"):
			return map[string]any{"result": map[string]any{"value": `{"url":"http://10.0.0.5/","title":"","width":1280,"height":900}`}}, nil
		default:
			return map[string]any{"result": map[string]any{"value": mustJSON(t, map[string]any{
				"url": "http://10.0.0.5/", "nodes": loginNodes(),
			})}}, nil
		}
	})
	return conn
}

func TestPageDownloadSanitizesTheServerName(t *testing.T) {
	dir := t.TempDir()
	conn := downloadConn(t, dir, "guid-1", "../../etc/passwd", "completed", []byte("report body"))
	page := attachedPage(t, conn)
	if _, err := page.Read(context.Background(), "", 0); err != nil {
		t.Fatalf("Read() = %v", err)
	}

	artifact, err := page.Download(context.Background(), "3", dir)
	if err != nil {
		t.Fatalf("Download() = %v", err)
	}
	if artifact.Filename != "passwd" {
		t.Errorf("Filename = %q, want the sanitized basename", artifact.Filename)
	}
	if filepath.Dir(artifact.Path) != dir {
		t.Errorf("Path = %q, want it inside the download directory", artifact.Path)
	}
	if artifact.Bytes != int64(len("report body")) {
		t.Errorf("Bytes = %d, want the saved size", artifact.Bytes)
	}
	if artifact.ContentType == "" {
		t.Error("ContentType is empty")
	}
	if _, err := os.Stat(filepath.Join(dir, "guid-1")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the GUID-named download was not renamed: %v", err)
	}
	for _, call := range conn.calls {
		if call.Method == "Browser.setDownloadBehavior" && call.Session != "" {
			t.Errorf("download behavior was set on a page session %q, want the browser session", call.Session)
		}
	}
}

func TestPageDownloadRefusesCancellation(t *testing.T) {
	dir := t.TempDir()
	conn := downloadConn(t, dir, "guid-2", "x.bin", "canceled", nil)
	page := attachedPage(t, conn)
	if _, err := page.Read(context.Background(), "", 0); err != nil {
		t.Fatalf("Read() = %v", err)
	}
	if _, err := page.Download(context.Background(), "3", dir); err == nil {
		t.Fatal("Download() announced a cancelled download")
	}
}

func TestPageNavigateWaitsForLoad(t *testing.T) {
	conn := pageConn(t, map[string]any{"url": "http://10.0.0.5/home", "title": "Home", "nodes": loginNodes()})
	page := attachedPage(t, conn)
	state, err := page.Navigate(context.Background(), "http://10.0.0.5/home")
	if err != nil {
		t.Fatalf("Navigate() = %v", err)
	}
	if state.URL != "http://10.0.0.5/home" || state.Title != "Home" {
		t.Errorf("Navigate() = %+v", state)
	}
}

func TestPageNavigateRefusesABadURL(t *testing.T) {
	page := attachedPage(t, pageConn(t, map[string]any{"url": "http://10.0.0.5/"}))
	for _, raw := range []string{"file:///etc/passwd", "javascript:alert(1)", "not a url", "http://"} {
		if _, err := page.Navigate(context.Background(), raw); err == nil {
			t.Errorf("Navigate(%q) accepted it", raw)
		}
	}
}

func TestPageNeverReadsCookieOrStorageValues(t *testing.T) {
	dir := t.TempDir()
	conn := downloadConn(t, dir, "guid-3", "report.txt", "completed", []byte("body"))
	page := attachedPage(t, conn)
	ctx := context.Background()
	if _, err := page.Read(ctx, "", 0); err != nil {
		t.Fatalf("Read() = %v", err)
	}
	if _, err := page.Click(ctx, "1"); err != nil {
		t.Fatalf("Click() = %v", err)
	}
	if _, err := page.TypeText(ctx, "2", "secret-value", false); err != nil {
		t.Fatalf("TypeText() = %v", err)
	}
	if _, err := page.Screenshot(ctx, filepath.Join(t.TempDir(), "shot.png"), false); err != nil {
		t.Fatalf("Screenshot() = %v", err)
	}
	if _, err := page.Download(ctx, "3", dir); err != nil {
		t.Fatalf("Download() = %v", err)
	}
	conn.mustNotMention(t)
}
