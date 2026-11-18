package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Page timing. A navigation that never completes is a visible tool error; an
// action that does not navigate returns as soon as the page settles.
const (
	// navigationTimeout bounds one page load.
	navigationTimeout = 30 * time.Second
	// clickSettle waits briefly for a click's navigation to begin, so the
	// returned URL is the new page rather than the one being left.
	clickSettle = 750 * time.Millisecond
	// downloadTimeout bounds the wait for a started download to complete.
	downloadTimeout = 60 * time.Second
	// downloadStartTimeout bounds the wait for a click to start a download.
	downloadStartTimeout = 15 * time.Second
	// evaluateTimeout bounds one page-side expression.
	evaluateTimeout = 20 * time.Second
)

// State is the page's address and viewport after an action.
type State struct {
	URL    string `json:"url"`
	Title  string `json:"title"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

// Page is one active page driven over CDP. It carries only the current
// snapshot's handles, so an action can address exactly what the last read
// showed (§3.2).
type Page struct {
	conn    Conn
	session string
	current *snapshot
}

// Attach connects CDP to the browser's single active page (§7), enabling the
// domains the driver uses and pinning the viewport.
func Attach(ctx context.Context, conn Conn) (*Page, error) {
	var targets struct {
		TargetInfos []struct {
			TargetID string `json:"targetId"`
			Type     string `json:"type"`
		} `json:"targetInfos"`
	}
	if err := conn.Call(ctx, "", "Target.getTargets", map[string]any{}, &targets); err != nil {
		return nil, err
	}
	targetID := ""
	for _, target := range targets.TargetInfos {
		if target.Type == "page" {
			targetID = target.TargetID
			break
		}
	}
	if targetID == "" {
		var created struct {
			TargetID string `json:"targetId"`
		}
		if err := conn.Call(ctx, "", "Target.createTarget", map[string]any{"url": "about:blank"}, &created); err != nil {
			return nil, err
		}
		targetID = created.TargetID
	}

	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := conn.Call(ctx, "", "Target.attachToTarget", map[string]any{
		"targetId": targetID,
		"flatten":  true,
	}, &attached); err != nil {
		return nil, err
	}
	if attached.SessionID == "" {
		return nil, fmt.Errorf("%w: Chromium attached no flattened session to %s", ErrTransport, targetID)
	}

	p := &Page{conn: conn, session: attached.SessionID}
	for _, setup := range []struct {
		method string
		params any
	}{
		{"Page.enable", map[string]any{}},
		{"Runtime.enable", map[string]any{}},
		{"Emulation.setDeviceMetricsOverride", map[string]any{
			"width": 1280, "height": 900, "deviceScaleFactor": 1, "mobile": false,
		}},
	} {
		if err := conn.Call(ctx, p.session, setup.method, setup.params, nil); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// Navigate loads an absolute http(s) URL and waits for the load to complete.
// Redirects are the browser's business; every hop is checked by the proxy
// (§3.3, §4.2).
func (p *Page) Navigate(ctx context.Context, rawURL string) (State, error) {
	rawURL = strings.TrimSpace(rawURL)
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return State{}, fmt.Errorf("browser_navigate: %q is not an absolute http(s) URL with a host", rawURL)
	}

	loads, cancel := p.conn.Subscribe("Page.loadEventFired")
	defer cancel()

	var navigation struct {
		ErrorText string `json:"errorText"`
	}
	if err := p.conn.Call(ctx, p.session, "Page.navigate", map[string]any{"url": rawURL}, &navigation); err != nil {
		return State{}, err
	}
	if navigation.ErrorText != "" {
		return State{}, fmt.Errorf("browser_navigate: %s: %s", rawURL, navigation.ErrorText)
	}

	select {
	case <-loads:
	case <-time.After(navigationTimeout):
		return State{}, fmt.Errorf("browser_navigate: %s did not finish loading within %s", rawURL, navigationTimeout)
	case <-ctx.Done():
		return State{}, fmt.Errorf("%w: browser_navigate: %w", ErrTransport, ctx.Err())
	}

	state, err := p.State(ctx)
	if err != nil {
		return State{}, err
	}
	if strings.HasPrefix(state.URL, "chrome-error://") {
		return State{}, fmt.Errorf("browser_navigate: %s could not be loaded (the browser showed its error page)", rawURL)
	}
	return state, nil
}

// State reads the page's URL, title, and viewport.
func (p *Page) State(ctx context.Context) (State, error) {
	evalCtx, cancel := context.WithTimeout(ctx, evaluateTimeout)
	defer cancel()
	raw, err := p.evaluate(evalCtx, `/*styx:state*/ JSON.stringify({
		url: location.href,
		title: document.title,
		width: window.innerWidth,
		height: window.innerHeight
	})`)
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return State{}, fmt.Errorf("browser: decode page state: %w", err)
	}
	return state, nil
}

// Read returns the aria snapshot, whole page or one element's subtree, bounded
// at maxChars (§3.2, §3.4). Reading is what mints the handles an action may
// use.
func (p *Page) Read(ctx context.Context, handle string, maxChars int) (string, error) {
	evalCtx, cancel := context.WithTimeout(ctx, evaluateTimeout)
	defer cancel()
	raw, err := p.evaluate(evalCtx, collectScript)
	if err != nil {
		return "", err
	}
	var collected rawSnapshot
	if err := json.Unmarshal([]byte(raw), &collected); err != nil {
		return "", fmt.Errorf("browser: decode the page snapshot: %w", err)
	}
	p.current = newSnapshot(collected)
	if strings.TrimSpace(handle) == "" {
		return p.current.render(maxChars), nil
	}
	found, err := p.current.lookup(handle)
	if err != nil {
		return "", err
	}
	return p.current.renderSubtree(found, maxChars), nil
}

// Click activates the element a handle addresses.
func (p *Page) Click(ctx context.Context, handle string) (State, error) {
	if p.current == nil {
		return State{}, fmt.Errorf("%w %q: no snapshot has been read in this session; take a fresh snapshot with browser_read",
			ErrStaleHandle, strings.TrimSpace(handle))
	}
	found, err := p.current.lookup(handle)
	if err != nil {
		return State{}, err
	}

	index := p.current.Nodes[found.Index].Index
	loads, cancel := p.conn.Subscribe("Page.loadEventFired")
	defer cancel()
	raw, err := p.evaluate(ctx, fmt.Sprintf(`/*styx:action*/ (() => {
		const el = document.querySelector('[data-styx-index="%d"]');
		if (!el) return JSON.stringify({ok:false, missing:true});
		if (el.disabled) return JSON.stringify({ok:false, blocked:true});
		el.scrollIntoView({block:'center', inline:'center'});
		el.click();
		return JSON.stringify({ok:true});
	})()`, index))
	if err != nil {
		return State{}, err
	}
	outcome, err := parseOutcome(raw)
	if err != nil {
		return State{}, err
	}
	if outcome.Missing {
		return State{}, p.stale(found)
	}
	if outcome.Blocked {
		return State{}, fmt.Errorf("browser_click: %s %q is disabled", found.Role, found.Name)
	}

	p.settle(loads)
	return p.State(ctx)
}

// TypeText focuses an element, types text into it, and optionally presses
// Enter. The typed text is the model's own argument and is never echoed back in
// the result.
func (p *Page) TypeText(ctx context.Context, handle, text string, submit bool) (State, error) {
	if p.current == nil {
		return State{}, fmt.Errorf("%w %q: no snapshot has been read in this session; take a fresh snapshot with browser_read",
			ErrStaleHandle, strings.TrimSpace(handle))
	}
	found, err := p.current.lookup(handle)
	if err != nil {
		return State{}, err
	}
	index := p.current.Nodes[found.Index].Index

	raw, err := p.evaluate(ctx, fmt.Sprintf(`/*styx:action*/ (() => {
		const el = document.querySelector('[data-styx-index="%d"]');
		if (!el) return JSON.stringify({ok:false, missing:true});
		if (el.disabled || el.readOnly) return JSON.stringify({ok:false, blocked:true});
		el.scrollIntoView({block:'center', inline:'center'});
		el.focus();
		if ('value' in el && typeof el.value === 'string') el.value = '';
		return JSON.stringify({ok:true});
	})()`, index))
	if err != nil {
		return State{}, err
	}
	outcome, err := parseOutcome(raw)
	if err != nil {
		return State{}, err
	}
	if outcome.Missing {
		return State{}, p.stale(found)
	}
	if outcome.Blocked {
		return State{}, fmt.Errorf("browser_type: %s %q is disabled or read-only", found.Role, found.Name)
	}

	if err := p.conn.Call(ctx, p.session, "Input.insertText", map[string]any{"text": text}, nil); err != nil {
		return State{}, err
	}
	if !submit {
		return p.State(ctx)
	}

	loads, cancel := p.conn.Subscribe("Page.loadEventFired")
	defer cancel()
	for _, event := range []map[string]any{
		{"type": "rawKeyDown", "key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13, "nativeVirtualKeyCode": 13},
		{"type": "char", "key": "Enter", "code": "Enter", "text": "\r", "windowsVirtualKeyCode": 13},
		{"type": "keyUp", "key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13, "nativeVirtualKeyCode": 13},
	} {
		if err := p.conn.Call(ctx, p.session, "Input.dispatchKeyEvent", event, nil); err != nil {
			return State{}, err
		}
	}
	p.settle(loads)
	return p.State(ctx)
}

// Screenshot writes a PNG artifact and returns its path and metadata, never its
// bytes (§3.4).
func (p *Page) Screenshot(ctx context.Context, path string, fullPage bool) (Artifact, error) {
	state, err := p.State(ctx)
	if err != nil {
		return Artifact{}, err
	}
	var capture struct {
		Data string `json:"data"`
	}
	if err := p.conn.Call(ctx, p.session, "Page.captureScreenshot", map[string]any{
		"format":                "png",
		"captureBeyondViewport": fullPage,
	}, &capture); err != nil {
		return Artifact{}, err
	}
	data, err := base64.StdEncoding.DecodeString(capture.Data)
	if err != nil {
		return Artifact{}, fmt.Errorf("browser: decode the screenshot: %w", err)
	}
	//nolint:gosec // artifacts are model-visible output, readable like the rest of .styx.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return Artifact{}, fmt.Errorf("browser: create screenshot directory: %w", err)
	}
	written, err := WriteArtifact(path, data)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{
		Path:   path,
		Bytes:  written,
		URL:    state.URL,
		Title:  state.Title,
		Width:  state.Width,
		Height: state.Height,
	}, nil
}

// Download activates a download element and saves the file into dir, keeping
// only its sanitized basename (§3.4). The returned artifact names the path,
// size, and sniffed content type.
func (p *Page) Download(ctx context.Context, handle, dir string) (Artifact, error) {
	if p.current == nil {
		return Artifact{}, fmt.Errorf("%w %q: no snapshot has been read in this session; take a fresh snapshot with browser_read",
			ErrStaleHandle, strings.TrimSpace(handle))
	}
	found, err := p.current.lookup(handle)
	if err != nil {
		return Artifact{}, err
	}
	index := p.current.Nodes[found.Index].Index

	//nolint:gosec // downloads are model-visible output, readable like the rest of .styx.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Artifact{}, fmt.Errorf("browser: create download directory %s: %w", dir, err)
	}
	// allowAndName saves each download under its GUID, so the harness decides
	// the visible name after sanitizing the server's suggestion (§3.4).
	if err := p.conn.Call(ctx, "", "Browser.setDownloadBehavior", map[string]any{
		"behavior":      "allowAndName",
		"downloadPath":  dir,
		"eventsEnabled": true,
	}, nil); err != nil {
		return Artifact{}, err
	}

	begins, cancelBegin := p.conn.Subscribe("Browser.downloadWillBegin")
	defer cancelBegin()
	progress, cancelProgress := p.conn.Subscribe("Browser.downloadProgress")
	defer cancelProgress()

	raw, err := p.evaluate(ctx, fmt.Sprintf(`/*styx:action*/ (() => {
		const el = document.querySelector('[data-styx-index="%d"]');
		if (!el) return JSON.stringify({ok:false, missing:true});
		if (el.disabled) return JSON.stringify({ok:false, blocked:true});
		el.scrollIntoView({block:'center', inline:'center'});
		el.click();
		return JSON.stringify({ok:true});
	})()`, index))
	if err != nil {
		return Artifact{}, err
	}
	outcome, err := parseOutcome(raw)
	if err != nil {
		return Artifact{}, err
	}
	if outcome.Missing {
		return Artifact{}, p.stale(found)
	}
	if outcome.Blocked {
		return Artifact{}, fmt.Errorf("browser_download: %s %q is disabled", found.Role, found.Name)
	}

	begin, err := waitEvent(ctx, begins, downloadStartTimeout)
	if err != nil {
		return Artifact{}, fmt.Errorf("browser_download: %s %q did not start a download: %w", found.Role, found.Name, err)
	}
	var started struct {
		GUID              string `json:"guid"`
		SuggestedFilename string `json:"suggestedFilename"`
		URL               string `json:"url"`
	}
	if err := json.Unmarshal(begin, &started); err != nil {
		return Artifact{}, fmt.Errorf("browser: decode the download event: %w", err)
	}
	if started.GUID == "" {
		return Artifact{}, errors.New("browser_download: the browser reported a download with no identifier")
	}

	if err := p.awaitDownload(ctx, progress, started.GUID); err != nil {
		return Artifact{}, err
	}

	source := filepath.Join(dir, started.GUID)
	if _, err := os.Stat(source); err != nil {
		return Artifact{}, fmt.Errorf("browser_download: the download finished but %s is missing: %w", source, err)
	}
	name := SanitizeDownloadName(started.SuggestedFilename)
	dest := UniquePath(dir, name)
	if err := os.Rename(source, dest); err != nil {
		return Artifact{}, fmt.Errorf("browser_download: keep %s: %w", name, err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		return Artifact{}, fmt.Errorf("browser_download: stat %s: %w", dest, err)
	}
	state, err := p.State(ctx)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{
		Path:        dest,
		Filename:    filepath.Base(dest),
		ContentType: sniffContentType(dest),
		Bytes:       info.Size(),
		URL:         state.URL,
		Title:       state.Title,
	}, nil
}

// awaitDownload waits for one download to complete, refusing a cancelled or
// interrupted one instead of announcing a partial file.
func (p *Page) awaitDownload(ctx context.Context, events <-chan json.RawMessage, guid string) error {
	deadline := time.Now().Add(downloadTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("browser_download: download %s did not complete within %s", guid, downloadTimeout)
		}
		raw, err := waitEvent(ctx, events, remaining)
		if err != nil {
			return fmt.Errorf("browser_download: download %s: %w", guid, err)
		}
		var update struct {
			GUID  string `json:"guid"`
			State string `json:"state"`
		}
		if err := json.Unmarshal(raw, &update); err != nil {
			continue
		}
		if update.GUID != guid {
			continue
		}
		switch update.State {
		case "completed":
			return nil
		case "canceled":
			return fmt.Errorf("browser_download: download %s was cancelled", guid)
		}
	}
}

// settle waits briefly for a click to begin a navigation, so the returned state
// names the page the action produced. A click that does not navigate returns
// after the short window.
func (p *Page) settle(loads <-chan json.RawMessage) {
	select {
	case <-loads:
	case <-time.After(clickSettle):
	}
}

// stale is the named refusal for a handle whose element is gone. The message
// always tells the model what to do next (§3.2).
func (p *Page) stale(handle Handle) error {
	return fmt.Errorf("%w %q: the page changed and the element %s %q is gone; take a fresh snapshot with browser_read",
		ErrStaleHandle, fmt.Sprint(handle.Number), handle.Role, handle.Name)
}

// evaluate runs one expression in the page and returns its string value.
func (p *Page) evaluate(ctx context.Context, expression string) (string, error) {
	var result struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text      string `json:"text"`
			Exception *struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	if err := p.conn.Call(ctx, p.session, "Runtime.evaluate", map[string]any{
		"expression":    expression,
		"returnByValue": true,
		"awaitPromise":  false,
		"userGesture":   true,
	}, &result); err != nil {
		return "", err
	}
	if result.ExceptionDetails != nil {
		detail := result.ExceptionDetails.Text
		if result.ExceptionDetails.Exception != nil && result.ExceptionDetails.Exception.Description != "" {
			detail = result.ExceptionDetails.Exception.Description
		}
		if detail == "" {
			detail = "the page raised an exception"
		}
		return "", fmt.Errorf("browser: page script failed: %s", detail)
	}
	return result.Result.Value, nil
}

// waitEvent returns the next event, or an error when ctx or the timeout ends
// the wait.
func waitEvent(ctx context.Context, events <-chan json.RawMessage, timeout time.Duration) (json.RawMessage, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case event, ok := <-events:
		if !ok {
			return nil, errors.New("the browser connection closed while waiting")
		}
		return event, nil
	case <-timer.C:
		return nil, fmt.Errorf("timed out after %s", timeout)
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrTransport, ctx.Err())
	}
}

// sniffContentType reports a download's type from its own bytes, never from a
// network round trip: the artifact is already local.
func sniffContentType(path string) string {
	//nolint:gosec // the path is a sanitized artifact in the session's download directory.
	f, err := os.Open(path)
	if err != nil {
		return "application/octet-stream"
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, 512)
	n, err := f.Read(head)
	if n <= 0 || err != nil {
		return "application/octet-stream"
	}
	return http.DetectContentType(head[:n])
}
