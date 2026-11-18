package agent

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// recordingBrowser is a hermetic browser seam: it records what the tools asked
// for and returns canned results.
type recordingBrowser struct {
	navigated []string
	reads     []readCall
	clicked   []string
	types     []typeCall
	shots     []bool
	downloads []string

	page     BrowserPage
	artifact BrowserArtifact
	err      error
}

type readCall struct {
	handle   string
	maxChars int
}

type typeCall struct {
	handle string
	text   string
	submit bool
}

func (b *recordingBrowser) Navigate(_ context.Context, rawURL string) (BrowserPage, error) {
	b.navigated = append(b.navigated, rawURL)
	return b.page, b.err
}

func (b *recordingBrowser) Read(_ context.Context, handle string, maxChars int) (string, error) {
	b.reads = append(b.reads, readCall{handle: handle, maxChars: maxChars})
	if b.err != nil {
		return "", b.err
	}
	return "snapshot", nil
}

func (b *recordingBrowser) Click(_ context.Context, handle string) (BrowserPage, error) {
	b.clicked = append(b.clicked, handle)
	return b.page, b.err
}

func (b *recordingBrowser) Type(_ context.Context, handle, text string, submit bool) (BrowserPage, error) {
	b.types = append(b.types, typeCall{handle: handle, text: text, submit: submit})
	return b.page, b.err
}

func (b *recordingBrowser) Screenshot(_ context.Context, fullPage bool) (BrowserArtifact, error) {
	b.shots = append(b.shots, fullPage)
	return b.artifact, b.err
}

func (b *recordingBrowser) Download(_ context.Context, handle string) (BrowserArtifact, error) {
	b.downloads = append(b.downloads, handle)
	return b.artifact, b.err
}

func TestBrowserToolNamesMatchTheBuiltSet(t *testing.T) {
	names := BrowserToolNames()
	if !reflect.DeepEqual(names, []string{
		"browser_navigate", "browser_read", "browser_click",
		"browser_type", "browser_screenshot", "browser_download",
	}) {
		t.Errorf("BrowserToolNames() = %v", names)
	}
	tools := BrowserTools(&recordingBrowser{})
	if len(tools) != len(names) {
		t.Fatalf("BrowserTools() = %d tools, want %d", len(tools), len(names))
	}
	for i, tool := range tools {
		if tool.Name != names[i] {
			t.Errorf("tool %d = %q, want %q", i, tool.Name, names[i])
		}
		if tool.Destructive || tool.ExploitClass {
			t.Errorf("%s is tagged destructive/exploit-class; a page load is neither", tool.Name)
		}
	}
}

func TestBrowserNavigateTargets(t *testing.T) {
	tool := BrowserNavigateTool(nil)
	tests := []struct {
		name string
		url  string
		want []string
	}{
		{name: "ip literal", url: "http://192.0.2.44/login", want: []string{"192.0.2.44"}},
		{name: "hostname with port", url: "https://app.acme.example:8443/x", want: []string{"app.acme.example"}},
		{name: "bracketed ipv6", url: "http://[2001:db8::1]:8080/x", want: []string{"2001:db8::1"}},
		{name: "no host", url: "definitely not a url", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, target := range tool.Targets(map[string]any{"url": tt.url}) {
				got = append(got, target.Addr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Targets(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestBrowserNavigateRefusesAnUncheckableURL(t *testing.T) {
	browser := &recordingBrowser{}
	tool := BrowserNavigateTool(browser)
	for _, raw := range []string{"file:///etc/passwd", "not a url", "http://"} {
		if _, err := tool.Handler(context.Background(), map[string]any{"url": raw}); err == nil {
			t.Errorf("Handler(%q) accepted it", raw)
		}
	}
	if len(browser.navigated) != 0 {
		t.Errorf("the browser was called for an uncheckable URL: %v", browser.navigated)
	}
}

func TestBrowserNavigateFormatsThePage(t *testing.T) {
	browser := &recordingBrowser{page: BrowserPage{URL: "http://10.0.0.5/home", Title: "Home"}}
	tool := BrowserNavigateTool(browser)
	got, err := tool.Handler(context.Background(), map[string]any{"url": "http://10.0.0.5/home"})
	if err != nil {
		t.Fatalf("Handler() = %v", err)
	}
	if !strings.Contains(got, "loaded: http://10.0.0.5/home") || !strings.Contains(got, "title: Home") {
		t.Errorf("Handler() = %q, want the loaded page", got)
	}
	if !strings.Contains(got, "browser_read") {
		t.Errorf("Handler() = %q, want the fresh-snapshot hint", got)
	}
}

func TestBrowserReadPassesTheBoundAndElement(t *testing.T) {
	browser := &recordingBrowser{}
	tool := BrowserReadTool(browser)
	got, err := tool.Handler(context.Background(), map[string]any{"handle": "3", "max_chars": float64(120)})
	if err != nil {
		t.Fatalf("Handler() = %v", err)
	}
	if got != "snapshot" {
		t.Errorf("Handler() = %q, want the driver's text", got)
	}
	if len(browser.reads) != 1 || browser.reads[0].handle != "3" || browser.reads[0].maxChars != 120 {
		t.Errorf("reads = %+v, want handle 3 at 120 characters", browser.reads)
	}
	if _, err := tool.Handler(context.Background(), map[string]any{"handle": "", "max_chars": float64(0)}); err != nil {
		t.Fatalf("Handler(default) = %v", err)
	}
	if browser.reads[1].maxChars != 0 {
		t.Errorf("default max_chars = %d, want the driver's default sentinel", browser.reads[1].maxChars)
	}
}

func TestBrowserClickAndTypePassHandles(t *testing.T) {
	browser := &recordingBrowser{page: BrowserPage{URL: "http://10.0.0.5/", Title: "Page"}}
	click := BrowserClickTool(browser)
	got, err := click.Handler(context.Background(), map[string]any{"handle": "2"})
	if err != nil {
		t.Fatalf("click Handler() = %v", err)
	}
	if len(browser.clicked) != 1 || browser.clicked[0] != "2" {
		t.Errorf("clicked = %v, want handle 2", browser.clicked)
	}
	if !strings.Contains(got, "clicked handle 2") || !strings.Contains(got, "browser_read") {
		t.Errorf("click Handler() = %q", got)
	}

	typed := BrowserTypeTool(browser)
	got, err = typed.Handler(context.Background(), map[string]any{
		"handle": "2", "text": "hunter2", "submit": true,
	})
	if err != nil {
		t.Fatalf("type Handler() = %v", err)
	}
	if len(browser.types) != 1 || browser.types[0].text != "hunter2" || !browser.types[0].submit {
		t.Errorf("types = %+v, want the text and submit flag", browser.types)
	}
	if strings.Contains(got, "hunter2") {
		t.Errorf("type Handler() = %q echoed the typed text", got)
	}
}

func TestBrowserScreenshotReturnsMetadataOnly(t *testing.T) {
	browser := &recordingBrowser{artifact: BrowserArtifact{
		Path:   ".styx/out/browser/s/shot-1.png",
		Bytes:  2048,
		URL:    "http://10.0.0.5/",
		Title:  "Page",
		Width:  1280,
		Height: 900,
	}}
	tool := BrowserScreenshotTool(browser)
	got, err := tool.Handler(context.Background(), map[string]any{"full_page": true})
	if err != nil {
		t.Fatalf("Handler() = %v", err)
	}
	for _, want := range []string{
		"path: .styx/out/browser/s/shot-1.png", "bytes: 2048", "viewport: 1280x900", "title: Page",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Handler() = %q, want it to contain %q", got, want)
		}
	}
	if !browser.shots[0] {
		t.Error("full_page was not forwarded")
	}
	if strings.Contains(got, "iVBOR") || strings.Contains(got, "base64") {
		t.Errorf("Handler() = %q carries image bytes", got)
	}
}

func TestBrowserDownloadReturnsTheSanitizedArtifact(t *testing.T) {
	browser := &recordingBrowser{artifact: BrowserArtifact{
		Path:        ".styx/out/downloads/s/report.txt",
		Filename:    "report.txt",
		ContentType: "text/plain; charset=utf-8",
		Bytes:       12,
		URL:         "http://10.0.0.5/export",
	}}
	tool := BrowserDownloadTool(browser)
	got, err := tool.Handler(context.Background(), map[string]any{"handle": "4"})
	if err != nil {
		t.Fatalf("Handler() = %v", err)
	}
	for _, want := range []string{
		"path: .styx/out/downloads/s/report.txt", "filename: report.txt",
		"bytes: 12", "content_type: text/plain; charset=utf-8",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Handler() = %q, want it to contain %q", got, want)
		}
	}
	if len(browser.downloads) != 1 || browser.downloads[0] != "4" {
		t.Errorf("downloads = %v, want handle 4", browser.downloads)
	}
}

func TestBrowserToolsPropagateTheStaleHandleError(t *testing.T) {
	stale := errors.New(`stale handle "7": take a fresh snapshot with browser_read`)
	browser := &recordingBrowser{err: stale}
	if _, err := BrowserClickTool(browser).Handler(context.Background(), map[string]any{"handle": "7"}); !errors.Is(err, stale) {
		t.Errorf("click Handler() = %v, want the driver's stale-handle error", err)
	}
	if _, err := BrowserReadTool(browser).Handler(context.Background(), map[string]any{"handle": "7", "max_chars": float64(0)}); !errors.Is(err, stale) {
		t.Errorf("read Handler() = %v, want the driver's stale-handle error", err)
	}
}

func TestBrowserToolsRefuseWithoutADriver(t *testing.T) {
	for _, tool := range BrowserTools(nil) {
		args := map[string]any{
			"url": "http://10.0.0.5/", "handle": "1", "text": "x",
			"submit": false, "max_chars": float64(0), "full_page": false,
		}
		_, err := tool.Handler(context.Background(), args)
		if err == nil {
			t.Errorf("%s ran without a driver", tool.Name)
		}
	}
}
