package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/policy"
)

// Browser is the harness-side browser driver (docs/browser-and-proxy.md §3).
// It is a seam: `agent` knows the six verbs and their contract, never how a
// browser process is launched or driven. The production implementation is
// internal/browser; tests substitute a recording fake and stay offline.
type Browser interface {
	// Navigate loads an absolute http(s) URL in the active page.
	Navigate(ctx context.Context, rawURL string) (BrowserPage, error)
	// Read returns a bounded aria snapshot; an empty handle is the whole page.
	Read(ctx context.Context, handle string, maxChars int) (string, error)
	// Click activates an element by its per-snapshot handle.
	Click(ctx context.Context, handle string) (BrowserPage, error)
	// Type types into an element and optionally submits.
	Type(ctx context.Context, handle, text string, submit bool) (BrowserPage, error)
	// Screenshot writes a PNG artifact and returns its metadata.
	Screenshot(ctx context.Context, fullPage bool) (BrowserArtifact, error)
	// Download activates a download element and returns the saved artifact.
	Download(ctx context.Context, handle string) (BrowserArtifact, error)
}

// BrowserPage is the page an action landed on.
type BrowserPage struct {
	URL   string
	Title string
}

// BrowserArtifact is a written artifact: its path, size, and metadata. There is
// deliberately no bytes field — no tool returns pixels or file contents
// (docs/browser-and-proxy.md §3.4).
type BrowserArtifact struct {
	Path        string
	Filename    string
	ContentType string
	Bytes       int64
	URL         string
	Title       string
	Width       int
	Height      int
}

// The six schemas are strict: every property is declared and required, and an
// action enum is deliberately absent — six verbs, one per tool (§3.2).
const (
	browserNavigateSchema = `{
  "type": "object",
  "properties": {
    "url": {
      "type": "string",
      "description": "Absolute http(s) URL to load in the active page. The host is checked against the engagement scope; redirects are followed hop by hop and each hop is checked."
    }
  },
  "required": ["url"],
  "additionalProperties": false
}`

	browserReadSchema = `{
  "type": "object",
  "properties": {
    "handle": {
      "type": "string",
      "description": "Element handle to read, as numbered in the latest snapshot ([3] link \"Home\"). Empty string reads the whole page."
    },
    "max_chars": {
      "type": "integer",
      "description": "Maximum characters to return; 0 means the 8192-character default, and the result is capped at 32768."
    }
  },
  "required": ["handle", "max_chars"],
  "additionalProperties": false
}`

	browserClickSchema = `{
  "type": "object",
  "properties": {
    "handle": {
      "type": "string",
      "description": "Handle of the element to activate, from the latest browser_read snapshot. A handle that snapshot did not expose, or whose element is gone, is refused as stale."
    }
  },
  "required": ["handle"],
  "additionalProperties": false
}`

	browserTypeSchema = `{
  "type": "object",
  "properties": {
    "handle": {
      "type": "string",
      "description": "Handle of the field to type into, from the latest browser_read snapshot."
    },
    "text": {
      "type": "string",
      "description": "Text to type into the field. It is never echoed back in the result."
    },
    "submit": {
      "type": "boolean",
      "description": "Press Enter after typing to submit the field's form."
    }
  },
  "required": ["handle", "text", "submit"],
  "additionalProperties": false
}`

	browserScreenshotSchema = `{
  "type": "object",
  "properties": {
    "full_page": {
      "type": "boolean",
      "description": "Capture the whole page rather than the viewport."
    }
  },
  "required": ["full_page"],
  "additionalProperties": false
}`

	browserDownloadSchema = `{
  "type": "object",
  "properties": {
    "handle": {
      "type": "string",
      "description": "Handle of the element that starts a download, from the latest browser_read snapshot."
    }
  },
  "required": ["handle"],
  "additionalProperties": false
}`
)

// BrowserToolNames are the six browser verbs, in contract order. Presets and
// registries use this list so the advertised set and the built set cannot
// drift.
func BrowserToolNames() []string {
	return []string{
		"browser_navigate",
		"browser_read",
		"browser_click",
		"browser_type",
		"browser_screenshot",
		"browser_download",
	}
}

// BrowserTools builds the six §3.2 browser tools over one driver. The harness
// registers them in both modes: the rule table prompts for them, and engagement
// scope widens a navigate whose host is in scope.
func BrowserTools(driver Browser) []Tool {
	return []Tool{
		BrowserNavigateTool(driver),
		BrowserReadTool(driver),
		BrowserClickTool(driver),
		BrowserTypeTool(driver),
		BrowserScreenshotTool(driver),
		BrowserDownloadTool(driver),
	}
}

// BrowserNavigateTool is `browser_navigate`: load an absolute http(s) URL.
// Its URL host is the call's scope target, exactly as web_fetch derives it
// (§3.3); a URL with no parseable host declares no targets and is refused by
// the handler rather than resolved as target-free.
func BrowserNavigateTool(driver Browser) Tool {
	return Tool{
		Name:        "browser_navigate",
		Description: "Load an absolute http(s) URL in the session's browser. The host is checked against the engagement scope, and every redirect hop and subresource is checked at the proxy. Follow with browser_read to see the page.",
		Parameters:  json.RawMessage(browserNavigateSchema),
		Targets: func(args map[string]any) []policy.Target {
			raw, _ := args["url"].(string)
			host := urlHost(raw)
			if host == "" {
				return nil
			}
			return []policy.Target{{Addr: host}}
		},
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			raw, err := stringArg(args, "url")
			if err != nil {
				return "", fmt.Errorf("browser_navigate: %w", err)
			}
			if err := validateBrowserURL(raw); err != nil {
				return "", err
			}
			if driver == nil {
				return "", errors.New("browser_navigate: no browser driver is configured")
			}
			state, err := driver.Navigate(ctx, raw)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("loaded: %s\ntitle: %s\n[handles are per-snapshot: call browser_read before the next action]",
				state.URL, pageTitle(state)), nil
		},
	}
}

// BrowserReadTool is `browser_read`: the bounded aria snapshot. Reading is what
// mints the handles click and type accept.
func BrowserReadTool(driver Browser) Tool {
	return Tool{
		Name:        "browser_read",
		Description: "Read the page as a bounded aria snapshot. Interactive nodes carry a per-snapshot number in brackets ([3] button \"Sign in\"); click and type accept only those numbers. Pass an empty handle for the whole page, or a handle to read one element's subtree.",
		Parameters:  json.RawMessage(browserReadSchema),
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			handle, err := stringArg(args, "handle")
			if err != nil {
				return "", fmt.Errorf("browser_read: %w", err)
			}
			maxChars, err := intArg(args, "max_chars", 0, 0)
			if err != nil {
				return "", fmt.Errorf("browser_read: %w", err)
			}
			if driver == nil {
				return "", errors.New("browser_read: no browser driver is configured")
			}
			return driver.Read(ctx, handle, maxChars)
		},
	}
}

// BrowserClickTool is `browser_click`: activate an element by handle.
func BrowserClickTool(driver Browser) Tool {
	return Tool{
		Name:        "browser_click",
		Description: "Activate an element by its per-snapshot handle. The handle must come from the latest browser_read; an unknown or stale handle is refused with a fresh-snapshot instruction.",
		Parameters:  json.RawMessage(browserClickSchema),
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			handle, err := stringArg(args, "handle")
			if err != nil {
				return "", fmt.Errorf("browser_click: %w", err)
			}
			if driver == nil {
				return "", errors.New("browser_click: no browser driver is configured")
			}
			state, err := driver.Click(ctx, handle)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("clicked handle %s\nurl: %s\ntitle: %s\n[handles are per-snapshot: call browser_read before the next action]",
				strings.TrimSpace(handle), state.URL, pageTitle(state)), nil
		},
	}
}

// BrowserTypeTool is `browser_type`: type into a field, optionally submit.
func BrowserTypeTool(driver Browser) Tool {
	return Tool{
		Name:        "browser_type",
		Description: "Type text into a field by its per-snapshot handle, optionally pressing Enter to submit. The typed text is never echoed in the result.",
		Parameters:  json.RawMessage(browserTypeSchema),
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			handle, err := stringArg(args, "handle")
			if err != nil {
				return "", fmt.Errorf("browser_type: %w", err)
			}
			text, err := stringArg(args, "text")
			if err != nil {
				return "", fmt.Errorf("browser_type: %w", err)
			}
			submit, err := boolArg(args, "submit")
			if err != nil {
				return "", fmt.Errorf("browser_type: %w", err)
			}
			if driver == nil {
				return "", errors.New("browser_type: no browser driver is configured")
			}
			state, err := driver.Type(ctx, handle, text, submit)
			if err != nil {
				return "", err
			}
			action := "typed"
			if submit {
				action = "typed and submitted"
			}
			return fmt.Sprintf("%s handle %s\nurl: %s\ntitle: %s\n[handles are per-snapshot: call browser_read before the next action]",
				action, strings.TrimSpace(handle), state.URL, pageTitle(state)), nil
		},
	}
}

// BrowserScreenshotTool is `browser_screenshot`: write a PNG artifact and
// return its path and metadata, never its bytes (§3.4).
func BrowserScreenshotTool(driver Browser) Tool {
	return Tool{
		Name:        "browser_screenshot",
		Description: "Capture the page as a PNG artifact under .styx/out/browser/<session>/ and return its path, size, URL, title, and viewport. The image itself is never returned as data.",
		Parameters:  json.RawMessage(browserScreenshotSchema),
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			fullPage, err := boolArg(args, "full_page")
			if err != nil {
				return "", fmt.Errorf("browser_screenshot: %w", err)
			}
			if driver == nil {
				return "", errors.New("browser_screenshot: no browser driver is configured")
			}
			artifact, err := driver.Screenshot(ctx, fullPage)
			if err != nil {
				return "", err
			}
			var b strings.Builder
			fmt.Fprintf(&b, "path: %s\nbytes: %d\nurl: %s\ntitle: %s",
				artifact.Path, artifact.Bytes, artifact.URL, titleOrPlaceholder(artifact.Title))
			if artifact.Width > 0 && artifact.Height > 0 {
				fmt.Fprintf(&b, "\nviewport: %dx%d", artifact.Width, artifact.Height)
			}
			return b.String(), nil
		},
	}
}

// BrowserDownloadTool is `browser_download`: activate a download element and
// return the saved artifact. The server-supplied filename is sanitized to a
// basename inside the session's download directory (§3.4).
func BrowserDownloadTool(driver Browser) Tool {
	return Tool{
		Name:        "browser_download",
		Description: "Activate an element that starts a download. The file is saved under .styx/out/downloads/<session>/ with its server-supplied filename sanitized to a basename, and the result names its path, size, and content type — never its bytes. Executing a download is bash in the container, under the ordinary rules.",
		Parameters:  json.RawMessage(browserDownloadSchema),
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			handle, err := stringArg(args, "handle")
			if err != nil {
				return "", fmt.Errorf("browser_download: %w", err)
			}
			if driver == nil {
				return "", errors.New("browser_download: no browser driver is configured")
			}
			artifact, err := driver.Download(ctx, handle)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("path: %s\nfilename: %s\nbytes: %d\ncontent_type: %s\nurl: %s",
				artifact.Path, artifact.Filename, artifact.Bytes, artifact.ContentType, artifact.URL), nil
		},
	}
}

// validateBrowserURL refuses a navigate that could not be scope-checked. The
// handler refuses rather than letting an unparseable URL run target-free (§3.2,
// §3.3).
func validateBrowserURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return fmt.Errorf("browser_navigate: %q is not an absolute http(s) URL with a host", raw)
	}
	return nil
}

// pageTitle renders a page's title for a tool result.
func pageTitle(page BrowserPage) string { return titleOrPlaceholder(page.Title) }

// titleOrPlaceholder names an untitled page rather than leaving a blank field.
func titleOrPlaceholder(title string) string {
	if strings.TrimSpace(title) == "" {
		return "(untitled)"
	}
	return title
}
