package browser

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Launch describes one browser launch. Every field is harness-supplied: the
// model never chooses a binary, a profile, or an egress path.
type Launch struct {
	// Binary is the resolved executable.
	Binary string
	// ProfileDir is the isolated profile the browser writes (§5).
	ProfileDir string
	// ProxyURL is the harness proxy. It is required: the browser's only egress
	// path is the proxy (§3.1), so an empty value is a refusal.
	ProxyURL string
	// CASPKI is the base64 SHA-256 SPKI of the engagement's interception CA.
	// When set, exactly this process trusts exactly this CA; the operator's own
	// browsing is untouched (§4.4).
	CASPKI string
}

// Args builds the browser's command line (§3.1). It refuses an incomplete
// launch rather than starting a browser with an egress path it did not intend:
// no proxy, no launch, and a proxy that is not an absolute http(s) URL is a
// configuration error.
func Args(l Launch) ([]string, error) {
	if strings.TrimSpace(l.Binary) == "" {
		return nil, fmt.Errorf("%w: no browser binary was resolved", ErrPrerequisite)
	}
	if strings.TrimSpace(l.ProfileDir) == "" {
		return nil, errors.New("browser: a launch needs an isolated profile directory")
	}
	proxy := strings.TrimSpace(l.ProxyURL)
	if proxy == "" {
		return nil, fmt.Errorf("%w: the browser dials the harness proxy and nothing else", ErrNoProxy)
	}
	parsed, err := url.Parse(proxy)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("browser: proxy %q is not an absolute http(s) URL", proxy)
	}

	args := []string{
		"--headless=new",
		"--user-data-dir=" + l.ProfileDir,
		// Port 0 makes Chromium choose an ephemeral port and report it only in
		// the profile's DevToolsActivePort file, so the port never appears on
		// the command line another local process can read (§3.1).
		"--remote-debugging-port=0",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-sync",
		// The profile is the harness's, not the operator's: a plain local
		// password store keeps cookie persistence independent of a desktop
		// keyring, with no prompt and no D-Bus dependency.
		"--password-store=basic",
		"--use-mock-keychain",
		// One egress path: QUIC off, and WebRTC restricted to proxied UDP.
		"--disable-quic",
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--proxy-server=" + proxy,
		// Chromium implicitly bypasses loopback; subtract that bypass so even a
		// loopback destination goes through the proxy.
		"--proxy-bypass-list=<-loopback>",
		"--window-size=1280,900",
	}
	if strings.TrimSpace(l.CASPKI) != "" {
		args = append(args, "--ignore-certificate-errors-spki-list="+strings.TrimSpace(l.CASPKI))
	}
	// The page the session starts on. Nothing is fetched until the model asks.
	args = append(args, "about:blank")
	return args, nil
}
