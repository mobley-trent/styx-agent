package browser

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestLaunchArgsForceOneEgressPath(t *testing.T) {
	args, err := Args(Launch{
		Binary:     "/usr/bin/chromium",
		ProfileDir: "/home/op/.local/share/styx/browsers/proj/eng",
		ProxyURL:   "http://10.0.0.1:3128",
		CASPKI:     "spki-pin",
	})
	if err != nil {
		t.Fatalf("Args() = %v", err)
	}
	for _, want := range []string{
		"--headless=new",
		"--user-data-dir=/home/op/.local/share/styx/browsers/proj/eng",
		"--remote-debugging-port=0",
		"--disable-quic",
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--proxy-server=http://10.0.0.1:3128",
		"--proxy-bypass-list=<-loopback>",
		"--ignore-certificate-errors-spki-list=spki-pin",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("args = %v, want it to contain %q", args, want)
		}
	}
	if args[len(args)-1] != "about:blank" {
		t.Errorf("last arg = %q, want the startup page", args[len(args)-1])
	}
	// The CDP port must never be a concrete number on the command line.
	for _, arg := range args {
		if strings.HasPrefix(arg, "--remote-debugging-port=") && arg != "--remote-debugging-port=0" {
			t.Errorf("args contain a fixed CDP port %q", arg)
		}
	}
}

func TestLaunchArgsRequireAProxy(t *testing.T) {
	_, err := Args(Launch{Binary: "/usr/bin/chromium", ProfileDir: "/tmp/profile"})
	if !errors.Is(err, ErrNoProxy) {
		t.Fatalf("Args() = %v, want ErrNoProxy", err)
	}
}

func TestLaunchArgsRejectABadProxy(t *testing.T) {
	for _, proxy := range []string{"socks5://10.0.0.1:1080", "10.0.0.1:3128", "http://"} {
		if _, err := Args(Launch{Binary: "/usr/bin/chromium", ProfileDir: "/tmp/profile", ProxyURL: proxy}); err == nil {
			t.Errorf("Args(proxy=%q) accepted it", proxy)
		}
	}
}

func TestLaunchArgsWithoutCAAreUnpinned(t *testing.T) {
	args, err := Args(Launch{Binary: "/usr/bin/chromium", ProfileDir: "/tmp/profile", ProxyURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("Args() = %v", err)
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "--ignore-certificate-errors-spki-list=") {
			t.Errorf("args = %v, want no CA pin when no CA is in play", args)
		}
	}
}
