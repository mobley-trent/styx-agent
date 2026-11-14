package containerlayer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// InterceptOptions turns the egress proxy into the engagement's interception
// proxy (§4.2): CONNECT is terminated with the engagement's CA, every request
// is scope-checked and captured, and the capture is replayable.
//
// Verdicts are deny-or-pass and never a prompt (§4.3): a tunnel has no
// in-flight call to raise a card on, and an unanswered prompt is a hung
// browser. The operator's widen is the engagement file.
type InterceptOptions struct {
	// CA signs the leaves the proxy presents. Required.
	CA *CA
	// Capture records every exchange. Required; the caller owns its lifetime.
	Capture *Capture
	// UpstreamTLS overrides how the proxy validates the destination. Nil uses
	// the host's roots; tests pin a pool.
	UpstreamTLS *tls.Config
	// Now stamps records; nil means time.Now.
	Now func() time.Time
}

// interceptor is the engagement-mode half of one proxy.
type interceptor struct {
	ca          *CA
	capture     *Capture
	upstreamTLS *tls.Config
	now         func() time.Time
}

// newInterceptor validates the interception configuration.
func newInterceptor(opts InterceptOptions) (*interceptor, error) {
	if opts.CA == nil {
		return nil, errors.New("containerlayer: interception needs the engagement's CA")
	}
	if opts.Capture == nil {
		return nil, errors.New("containerlayer: interception needs a capture")
	}
	ic := &interceptor{ca: opts.CA, capture: opts.Capture, upstreamTLS: opts.UpstreamTLS, now: opts.Now}
	if ic.now == nil {
		ic.now = time.Now
	}
	return ic, nil
}

// ReplayRequest is one proxy_replay call (§4.6): re-send a captured exchange,
// with an empty field meaning "as captured".
type ReplayRequest struct {
	// ID is the captured exchange to re-send.
	ID string
	// Method overrides the captured method; empty uses it.
	Method string
	// URL overrides the captured destination; empty uses it.
	URL string
	// HeadersJSON replaces the captured headers when non-empty: a JSON object
	// of strings, the same string-carried shape the skill tool uses.
	HeadersJSON string
	// Body overrides the captured body; empty re-sends it as captured. An
	// elided captured body refuses rather than sending a truncated one.
	Body string
}

// ReplayResult is the replay's model-facing receipt: the exchange it produced,
// redacted, and the segment it landed in, so it can be cited as
// capture-<n>.jsonl#<id> (§4.5).
type ReplayResult struct {
	Receipt  Receipt  `json:"receipt"`
	Exchange Exchange `json:"exchange"`
}

// replayLimit is how much of a replayed response the record keeps, mirroring
// the capture's own body bound.
//
// proxyDenial is the structured refusal a request gets instead of traffic
// (§4.3): it names the reason and the destination, so the model can change
// course without a prompt nobody can answer.
type proxyDenial struct {
	Error   string `json:"error"`
	Reason  string `json:"reason,omitempty"`
	Host    string `json:"host,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Audit   string `json:"audit,omitempty"`
	Capture string `json:"capture,omitempty"`
}

// Intercept bounds.
const tunnelIdleTimeout = 2 * time.Minute

// interceptConnect terminates a CONNECT tunnel: the destination is checked
// before the TLS handshake, so a refusal is a plaintext 403 the client can
// read, and every request inside the tunnel is checked again as it arrives.
func (p *EgressProxy) interceptConnect(w http.ResponseWriter, r *http.Request) {
	start := p.now()
	host, port := splitAuthority(r.Host, "443")
	authority := net.JoinHostPort(host, port)

	if err := p.verify(r.Context(), host); err != nil {
		p.deny(w, nil, p.intercept.denied(start, http.MethodConnect, "https://"+authority, host, "https", err))
		return
	}
	leaf, err := p.intercept.ca.Leaf(host)
	if err != nil {
		writeProxyError(w, err)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxying not supported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	tlsConn := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		// The intercepting side speaks HTTP/1.1 only; offering h2 to the
		// client would promise a framing this proxy does not implement.
		NextProtos: []string{"http/1.1"},
	})
	hsCtx, cancel := context.WithTimeout(r.Context(), defaultProxyTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	p.serveTunnel(context.WithoutCancel(r.Context()), tlsConn, host, port)
}

// serveTunnel reads requests from one intercepted TLS connection.
func (p *EgressProxy) serveTunnel(ctx context.Context, conn net.Conn, host, port string) {
	br := bufio.NewReader(conn)
	connectAuthority := net.JoinHostPort(host, port)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(tunnelIdleTimeout)); err != nil {
			return
		}
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		if !p.serveTunnelRequest(ctx, conn, req, connectAuthority) {
			return
		}
	}
}

// serveTunnelRequest checks, forwards, records, and relays one request. It
// reports whether the tunnel stays open.
func (p *EgressProxy) serveTunnelRequest(ctx context.Context, conn net.Conn, req *http.Request, connectAuthority string) bool {
	start := p.now()
	scheme := "https"
	authority := connectAuthority
	if req.URL.IsAbs() {
		scheme = req.URL.Scheme
		authority = req.URL.Host
	} else if req.Host != "" {
		authority = req.Host
	}
	defaultPort := "443"
	if scheme == "http" {
		defaultPort = "80"
	}
	host, _ := splitAuthority(authority, defaultPort)
	rawURL := scheme + "://" + authority + requestTarget(req)

	// A capture that cannot record must not forward: the exchange would pass
	// uncaptured (§8). The pre-flight also rotates a full segment here, so a
	// full disk surfaces before the dial rather than after.
	if err := p.intercept.capture.Ready(); err != nil {
		writeTunnelJSON(conn, http.StatusBadGateway, proxyDenial{Error: "capture-unavailable", Detail: err.Error()})
		return false
	}
	if err := p.verify(ctx, host); err != nil {
		p.deny(nil, conn, p.intercept.denied(start, req.Method, rawURL, host, scheme, err))
		return false
	}

	out, reqRec := p.upstreamRequest(ctx, req, scheme, authority)
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		if errors.Is(err, ErrNotAllowed) {
			p.deny(nil, conn, p.intercept.denied(start, req.Method, rawURL, host, scheme, err))
			return false
		}
		writeTunnelFailure(conn, err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	removeHopHeaders(resp.Header)

	keep := req.ProtoAtLeast(1, 1) && !req.Close && !resp.Close && resp.ContentLength >= 0
	limit := p.intercept.capture.keepLimit()
	respRec := newBodyRecorder(resp.Body, limit)
	small, err := readUpTo(respRec, limit)
	if err != nil {
		writeTunnelFailure(conn, err)
		return false
	}
	ex := p.intercept.exchange(start, req.Method, rawURL, host, scheme, headersOf(req.Header), requestBody(reqRec), resp, respRec)

	if !small {
		// The body is too large to hold, so it streams: the record is written
		// after the bytes are on the wire, and a failure poisons the capture so
		// no later exchange passes.
		if err := writeTunnelHead(conn, resp, keep); err != nil {
			return false
		}
		if _, err := conn.Write(respRec.keptBytes()); err != nil {
			return false
		}
		if _, err := io.Copy(conn, respRec); err != nil {
			return false
		}
		_, _ = p.intercept.capture.Write(ex)
		return keep
	}

	// Small enough to record verbatim: the record is written before the client
	// can see the exchange, so a full disk refuses it rather than letting it
	// pass uncaptured (§8).
	if _, err := p.intercept.capture.Write(ex); err != nil {
		writeTunnelJSON(conn, http.StatusBadGateway, proxyDenial{Error: "capture-unavailable", Detail: err.Error()})
		return false
	}
	if err := writeTunnelResponse(conn, resp, keep, respRec.keptBytes()); err != nil {
		return false
	}
	return keep
}

// interceptForward handles an absolute-URI HTTP request in engagement mode:
// the same check, capture, and relay rules as the tunnel, with no TLS to
// terminate.
func (p *EgressProxy) interceptForward(w http.ResponseWriter, r *http.Request) {
	start := p.now()
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	authority := r.URL.Host
	host, _ := splitAuthority(authority, "80")
	rawURL := r.URL.String()

	if err := p.intercept.capture.Ready(); err != nil {
		writeCaptureFailure(w, err)
		return
	}
	out, reqRec := p.upstreamRequest(r.Context(), r, scheme, authority)
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		if errors.Is(err, ErrNotAllowed) {
			p.deny(w, nil, p.intercept.denied(start, r.Method, rawURL, host, scheme, err))
			return
		}
		writeProxyError(w, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	removeHopHeaders(resp.Header)

	limit := p.intercept.capture.keepLimit()
	respRec := newBodyRecorder(resp.Body, limit)
	small, err := readUpTo(respRec, limit)
	if err != nil {
		writeProxyError(w, err)
		return
	}
	ex := p.intercept.exchange(start, r.Method, rawURL, host, scheme, headersOf(r.Header), requestBody(reqRec), resp, respRec)

	if !small {
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respRec.keptBytes())
		_, _ = io.Copy(w, respRec)
		_, _ = p.intercept.capture.Write(ex)
		return
	}
	if _, err := p.intercept.capture.Write(ex); err != nil {
		writeCaptureFailure(w, err)
		return
	}
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respRec.keptBytes())
}

// Replay re-sends a captured exchange with the overrides the caller names and
// records the traffic it produces (§4.6). An unknown id, an elided body, or a
// destination outside the pinned scope is a named error, never a synthesized
// request.
func (p *EgressProxy) Replay(ctx context.Context, req ReplayRequest) (ReplayResult, error) {
	if p.intercept == nil {
		return ReplayResult{}, errors.New("containerlayer: replay needs an interception proxy")
	}
	if err := p.intercept.capture.Ready(); err != nil {
		return ReplayResult{}, err
	}
	src, err := p.intercept.capture.raw(req.ID)
	if err != nil {
		return ReplayResult{}, err
	}
	method := src.Method
	if req.Method != "" {
		method = req.Method
	}
	rawURL := src.URL
	if req.URL != "" {
		rawURL = req.URL
	}
	headers := src.RequestHeaders
	if strings.TrimSpace(req.HeadersJSON) != "" {
		headers, err = decodeReplayHeaders(req.HeadersJSON)
		if err != nil {
			return ReplayResult{}, err
		}
	}

	var body []byte
	switch {
	case req.Body != "":
		body = []byte(req.Body)
	case src.RequestBody.Elided:
		return ReplayResult{}, fmt.Errorf("%w: exchange %q kept no body (%d bytes); send one explicitly", ErrBodyElided, src.ID, src.RequestBody.Size)
	default:
		body, err = base64.StdEncoding.DecodeString(src.RequestBody.Data)
		if err != nil {
			return ReplayResult{}, fmt.Errorf("containerlayer: decode captured body of %q: %w", src.ID, err)
		}
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return ReplayResult{}, fmt.Errorf("containerlayer: replay url %q: %w", rawURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ReplayResult{}, fmt.Errorf("containerlayer: replay url %q is not an absolute http(s) URL", rawURL)
	}

	out := &http.Request{
		Method:        method,
		URL:           u,
		Host:          u.Host,
		Header:        headerOf(headers),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: int64(len(body)),
		Body:          http.NoBody,
	}
	removeHopHeaders(out.Header)
	out.Header.Del("Content-Length")
	if len(body) > 0 {
		out.Body = io.NopCloser(bytes.NewReader(body))
	}

	start := p.now()
	resp, err := p.transport.RoundTrip(out.WithContext(ctx))
	if err != nil {
		if errors.Is(err, ErrNotAllowed) {
			denied := p.intercept.denied(start, method, rawURL, u.Hostname(), u.Scheme, err)
			denied.ReplayOf = src.ID
			_, _ = p.intercept.capture.Write(denied)
			return ReplayResult{}, fmt.Errorf("%w: replay %q to %s", ErrNotAllowed, src.ID, u.Host)
		}
		return ReplayResult{}, fmt.Errorf("containerlayer: replay %q: %w", src.ID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	removeHopHeaders(resp.Header)

	limit := p.intercept.capture.keepLimit()
	respRec := newBodyRecorder(resp.Body, limit)
	small, err := readUpTo(respRec, limit)
	if err != nil {
		return ReplayResult{}, fmt.Errorf("containerlayer: read replay response: %w", err)
	}
	if !small {
		if _, err := io.Copy(io.Discard, respRec); err != nil {
			return ReplayResult{}, fmt.Errorf("containerlayer: read replay response: %w", err)
		}
	}
	ex := p.intercept.exchange(start, method, rawURL, u.Hostname(), u.Scheme, headersOf(out.Header), bodyOf(body, p.intercept.capture.bodyMax), resp, respRec)
	ex.ReplayOf = src.ID
	receipt, err := p.intercept.capture.Write(ex)
	if err != nil {
		return ReplayResult{}, err
	}
	view, err := p.intercept.capture.Get(receipt.ID)
	if err != nil {
		return ReplayResult{}, err
	}
	return ReplayResult{Receipt: receipt, Exchange: view}, nil
}

// upstreamRequest clones a proxied request into the harness's own outbound
// request, recording the body it forwards.
func (p *EgressProxy) upstreamRequest(ctx context.Context, req *http.Request, scheme, authority string) (*http.Request, *recordingBody) {
	out := req.Clone(ctx)
	out.RequestURI = ""
	out.URL.Scheme = scheme
	out.URL.Host = authority
	out.Host = authority
	removeHopHeaders(out.Header)
	if req.Body != nil && req.Body != http.NoBody {
		rec := &recordingBody{bodyRecorder: newBodyRecorder(req.Body, p.intercept.capture.keepLimit()), src: req.Body}
		out.Body = rec
		return out, rec
	}
	out.Body = nil
	return out, nil
}

// exchange assembles the record of one exchange.
func (i *interceptor) exchange(start time.Time, method, rawURL, host, scheme string, reqHeaders []Header, reqBody Body, resp *http.Response, respRec *bodyRecorder) Exchange {
	ex := Exchange{
		Time:            start,
		Method:          method,
		URL:             rawURL,
		Host:            host,
		Scheme:          scheme,
		Status:          resp.StatusCode,
		RequestHeaders:  reqHeaders,
		ResponseHeaders: headersOf(resp.Header),
		RequestBody:     reqBody,
		DurationMS:      i.now().Sub(start).Milliseconds(),
	}
	if respRec != nil {
		ex.ResponseBody = respRec.body(i.capture.bodyMax)
	}
	return ex
}

// denied is the record of a request the proxy refused on scope (§4.3).
func (i *interceptor) denied(start time.Time, method, rawURL, host, scheme string, cause error) Exchange {
	return Exchange{
		Time:       start,
		Method:     method,
		URL:        rawURL,
		Host:       host,
		Scheme:     scheme,
		Status:     http.StatusForbidden,
		Denied:     true,
		Reason:     "out-of-scope",
		Detail:     cause.Error(),
		DurationMS: i.now().Sub(start).Milliseconds(),
	}
}

// deny records a refusal in the capture and the audit, then answers it: a 403
// over the connection for a tunnel, a 403 body for a forward. It never
// forwards the request.
func (p *EgressProxy) deny(w http.ResponseWriter, conn net.Conn, ex Exchange) {
	body := proxyDenial{Error: "out-of-scope", Reason: "out-of-scope", Host: ex.Host, Detail: ex.Detail}
	if _, err := p.intercept.capture.Write(ex); err != nil {
		body.Capture = err.Error()
	}
	if err := p.recordEvent(ProxyEvent{Kind: EventScopeDenial, Host: ex.Host, Reason: "out-of-scope", Detail: ex.Detail}); err != nil {
		body.Audit = err.Error()
	}
	if conn != nil {
		writeTunnelJSON(conn, http.StatusForbidden, body)
		return
	}
	writeJSON(w, http.StatusForbidden, body)
}

// requestBody renders the body a proxied request forwarded, zero when it sent
// none.
func requestBody(rec *recordingBody) Body {
	if rec == nil {
		return Body{}
	}
	return rec.body(rec.keepLimit - 1)
}

// bodyOf renders an override body for the record.
func bodyOf(data []byte, limit int64) Body {
	sum := sha256.Sum256(data)
	body := Body{Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
	if int64(len(data)) > limit {
		body.Elided = true
		return body
	}
	body.Encoding = "base64"
	body.Data = base64.StdEncoding.EncodeToString(data)
	return body
}

// decodeReplayHeaders parses the string-carried header object of a replay.
func decodeReplayHeaders(payload string) ([]Header, error) {
	var obj map[string]string
	if err := json.Unmarshal([]byte(payload), &obj); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReplayHeaders, err)
	}
	names := make([]string, 0, len(obj))
	for name := range obj {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Header, 0, len(names))
	for _, name := range names {
		out = append(out, Header{Name: name, Value: obj[name]})
	}
	return out, nil
}

// splitAuthority splits "host:port", tolerating an authority without a port.
func splitAuthority(authority, defaultPort string) (string, string) {
	host, port, err := net.SplitHostPort(authority)
	if err == nil {
		return host, port
	}
	return strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]"), defaultPort
}

// requestTarget is the origin-form target of a request, for the record's URL.
func requestTarget(req *http.Request) string {
	if target := req.URL.RequestURI(); target != "" {
		return target
	}
	return "/"
}

// writeTunnelHead writes a response's status line and headers over a raw
// connection. A response with no known length, or a connection that must not
// be reused, is close-delimited.
func writeTunnelHead(conn net.Conn, resp *http.Response, keep bool) error {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", resp.StatusCode, statusText(resp.StatusCode))
	if !keep {
		b.WriteString("Connection: close\r\n")
	}
	if err := resp.Header.Write(&b); err != nil {
		return err
	}
	b.WriteString("\r\n")
	_, err := io.WriteString(conn, b.String())
	return err
}

// writeTunnelResponse writes a whole response over a raw connection.
func writeTunnelResponse(conn net.Conn, resp *http.Response, keep bool, body []byte) error {
	if err := writeTunnelHead(conn, resp, keep); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	_, err := conn.Write(body)
	return err
}

// writeTunnelFailure answers a tunnel client with a structured proxy failure.
func writeTunnelFailure(conn net.Conn, err error) {
	writeTunnelJSON(conn, http.StatusBadGateway, proxyDenial{Error: "proxy-failure", Detail: err.Error()})
}

// writeTunnelJSON writes one JSON answer over a raw connection.
func writeTunnelJSON(conn net.Conn, status int, payload proxyDenial) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	data = append(data, '\n')
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nX-Styx-Proxy: deny\r\nConnection: close\r\n\r\n%s",
		status, statusText(status), len(data), data)
}

// writeCaptureFailure answers a request the capture refused to record (§8):
// the exchange does not pass uncaptured.
func writeCaptureFailure(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadGateway, proxyDenial{Error: "capture-unavailable", Detail: err.Error()})
}

// writeJSON writes one JSON answer.
func writeJSON(w http.ResponseWriter, status int, payload proxyDenial) {
	data, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Styx-Proxy", "deny")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}

// copyHeader appends src's header fields to dst.
func copyHeader(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

// statusText is a status line's reason phrase.
func statusText(code int) string {
	if text := http.StatusText(code); text != "" {
		return text
	}
	return "Status"
}
