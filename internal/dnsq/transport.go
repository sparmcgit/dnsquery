package dnsq

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Encrypted transports, chosen by the scheme of a server address.
const (
	ProtoTLS   = "tls"   // DNS over TLS, RFC 7858
	ProtoHTTPS = "https" // DNS over HTTPS, RFC 8484
	ProtoQUIC  = "quic"  // DNS over QUIC, RFC 9250
)

// paddingBlock is the block size encrypted queries are padded to, as
// RFC 8467 section 4.1 recommends, so their length reveals less.
const paddingBlock = 128

// maxStreamMsg is the largest DNS message on a stream transport: the
// two-byte length prefix of RFC 1035 section 4.2.2 (and RFC 9250).
const maxStreamMsg = 65535

// ParseServer normalizes a server address. Plain DNS is ip[:port] (port
// 53; bare IPv6 addresses are accepted without brackets). Encrypted
// transports use a URL:
//
//	tls://host[:port][#tls-name]         DNS over TLS (port 853)
//	https://host[:port]/path[#tls-name]  DNS over HTTPS (port 443)
//	quic://host[:port][#tls-name]        DNS over QUIC (port 853, needs -tags doq)
//
// host may be a name or an IP address. #tls-name sets the server name:
// the certificate is checked against it (and, for https, it is the HTTP
// host) while the connection goes to host, so with an IP address as host
// no name lookup is needed.
func ParseServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		if host, port, err := net.SplitHostPort(s); err == nil {
			if host == "" {
				return "", fmt.Errorf("invalid server %q", s)
			}
			return net.JoinHostPort(host, port), nil
		}
		if strings.Trim(s, "[]") == "" {
			return "", fmt.Errorf("invalid server %q", s)
		}
		return net.JoinHostPort(strings.Trim(s, "[]"), "53"), nil
	}
	u, err := url.Parse(strings.ToLower(scheme) + "://" + rest)
	if err != nil {
		return "", fmt.Errorf("invalid server %q: %v", s, err)
	}
	if u.Hostname() == "" || u.User != nil {
		return "", fmt.Errorf("invalid server %q: no host", s)
	}
	if strings.ContainsAny(u.Fragment, ":/@?[]# ") {
		return "", fmt.Errorf("invalid server %q: #tls-name must be a host name", s)
	}
	switch u.Scheme {
	case ProtoHTTPS:
		if u.Path == "" {
			return "", fmt.Errorf("invalid server %q: no path; DoH servers usually use /dns-query", s)
		}
		return u.String(), nil
	case ProtoTLS, ProtoQUIC:
		if u.Scheme == ProtoQUIC && !DoQAvailable {
			return "", fmt.Errorf("invalid server %q: DNS over QUIC is not included in this build; rebuild with -tags doq (TAGS=doq ./compile)", s)
		}
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return "", fmt.Errorf("invalid server %q: %s:// takes no path or query", s, u.Scheme)
		}
		port := u.Port()
		if port == "" {
			port = "853"
		}
		out := u.Scheme + "://" + net.JoinHostPort(u.Hostname(), port)
		if u.Fragment != "" {
			out += "#" + u.Fragment
		}
		return out, nil
	default:
		return "", fmt.Errorf("invalid server %q: unknown scheme %q (use tls://, https:// or quic://, or ip[:port] for plain DNS)", s, scheme)
	}
}

// transport sends one query over an encrypted connection.
type transport interface {
	exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
	close()
}

// transportFor returns the protocol of server and, for an encrypted
// server, its transport. Transports are created once per server, so
// connections are reused across queries.
func (r *Resolver) transportFor(server string) (string, transport, error) {
	scheme, _, ok := strings.Cut(server, "://")
	if !ok {
		if r.TCP {
			return "tcp", nil, nil
		}
		return "udp", nil, nil
	}
	r.transportsMu.Lock()
	defer r.transportsMu.Unlock()
	if t, ok := r.transports[server]; ok {
		return scheme, t, nil
	}
	u, err := url.Parse(server)
	if err != nil {
		return "", nil, err
	}
	conf := &tls.Config{MinVersion: tls.VersionTLS12}
	if r.TLSConfig != nil {
		conf = r.TLSConfig.Clone()
	}
	conf.ServerName = u.Hostname()
	if u.Fragment != "" {
		conf.ServerName = u.Fragment
	}
	var t transport
	switch u.Scheme {
	case ProtoTLS:
		conf.NextProtos = []string{"dot"} // RFC 7858, ALPN registered by RFC 8310
		t = &dotTransport{addr: u.Host, conf: conf}
	case ProtoHTTPS:
		t = newDoHTransport(u, conf)
	case ProtoQUIC:
		conf.NextProtos = []string{"doq"} // RFC 9250 section 4.1.1
		conf.MinVersion = tls.VersionTLS13
		if t, err = newDoQTransport(u.Host, conf); err != nil {
			return "", nil, err
		}
	default:
		return "", nil, fmt.Errorf("unknown transport %q", u.Scheme)
	}
	if r.transports == nil {
		r.transports = map[string]transport{}
	}
	r.transports[server] = t
	return u.Scheme, t, nil
}

// Close closes the connections kept open to encrypted servers.
func (r *Resolver) Close() {
	r.transportsMu.Lock()
	defer r.transportsMu.Unlock()
	for _, t := range r.transports {
		t.close()
	}
	r.transports = nil
}

// pad adds an EDNS(0) Padding option (RFC 7830) so the packed query is a
// multiple of paddingBlock bytes (RFC 8467 section 4.1). m must have EDNS.
func pad(m *dns.Msg) {
	opt := m.IsEdns0()
	p := &dns.EDNS0_PADDING{}
	opt.Option = append(opt.Option, p)
	if n := m.Len() % paddingBlock; n != 0 {
		p.Padding = make([]byte, paddingBlock-n)
	}
}

// exchangeStream writes m with its two-byte length prefix on conn and
// reads the reply, both bounded by ctx.
func exchangeStream(ctx context.Context, rw io.ReadWriter, setDeadline func(time.Time) error, m *dns.Msg) (*dns.Msg, error) {
	if d, ok := ctx.Deadline(); ok {
		if err := setDeadline(d); err != nil {
			return nil, err
		}
	}
	// Unblock reads and writes when ctx is cancelled.
	stop := context.AfterFunc(ctx, func() { _ = setDeadline(time.Now()) })
	defer stop()
	wire, err := m.Pack()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(buf, uint16(len(wire)))
	copy(buf[2:], wire)
	if _, err := rw.Write(buf); err != nil {
		return nil, ctxErr(ctx, err)
	}
	if _, err := io.ReadFull(rw, buf[:2]); err != nil {
		return nil, ctxErr(ctx, err)
	}
	reply := make([]byte, binary.BigEndian.Uint16(buf))
	if _, err := io.ReadFull(rw, reply); err != nil {
		return nil, ctxErr(ctx, err)
	}
	return unpackReply(reply, m)
}

// ctxErr prefers ctx's error, so a deadline shows as a timeout and a
// cancellation as such, over the I/O error it caused.
func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// unpackReply parses a reply and checks that it answers m.
func unpackReply(b []byte, m *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg)
	if err := resp.Unpack(b); err != nil {
		return nil, err
	}
	if resp.Id != m.Id {
		return nil, fmt.Errorf("response ID %d does not match query ID %d", resp.Id, m.Id)
	}
	return resp, nil
}

// dotTransport is DNS over TLS (RFC 7858): one query at a time per
// connection, with idle connections kept for the next query (section 3.4).
type dotTransport struct {
	addr string
	conf *tls.Config

	// idleTimeout is how long an unused connection is kept; 0 means
	// dotIdleTimeout.
	idleTimeout time.Duration

	mu   sync.Mutex
	idle []idleConn // oldest first
}

type idleConn struct {
	conn  *tls.Conn
	since time.Time
}

const (
	// dotMaxIdle bounds the idle connections kept per server.
	dotMaxIdle = 8
	// dotIdleTimeout drops connections unused this long. A firewall or NAT
	// may forget an idle connection without telling either end; the next
	// query on it would then wait for the whole --timeout.
	dotIdleTimeout = 20 * time.Second
)

func (t *dotTransport) exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	for {
		conn, reused := t.get()
		if conn == nil {
			d := tls.Dialer{Config: t.conf}
			c, err := d.DialContext(ctx, "tcp", t.addr)
			if err != nil {
				return nil, ctxErr(ctx, err)
			}
			conn = c.(*tls.Conn)
		}
		resp, err := exchangeStream(ctx, conn, conn.SetDeadline, m)
		if err == nil && ctx.Err() == nil && conn.SetDeadline(time.Time{}) == nil {
			t.put(conn)
			return resp, nil
		}
		_ = conn.Close()
		// The server may have closed an idle connection (RFC 7858
		// section 3.4): try again on a new one.
		if reused && err != nil && ctx.Err() == nil {
			continue
		}
		return resp, err
	}
}

// get returns the most recently used idle connection, after closing
// those idle for longer than the idle timeout.
func (t *dotTransport) get() (*tls.Conn, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	timeout := t.idleTimeout
	if timeout == 0 {
		timeout = dotIdleTimeout
	}
	expired := 0
	for expired < len(t.idle) && time.Since(t.idle[expired].since) > timeout {
		_ = t.idle[expired].conn.Close()
		expired++
	}
	t.idle = t.idle[expired:]
	if n := len(t.idle); n > 0 {
		c := t.idle[n-1].conn
		t.idle = t.idle[:n-1]
		return c, true
	}
	return nil, false
}

func (t *dotTransport) put(c *tls.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.idle) >= dotMaxIdle {
		_ = c.Close()
		return
	}
	t.idle = append(t.idle, idleConn{c, time.Now()})
}

func (t *dotTransport) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range t.idle {
		_ = c.conn.Close()
	}
	t.idle = nil
}

// dohTransport is DNS over HTTPS (RFC 8484), with POST requests over a
// shared HTTP/2 connection.
type dohTransport struct {
	url    string
	client *http.Client
}

const dohMediaType = "application/dns-message"

// newDoHTransport sends requests to u. With #tls-name, requests go to
// https://tls-name/path over connections to u's host, the way a browser
// would reach tls-name had it resolved to that address.
func newDoHTransport(u *url.URL, conf *tls.Config) *dohTransport {
	req := *u
	req.Fragment = ""
	d := &net.Dialer{}
	dial := d.DialContext
	if u.Fragment != "" {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		addr := net.JoinHostPort(u.Hostname(), port)
		dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}
		req.Host = u.Fragment
		if u.Port() != "" {
			req.Host = net.JoinHostPort(u.Fragment, u.Port())
		}
	}
	tr := &http.Transport{
		// Connect directly: a proxy would change which resolver is measured.
		Proxy:               nil,
		DialContext:         dial,
		TLSClientConfig:     conf,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: dotMaxIdle,
		IdleConnTimeout:     30 * time.Second,
	}
	return &dohTransport{url: req.String(), client: &http.Client{Transport: tr}}
}

func (t *dohTransport) exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	wire, err := m.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dohMediaType)
	req.Header.Set("Accept", dohMediaType)
	res, err := t.client.Do(req)
	if err != nil {
		return nil, ctxErr(ctx, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s from %s", res.Status, t.url)
	}
	if mt, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type")); mt != dohMediaType {
		return nil, fmt.Errorf("unexpected content type %q from %s", res.Header.Get("Content-Type"), t.url)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxStreamMsg+1))
	if err != nil {
		return nil, ctxErr(ctx, err)
	}
	if len(body) > maxStreamMsg {
		return nil, fmt.Errorf("response from %s larger than %d bytes", t.url, maxStreamMsg)
	}
	return unpackReply(body, m)
}

func (t *dohTransport) close() { t.client.CloseIdleConnections() }
