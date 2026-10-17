package dnsq

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// ParseProxy checks a --proxy URL: http://, https:// or socks5://
// host[:port], optionally with user:password@. It returns nil for "".
func ParseProxy(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid --proxy value %q: %w", raw, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid --proxy value %q (expected scheme://host[:port])", raw)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	switch parsed.Scheme {
	case "http", "https", "socks5":
	default:
		return nil, fmt.Errorf("invalid --proxy scheme %q (expected http, https, or socks5)", parsed.Scheme)
	}
	return parsed, nil
}

// proxyAddr is the proxy's host:port, with the scheme's default port as
// net/http uses them.
func proxyAddr(p *url.URL) string {
	if p.Port() != "" {
		return p.Host
	}
	port := map[string]string{"http": "80", "https": "443", "socks5": "1080"}[p.Scheme]
	return net.JoinHostPort(p.Hostname(), port)
}

// dial opens a TCP connection to addr, through r.Proxy when set. Every
// stream transport dials with it; the target host name, if any, is sent
// to the proxy unresolved.
func (r *Resolver) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{}
	if r.Proxy == nil {
		return d.DialContext(ctx, network, addr)
	}
	if r.Proxy.Scheme == "socks5" {
		var auth *proxy.Auth
		if u := r.Proxy.User; u != nil {
			pw, _ := u.Password()
			auth = &proxy.Auth{User: u.Username(), Password: pw}
		}
		s, err := proxy.SOCKS5("tcp", proxyAddr(r.Proxy), auth, d)
		if err != nil {
			return nil, err
		}
		return s.(proxy.ContextDialer).DialContext(ctx, network, addr)
	}
	return r.dialConnect(ctx, d, addr)
}

// dialConnect opens a tunnel to addr with HTTP CONNECT (RFC 9110 section
// 9.3.6), over TLS to an https:// proxy.
func (r *Resolver) dialConnect(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
	p := r.Proxy
	conn, err := d.DialContext(ctx, "tcp", proxyAddr(p))
	if err != nil {
		return nil, err
	}
	if p.Scheme == "https" {
		conf := &tls.Config{MinVersion: tls.VersionTLS12}
		if r.TLSConfig != nil {
			conf = r.TLSConfig.Clone()
		}
		conf.ServerName, conf.NextProtos = p.Hostname(), nil
		tc := tls.Client(conn, conf)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("proxy %s: %w", p.Host, ctxErr(ctx, err))
		}
		conn = tc
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: http.Header{}}
	if u := p.User; u != nil {
		pw, _ := u.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)))
	}
	br := bufio.NewReader(conn)
	err = req.Write(conn)
	var res *http.Response
	if err == nil {
		res, err = http.ReadResponse(br, req)
	}
	if !stop() || err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy %s: CONNECT %s: %w", p.Host, addr, ctxErr(ctx, err))
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy %s: CONNECT %s: %s", p.Host, addr, res.Status)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if br.Buffered() > 0 {
		return &bufferedConn{conn, br}, nil
	}
	return conn, nil
}

// bufferedConn reads first what was read past the CONNECT response.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
