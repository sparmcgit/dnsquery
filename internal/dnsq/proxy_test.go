package dnsq

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseProxy(t *testing.T) {
	for raw, want := range map[string]string{
		"":                             "",
		"http://127.0.0.1:8080":        "http://127.0.0.1:8080",
		" SOCKS5://127.0.0.1:9050 ":    "socks5://127.0.0.1:9050",
		"https://user:pw@proxy.test":   "https://user:pw@proxy.test",
		"ftp://127.0.0.1":              "error",
		"127.0.0.1:8080":               "error",
		"socks5://":                    "error",
		"http://[::1":                  "error",
		"socks4://127.0.0.1:1080":      "error",
		"http://proxy.test:3128/path/": "http://proxy.test:3128/path/",
	} {
		u, err := ParseProxy(raw)
		got := "error"
		switch {
		case err == nil && u == nil:
			got = ""
		case err == nil:
			got = u.String()
		}
		if got != want {
			t.Errorf("ParseProxy(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for raw, want := range map[string]string{
		"http://p.test":        "p.test:80",
		"https://p.test":       "p.test:443",
		"socks5://[::1]":       "[::1]:1080",
		"socks5://p.test:9050": "p.test:9050",
	} {
		u, _ := ParseProxy(raw)
		if got := proxyAddr(u); got != want {
			t.Errorf("proxyAddr(%s) = %s, want %s", raw, got, want)
		}
	}
}

// proxyLog records the targets a test proxy was asked to connect to.
type proxyLog struct {
	mu      sync.Mutex
	targets []string
}

func (l *proxyLog) add(target string) {
	l.mu.Lock()
	l.targets = append(l.targets, target)
	l.mu.Unlock()
}

func (l *proxyLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.targets...)
}

// pipe copies between a and b until either side closes.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	_ = a.Close()
	_ = b.Close()
}

// startSOCKS5 runs a SOCKS5 proxy (RFC 1928) on loopback; with user set it
// requires that user and password (RFC 1929).
func startSOCKS5(t testing.TB, user, password string, log *proxyLog) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				if err := serveSOCKS5(c, user, password, log); err != nil {
					_ = c.Close()
				}
			}()
		}
	}()
	return l.Addr().String()
}

func serveSOCKS5(c net.Conn, user, password string, log *proxyLog) error {
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, buf[:buf[1]]); err != nil {
		return err
	}
	method := byte(0x00)
	if user != "" {
		method = 0x02
	}
	if _, err := c.Write([]byte{5, method}); err != nil {
		return err
	}
	if user != "" {
		if _, err := io.ReadFull(c, buf[:2]); err != nil {
			return err
		}
		u := make([]byte, buf[1])
		if _, err := io.ReadFull(c, u); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return err
		}
		p := make([]byte, buf[0])
		if _, err := io.ReadFull(c, p); err != nil {
			return err
		}
		if string(u) != user || string(p) != password {
			_, _ = c.Write([]byte{1, 1})
			return errors.New("bad credentials")
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return err
		}
	}
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return err
	}
	var host string
	switch buf[3] {
	case 1:
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return err
		}
		host = net.IP(buf[:4]).String()
	case 3:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return err
		}
		n := int(buf[0])
		if _, err := io.ReadFull(c, buf[:n]); err != nil {
			return err
		}
		host = string(buf[:n])
	case 4:
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return err
		}
		host = net.IP(buf[:16]).String()
	default:
		return errors.New("bad address type")
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return err
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(buf[:2]))))
	log.add(target)
	up, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		_ = up.Close()
		return err
	}
	pipe(c, up)
	return nil
}

// startHTTPProxy runs an HTTP CONNECT proxy on loopback, over TLS with
// cert when it is not nil. With auth set, it requires that
// Proxy-Authorization value.
func startHTTPProxy(t testing.TB, cert *tls.Certificate, auth string, log *proxyLog) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		if auth != "" && r.Header.Get("Proxy-Authorization") != auth {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		log.add(r.Host)
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		c, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			_ = up.Close()
			_ = c.Close()
			return
		}
		pipe(c, up)
	}))
	if cert != nil {
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestProxy(t *testing.T) {
	// The certificate names the loopback address (the proxy, DoT) and
	// dns.test (DoH via #tls-name).
	cert, pool := testCert(t, "127.0.0.1", "dns.test")
	plain := startServer(t, zoneHandler)
	dot := startDoT(t, cert, &queryLog{})
	doh := startDoH(t, cert, &queryLog{})
	dohAddr := strings.TrimPrefix(doh, "https://")
	servers := []string{plain, "tls://" + dot, doh + "/dns-query#dns.test"}
	// What each server makes the proxy connect to.
	targets := []string{plain, dot, dohAddr}

	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	proxies := map[string]func(*proxyLog) string{
		"socks5": func(l *proxyLog) string { return "socks5://" + startSOCKS5(t, "", "", l) },
		"socks5 auth": func(l *proxyLog) string {
			return "socks5://alice:s3cret@" + startSOCKS5(t, "alice", "s3cret", l)
		},
		"http auth": func(l *proxyLog) string {
			return strings.Replace(startHTTPProxy(t, nil, basic, l), "http://", "http://alice:s3cret@", 1)
		},
		"https": func(l *proxyLog) string { return startHTTPProxy(t, &cert, "", l) },
	}
	for name, start := range proxies {
		t.Run(name, func(t *testing.T) {
			log := &proxyLog{}
			p, err := ParseProxy(start(log))
			if err != nil {
				t.Fatal(err)
			}
			for i, raw := range servers {
				server, err := ParseServer(raw)
				if err != nil {
					t.Fatal(err)
				}
				r := &Resolver{Servers: []string{server}, Proxy: p, Timeout: 2 * time.Second, TLSConfig: &tls.Config{RootCAs: pool}}
				rows := r.Lookup(context.Background(), "www.example", dns.TypeA, false)
				r.Close()
				if got := rows[0]; got.Status != StatusNoError || got.Value != "192.0.2.1" {
					t.Fatalf("%s: status=%s value=%q err=%s", server, got.Status, got.Value, got.Error)
				}
				if i == 0 && rows[0].Protocol != "tcp" {
					t.Errorf("plain server through proxy: protocol %s, want tcp", rows[0].Protocol)
				}
				if got := log.all(); len(got) == 0 || got[len(got)-1] != targets[i] {
					t.Errorf("%s: proxy connected to %v, want %s", server, got, targets[i])
				}
			}
		})
	}
}

// hangingTCP accepts TCP connections and never answers.
func hangingTCP(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	return l.Addr().String()
}

func TestProxyFailures(t *testing.T) {
	plain := startServer(t, zoneHandler)
	log := &proxyLog{}
	httpProxy := startHTTPProxy(t, nil, "Basic xyz", log)
	socks := startSOCKS5(t, "alice", "s3cret", log)
	for raw, want := range map[string]string{
		httpProxy:                                "407",
		"socks5://alice:wrong@" + socks:          "socks",
		"http://" + closedPort(t):                "refused",
		"socks5://alice:s3cret@" + closedPort(t): "refused",
		"socks5://alice:s3cret@" + hangingTCP(t): "deadline",
		"http://" + hangingTCP(t):                "deadline",
	} {
		p, err := ParseProxy(raw)
		if err != nil {
			t.Fatal(err)
		}
		r := &Resolver{Servers: []string{plain}, Proxy: p, Timeout: 300 * time.Millisecond}
		got := r.Lookup(context.Background(), "www.example", dns.TypeA, false)[0]
		if got.Status != StatusError || !strings.Contains(got.Error, want) {
			t.Errorf("%s: status=%s err=%q, want error with %q", raw, got.Status, got.Error, want)
		}
	}
	if len(log.all()) != 0 {
		t.Errorf("proxy connected without valid credentials: %v", log.all())
	}
}

func TestProxyRejectsQUIC(t *testing.T) {
	if err := ProxyCompatible("quic://192.0.2.1:853"); err == nil {
		t.Error("quic:// server accepted with a proxy")
	}
	for _, s := range []string{"192.0.2.1:53", "tls://192.0.2.1:853", "https://192.0.2.1/dns-query"} {
		if err := ProxyCompatible(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	p, _ := url.Parse("socks5://127.0.0.1:1080")
	r := &Resolver{Proxy: p}
	if _, _, err := r.transportFor("quic://192.0.2.1:853"); !errors.Is(err, errProxyQUIC) {
		t.Errorf("transportFor quic:// with proxy: %v", err)
	}
}
