package dnsq

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseServer(t *testing.T) {
	good := map[string]string{
		"192.0.2.53":                              "192.0.2.53:53",
		"2001:db8::1":                             "[2001:db8::1]:53",
		"tls://1.1.1.1":                           "tls://1.1.1.1:853",
		"TLS://dns.example:8853":                  "tls://dns.example:8853",
		"tls://1.1.1.1#cloudflare-dns.com":        "tls://1.1.1.1:853#cloudflare-dns.com",
		"tls://[2001:db8::1]":                     "tls://[2001:db8::1]:853",
		"https://dns.example/dns-query":           "https://dns.example/dns-query",
		"https://192.0.2.1:8443/resolve?x=1":      "https://192.0.2.1:8443/resolve?x=1",
		"https://8.8.8.8/dns-query#dns.google":    "https://8.8.8.8/dns-query#dns.google",
		"  https://cloudflare-dns.com/dns-query ": "https://cloudflare-dns.com/dns-query",
	}
	quic := map[string]string{
		"quic://dns.example":               "quic://dns.example:853",
		"quic://192.0.2.1:784#dns.example": "quic://192.0.2.1:784#dns.example",
	}
	for in, want := range quic {
		if DoQAvailable {
			good[in] = want
		} else if _, err := ParseServer(in); err == nil || !strings.Contains(err.Error(), "-tags doq") {
			t.Errorf("ParseServer(%q) in a build without DoQ: want a rebuild hint, got %v", in, err)
		}
	}
	for in, want := range good {
		if got, err := ParseServer(in); err != nil || got != want {
			t.Errorf("ParseServer(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{":53", "[]", "tls://", "tls://host/path", "ftp://host",
		"https://dns.example", "https://192.0.2.1/dns-query#name:443", "tls://192.0.2.1#a/b", "quic://u@host"} {
		if got, err := ParseServer(in); err == nil {
			t.Errorf("ParseServer(%q) = %q, want error", in, got)
		}
	}
}

func TestPadToBlock(t *testing.T) {
	for _, name := range []string{"a.", "www.example.", strings.Repeat("x", 60) + "." + strings.Repeat("y", 60) + "."} {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		m.SetEdns0(ednsUDPSize, true)
		pad(m)
		wire, err := m.Pack()
		if err != nil || len(wire)%paddingBlock != 0 {
			t.Errorf("%s: padded to %d bytes, %v", name, len(wire), err)
		}
	}
}

// testCert returns a self-signed certificate for names (DNS names or IP
// addresses) and a pool that trusts it.
func testCert(t testing.TB, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dnsquery test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// queryLog records what an encrypted test server received.
type queryLog struct {
	mu      sync.Mutex
	ids     []uint16
	sizes   []int
	padded  []bool
	hosts   []string // DoH: HTTP Host of each request
	conns   atomic.Int32
	answers atomic.Int32
}

// answer replies to req like zoneHandler and records it.
func (l *queryLog) answer(req *dns.Msg, size int) *dns.Msg {
	padded := false
	if opt := req.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			_, ok := o.(*dns.EDNS0_PADDING)
			padded = padded || ok
		}
	}
	l.mu.Lock()
	l.ids, l.sizes, l.padded = append(l.ids, req.Id), append(l.sizes, size), append(l.padded, padded)
	l.mu.Unlock()
	l.answers.Add(1)
	w := &captureWriter{}
	zoneHandler(w, req)
	return w.msg
}

// captureWriter is a dns.ResponseWriter that keeps the reply.
type captureWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (w *captureWriter) RemoteAddr() net.Addr      { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (w *captureWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }

// countingListener counts accepted connections.
type countingListener struct {
	net.Listener
	n *atomic.Int32
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

// startDoT serves DNS over TLS with cert on loopback.
func startDoT(t testing.TB, cert tls.Certificate, log *queryLog) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conf := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"dot"}}
	tl := tls.NewListener(countingListener{l, &log.conns}, conf)
	started := make(chan struct{})
	srv := &dns.Server{Listener: tl, Net: "tcp-tls", NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			wire, _ := req.Pack()
			_ = w.WriteMsg(log.answer(req, len(wire)))
		})}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return l.Addr().String()
}

// startDoH serves DNS over HTTPS at /dns-query.
func startDoH(t testing.TB, cert tls.Certificate, log *queryLog) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req := new(dns.Msg)
		if r.URL.Path != "/dns-query" || r.Method != http.MethodPost ||
			r.Header.Get("Content-Type") != dohMediaType || req.Unpack(body) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if r.ProtoMajor != 2 {
			http.Error(w, "want HTTP/2", http.StatusBadRequest)
			return
		}
		log.mu.Lock()
		log.hosts = append(log.hosts, r.Host)
		log.mu.Unlock()
		wire, _ := log.answer(req, len(body)).Pack()
		w.Header().Set("Content-Type", dohMediaType)
		_, _ = w.Write(wire)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			log.conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

// startDoQ serves DNS over QUIC on loopback; it is nil in builds without
// DoQ (see transport_doq_test.go).
var startDoQ func(testing.TB, tls.Certificate, *queryLog) string

func TestEncryptedTransports(t *testing.T) {
	cert, pool := testCert(t, "127.0.0.1")
	cases := []struct {
		proto  string
		start  func(testing.TB, tls.Certificate, *queryLog) string
		server func(addr string) string
		zeroID bool
	}{
		{ProtoTLS, startDoT, func(a string) string { return "tls://" + a }, false},
		{ProtoHTTPS, startDoH, func(u string) string { return u + "/dns-query" }, true},
	}
	if startDoQ != nil {
		cases = append(cases, struct {
			proto  string
			start  func(testing.TB, tls.Certificate, *queryLog) string
			server func(addr string) string
			zeroID bool
		}{ProtoQUIC, startDoQ, func(a string) string { return "quic://" + a }, true})
	}
	for _, tc := range cases {
		t.Run(tc.proto, func(t *testing.T) {
			log := &queryLog{}
			server, err := ParseServer(tc.server(tc.start(t, cert, log)))
			if err != nil {
				t.Fatal(err)
			}
			r := &Resolver{Servers: []string{server}, Timeout: 2 * time.Second, TLSConfig: &tls.Config{RootCAs: pool}}
			t.Cleanup(r.Close)
			ctx := context.Background()

			rows := r.Lookup(ctx, "www.example", dns.TypeA, false)
			if got := rows[0]; got.Status != StatusNoError || got.Value != "192.0.2.1" || got.Protocol != tc.proto || got.Server != server {
				t.Fatalf("got status=%s value=%q proto=%s server=%s err=%s", got.Status, got.Value, got.Protocol, got.Server, got.Error)
			}
			if got := r.Lookup(ctx, "nope.example", dns.TypeA, false)[0]; got.Status != "NXDOMAIN" {
				t.Errorf("nope.example: %s %s", got.Status, got.Error)
			}
			if n := log.conns.Load(); n != 1 {
				t.Errorf("%d connections for 2 queries in a row, want 1", n)
			}
			// Concurrent queries share the connection or the pool.
			var wg sync.WaitGroup
			for i := range 20 {
				wg.Go(func() {
					name := "www.example"
					if i%2 == 1 {
						name = "example"
					}
					if got := r.Lookup(ctx, name, dns.TypeSOA, false)[0]; got.Status == StatusError {
						t.Errorf("%s: %s", name, got.Error)
					}
				})
			}
			wg.Wait()

			log.mu.Lock()
			defer log.mu.Unlock()
			for i := range log.ids {
				if log.sizes[i]%paddingBlock != 0 || !log.padded[i] {
					t.Errorf("query %d: %d bytes, padding %v; want padded to %d", i, log.sizes[i], log.padded[i], paddingBlock)
				}
				if tc.zeroID && log.ids[i] != 0 {
					t.Errorf("query %d: ID %d, want 0", i, log.ids[i])
				}
			}
			if n := log.conns.Load(); n < 1 || n > dotMaxIdle+1 && tc.proto == ProtoTLS || n > 1 && tc.proto != ProtoTLS {
				t.Errorf("%d connections for %d queries", n, len(log.ids))
			}
		})
	}
}

func TestEncryptedCertificateChecks(t *testing.T) {
	// The certificate names dns.test only, not the address.
	cert, pool := testCert(t, "dns.test")
	dot := startDoT(t, cert, &queryLog{})
	dohLog := &queryLog{}
	doh := startDoH(t, cert, dohLog) + "/dns-query"
	cases := []struct{ server, want string }{
		{"tls://" + dot, "certificate"},
		{doh, "certificate"},
		{"tls://" + dot + "#dns.test", ""},
		{doh + "#dns.test", ""},
		{"tls://" + dot + "#other.test", "certificate"},
		{doh + "#other.test", "certificate"},
	}
	if startDoQ != nil {
		doq := startDoQ(t, cert, &queryLog{})
		cases = append(cases, []struct{ server, want string }{
			{"quic://" + doq, "certificate"},
			{"quic://" + doq + "#dns.test", ""},
			{"quic://" + doq + "#other.test", "certificate"},
		}...)
	}
	for _, tc := range cases {
		server, err := ParseServer(tc.server)
		if err != nil {
			t.Fatal(err)
		}
		r := &Resolver{Servers: []string{server}, Timeout: 2 * time.Second, TLSConfig: &tls.Config{RootCAs: pool}}
		got := r.Lookup(context.Background(), "www.example", dns.TypeA, false)[0]
		r.Close()
		if tc.want == "" && got.Status != StatusNoError || tc.want != "" && !strings.Contains(got.Error, tc.want) {
			t.Errorf("%s: status %s, error %q; want error containing %q", tc.server, got.Status, got.Error, tc.want)
		}
	}
	// The DoH request names the server, not the address it went to.
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimSuffix(doh, "/dns-query"), "https://"))
	dohLog.mu.Lock()
	if want := "dns.test:" + port; len(dohLog.hosts) != 1 || dohLog.hosts[0] != want {
		t.Errorf("DoH Host headers %q, want [%s]", dohLog.hosts, want)
	}
	dohLog.mu.Unlock()
	// Without the test CA, the system roots reject the certificate.
	server, _ := ParseServer("tls://" + dot + "#dns.test")
	r := &Resolver{Servers: []string{server}, Timeout: 2 * time.Second}
	defer r.Close()
	if got := r.Lookup(context.Background(), "www.example", dns.TypeA, false)[0]; got.Status != StatusError {
		t.Errorf("untrusted certificate accepted: %s", got.Status)
	}
}

// TestDoTReconnectsAfterIdleClose checks that a pooled connection the
// server has closed is replaced instead of failing the query.
func TestDoTReconnectsAfterIdleClose(t *testing.T) {
	cert, pool := testCert(t, "127.0.0.1")
	log := &queryLog{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	tl := tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			log.conns.Add(1)
			// Answer one query, then close, as a server with a short
			// idle timeout would.
			go func() {
				defer func() { _ = c.Close() }()
				dc := &dns.Conn{Conn: c}
				req, err := dc.ReadMsg()
				if err != nil {
					return
				}
				_ = dc.WriteMsg(log.answer(req, 0))
			}()
		}
	}()
	server, _ := ParseServer("tls://" + l.Addr().String())
	r := &Resolver{Servers: []string{server}, Timeout: 2 * time.Second, TLSConfig: &tls.Config{RootCAs: pool}}
	defer r.Close()
	for i := range 3 {
		if got := r.Lookup(context.Background(), "www.example", dns.TypeAAAA, false)[0]; got.Status != StatusNoData {
			t.Fatalf("query %d: %s %s", i, got.Status, got.Error)
		}
		time.Sleep(20 * time.Millisecond) // let the close arrive
	}
	if n := log.conns.Load(); n != 3 {
		t.Errorf("%d connections, want 3", n)
	}
}

func TestEncryptedTimeoutIsRetried(t *testing.T) {
	cert, pool := testCert(t, "127.0.0.1")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var conns atomic.Int32
	tl := tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() { _, _ = io.Copy(io.Discard, c) }() // never answers
		}
	}()
	server, _ := ParseServer("tls://" + l.Addr().String())
	var trace strings.Builder
	r := &Resolver{Servers: []string{server}, Timeout: 100 * time.Millisecond, Retries: 1,
		TLSConfig: &tls.Config{RootCAs: pool}, Trace: NewTracer(&trace)}
	defer r.Close()
	got := r.Lookup(context.Background(), "www.example", dns.TypeA, false)[0]
	if got.Status != StatusError || !strings.Contains(trace.String(), "retry 1 of 1") {
		t.Errorf("status %s, error %q; trace:\n%s", got.Status, got.Error, trace.String())
	}
}

func TestDoHHTTPErrors(t *testing.T) {
	cert, pool := testCert(t, "127.0.0.1")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/text":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()
	for path, want := range map[string]string{"/missing": "HTTP 404", "/text": "content type"} {
		r := &Resolver{Servers: []string{srv.URL + path}, Timeout: time.Second, TLSConfig: &tls.Config{RootCAs: pool}}
		got := r.Lookup(context.Background(), "www.example", dns.TypeA, false)[0]
		r.Close()
		if got.Status != StatusError || !strings.Contains(got.Error, want) {
			t.Errorf("%s: status %s, error %q; want %q", path, got.Status, got.Error, want)
		}
	}
}

// TestDoTDropsLongIdleConnections checks that a connection unused for
// longer than the idle timeout is not reused: a firewall may have
// forgotten it, and a query on it would wait for the whole timeout.
func TestDoTDropsLongIdleConnections(t *testing.T) {
	cert, pool := testCert(t, "127.0.0.1")
	log := &queryLog{}
	server, _ := ParseServer("tls://" + startDoT(t, cert, log))
	r := &Resolver{Servers: []string{server}, Timeout: 2 * time.Second, TLSConfig: &tls.Config{RootCAs: pool}}
	defer r.Close()
	_, tr, err := r.transportFor(server)
	if err != nil {
		t.Fatal(err)
	}
	tr.(*dotTransport).idleTimeout = 100 * time.Millisecond
	ctx := context.Background()
	for i, name := range []string{"www.example", "example", "nope.example"} {
		if i == 2 {
			time.Sleep(150 * time.Millisecond)
		}
		if got := r.Lookup(ctx, name, dns.TypeA, false)[0]; got.Status == StatusError {
			t.Fatalf("%s: %s", name, got.Error)
		}
	}
	// The second query reuses the first connection; the third comes
	// after the idle timeout and needs a new one.
	if n := log.conns.Load(); n != 2 {
		t.Errorf("%d connections, want 2", n)
	}
}
