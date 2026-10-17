package dnsq

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

// startServer runs handler on UDP and TCP on the same loopback port.
func startServer(t testing.TB, handler dns.HandlerFunc) string {
	t.Helper()
	// The TCP port matching a free UDP port may be taken; try a few.
	var pc net.PacketConn
	var l net.Listener
	var err error
	for range 20 {
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if l, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			break
		}
		_ = pc.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	udp := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: wg.Done}
	tcp := &dns.Server{Listener: l, Handler: handler, NotifyStartedFunc: wg.Done}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	wg.Wait()
	t.Cleanup(func() { _ = udp.Shutdown(); _ = tcp.Shutdown() })
	return pc.LocalAddr().String()
}

func soa(zone string, ttl, minttl uint32) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:  "ns1." + zone, Mbox: "hostmaster." + zone, Serial: 42, Minttl: minttl,
	}
}

func zoneHandler(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	q := req.Question[0]
	isUDP := w.RemoteAddr().Network() == "udp"
	switch {
	case q.Name == "big.example.":
		if isUDP {
			m.Truncated = true
		} else {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 9)})
		}
	case q.Name == "noedns.example." && req.IsEdns0() != nil:
		m.Rcode = dns.RcodeFormatError
	case q.Name == "example." && q.Qtype == dns.TypeSOA:
		m.Answer = append(m.Answer, soa("example.", 3600, 300))
	case q.Name == "www.example.", q.Name == "noedns.example.":
		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)})
		} else {
			m.Ns = append(m.Ns, soa("example.", 3600, 300))
		}
	case strings.HasSuffix(q.Name, "example."):
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, soa("example.", 120, 900))
	default:
		m.Rcode = dns.RcodeRefused
	}
	_ = w.WriteMsg(m)
}

func newTestResolver(t *testing.T) *Resolver {
	return &Resolver{Servers: []string{startServer(t, zoneHandler)}, Timeout: 2 * time.Second}
}

func TestLookupStatuses(t *testing.T) {
	r := newTestResolver(t)
	ctx := context.Background()
	tests := []struct {
		name, qtype, status, value, proto string
		ttl                               uint32
	}{
		{"www.example", "A", StatusNoError, "192.0.2.1", "udp", 60},
		{"www.example", "MX", StatusNoData, "", "udp", 300},
		{"nope.example", "A", "NXDOMAIN", "", "udp", 120},
		{"big.example", "A", StatusNoError, "192.0.2.9", "tcp", 60},
		{"noedns.example", "A", StatusNoError, "192.0.2.1", "udp", 60},
		{"other.test", "A", "REFUSED", "", "udp", 0},
	}
	for _, tt := range tests {
		qt, _ := ParseType(tt.qtype)
		rows := r.Lookup(ctx, tt.name, qt, false)
		if len(rows) != 1 {
			t.Fatalf("%s: got %d rows", tt.name, len(rows))
		}
		got := rows[0]
		if got.Status != tt.status || got.Value != tt.value || got.Protocol != tt.proto || got.TTL != tt.ttl {
			t.Errorf("%s %s: got status=%s value=%q proto=%s ttl=%d", tt.name, tt.qtype, got.Status, got.Value, got.Protocol, got.TTL)
		}
		if Explain(got) == "" {
			t.Errorf("%s: empty explanation", tt.name)
		}
	}
}

func TestRetriesOnTimeout(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	// Drops the first two queries for each name, then answers.
	addr := startServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		mu.Lock()
		seen[req.Question[0].Name]++
		n := seen[req.Question[0].Name]
		mu.Unlock()
		if n <= 2 {
			return
		}
		zoneHandler(w, req)
	})
	count := func(name string) int {
		mu.Lock()
		defer mu.Unlock()
		return seen[name]
	}
	ctx := context.Background()
	r := &Resolver{Servers: []string{addr}, Timeout: 100 * time.Millisecond, Retries: 2}
	if rows := r.Lookup(ctx, "www.example", dns.TypeA, false); rows[0].Status != StatusNoError {
		t.Errorf("with 2 retries: got %s %s", rows[0].Status, rows[0].Error)
	}
	r.Retries = 1
	rows := r.Lookup(ctx, "noedns.example", dns.TypeA, false)
	if rows[0].Status != StatusError || !strings.Contains(rows[0].Error, "no usable response after 2 attempts to 1 server(s)") {
		t.Errorf("with 1 retry: got %s %q", rows[0].Status, rows[0].Error)
	}
	if n := count("noedns.example."); n != 2 {
		t.Errorf("sent %d queries, want 2", n)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	r.Retries = 5
	if rows := r.Lookup(cancelled, "cancel.example", dns.TypeA, false); rows[0].Status != StatusError || count("cancel.example.") > 1 {
		t.Errorf("cancelled lookup retried: %d queries, %s", count("cancel.example."), rows[0].Status)
	}
}

// silentServer returns a UDP address that accepts queries but never answers.
func silentServer(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

// closedPort returns a UDP address with nothing listening, so queries fail
// immediately with "connection refused".
func closedPort(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

func rcodeServer(t *testing.T, rcode int) string {
	return startServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, rcode)
		_ = w.WriteMsg(m)
	})
}

func TestServerFailover(t *testing.T) {
	good := startServer(t, zoneHandler)
	servfail := rcodeServer(t, dns.RcodeServerFailure)
	refused := rcodeServer(t, dns.RcodeRefused)
	ctx := context.Background()
	lookup := func(retries int, servers ...string) Row {
		r := &Resolver{Servers: servers, Timeout: 100 * time.Millisecond, Retries: retries}
		return r.Lookup(ctx, "www.example", dns.TypeA, false)[0]
	}

	cases := []struct {
		name    string
		servers []string
		status  string
		server  string
	}{
		{"silent then good", []string{silentServer(t), good}, StatusNoError, good},
		{"refused connection then good", []string{closedPort(t), good}, StatusNoError, good},
		{"SERVFAIL then good", []string{servfail, good}, StatusNoError, good},
		{"REFUSED then good", []string{refused, good}, StatusNoError, good},
		{"all SERVFAIL/REFUSED keeps last answer", []string{servfail, refused}, "REFUSED", refused},
		{"good first is not skipped", []string{good, servfail}, StatusNoError, good},
	}
	for _, c := range cases {
		got := lookup(0, c.servers...)
		if got.Status != c.status || got.Server != c.server {
			t.Errorf("%s: got status=%s server=%s error=%q", c.name, got.Status, got.Server, got.Error)
		}
	}

	// Only servers that timed out are retried: 2 rounds over the silent
	// server, 1 attempt at the closed port.
	got := lookup(1, silentServer(t), closedPort(t))
	if got.Status != StatusError || !strings.Contains(got.Error, "after 3 attempts to 2 server(s)") {
		t.Errorf("all failing: got %s %q", got.Status, got.Error)
	}
	if !strings.Contains(got.Server, ",") {
		t.Errorf("error row should list all servers, got %q", got.Server)
	}
}

func TestLimiterPacesEveryTransmission(t *testing.T) {
	var mu sync.Mutex
	var sent []time.Time
	// Drops the first query for each name so one lookup needs a retry.
	seen := map[string]bool{}
	addr := startServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		mu.Lock()
		sent = append(sent, time.Now())
		first := !seen[req.Question[0].Name]
		seen[req.Question[0].Name] = true
		mu.Unlock()
		if !first {
			zoneHandler(w, req)
		}
	})
	r := &Resolver{Servers: []string{addr}, Timeout: 20 * time.Millisecond, Retries: 1,
		Limiter: rate.NewLimiter(rate.Limit(20), 1)}
	for _, name := range []string{"www.example", "noedns.example"} {
		if row := r.Lookup(context.Background(), name, dns.TypeA, false)[0]; row.Status != StatusNoError {
			t.Fatalf("%s: %s %s", name, row.Status, row.Error)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	// www: drop + retry; noedns: drop + retry, FORMERR, retry without EDNS.
	if len(sent) < 5 {
		t.Fatalf("server saw %d queries, want at least 5", len(sent))
	}
	for i := 1; i < len(sent); i++ {
		// 20/s means 50ms apart; allow scheduling jitter.
		if gap := sent[i].Sub(sent[i-1]); gap < 40*time.Millisecond {
			t.Errorf("queries %d and %d only %v apart", i-1, i, gap)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	slow := &Resolver{Servers: []string{addr}, Timeout: time.Second, Limiter: rate.NewLimiter(rate.Limit(0.001), 1)}
	slow.Limiter.Allow() // use the only token
	if row := slow.Lookup(ctx, "www.example", dns.TypeA, false)[0]; row.Status != StatusError {
		t.Errorf("cancelled wait for a token should fail, got %s", row.Status)
	}
}

// oversizedServer sends UDP answers larger than the client's EDNS payload
// size without setting TC, as some VPN and middlebox resolvers do; over
// TCP it answers normally unless tcpFails is set.
func oversizedServer(t *testing.T, tcpFails bool) string {
	return startServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		if w.RemoteAddr().Network() == "tcp" && tcpFails {
			_ = w.Close()
			return
		}
		for i := range 20 {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{fmt.Sprintf("%02d %s", i, strings.Repeat("x", 100))}})
		}
		_ = w.WriteMsg(m) // about 2.5 KB, no TC
	})
}

func TestOversizedUDPAnswerRetriedOverTCP(t *testing.T) {
	var trace bytes.Buffer
	r := &Resolver{Servers: []string{oversizedServer(t, false)}, Timeout: time.Second, Trace: NewTracer(&trace)}
	row := r.Lookup(context.Background(), "big.test", dns.TypeTXT, false)
	if row[0].Status != StatusNoError || row[0].Protocol != "tcp" || len(row) != 20 {
		t.Fatalf("got %d rows, status %s over %s: %s", len(row), row[0].Status, row[0].Protocol, row[0].Error)
	}
	if !strings.Contains(trace.String(), "UDP answer unreadable, probably larger than the 1232 bytes requested") {
		t.Errorf("trace should explain the TCP retry:\n%s", trace.String())
	}

	r = &Resolver{Servers: []string{oversizedServer(t, true)}, Timeout: time.Second}
	row = r.Lookup(context.Background(), "big.test", dns.TypeTXT, false)
	if row[0].Status != StatusError || !strings.Contains(row[0].Error, "not marked truncated; TCP retry failed") {
		t.Errorf("when TCP fails too the error should say why: %s %q", row[0].Status, row[0].Error)
	}
}

func TestTryToResolveAndAuthoritative(t *testing.T) {
	r := newTestResolver(t)
	rows := r.Lookup(context.Background(), "www.example", dns.TypeSOA, true)
	if len(rows) != 1 || rows[0].Status != StatusNoError || rows[0].Zone != "example." || rows[0].Query != "www.example" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
	if got := FilterAuthoritative(append([]Row{}, rows...), []string{"NS1.example"}); len(got) != 1 {
		t.Errorf("matching MNAME filtered out")
	}
	if got := FilterAuthoritative(rows, []string{"ns2.example."}); len(got) != 0 {
		t.Errorf("non-matching MNAME kept")
	}
}

func TestInternationalizedNames(t *testing.T) {
	cases := map[string]string{
		"räksmörgås.se":         "xn--rksmrgs-5wao1o.se.",
		"RÄKSMÖRGÅS.SE":         "xn--rksmrgs-5wao1o.SE.", // mapped label lower-cased, ASCII left as typed
		"_dmarc.räksmörgås.se":  "_dmarc.xn--rksmrgs-5wao1o.se.",
		"www.räksmörgås.se.":    "www.xn--rksmrgs-5wao1o.se.",
		"xn--rksmrgs-5wao1o.se": "xn--rksmrgs-5wao1o.se.",
		"straße.de":             "xn--strae-oqa.de.",      // IDNA 2008, not "strasse"
		"räksmörgås。se":         "xn--rksmrgs-5wao1o.se.", // ideographic full stop
		"例え.jp":                 "xn--r8jz45g.jp.",
	}
	for in, want := range cases {
		if got, err := Normalize(in, dns.TypeA); err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := Normalize("bücher-.de", dns.TypeA); err == nil || !strings.Contains(err.Error(), "invalid internationalized domain name") {
		t.Errorf("trailing hyphen should be rejected: %v", err)
	}
	for in, want := range map[string]string{
		"xn--rksmrgs-5wao1o.se.":        "räksmörgås.se.",
		"_dmarc.xn--rksmrgs-5wao1o.se.": "_dmarc.räksmörgås.se.",
		"example.com.":                  "example.com.",
		"xn--invalid-.se.":              "xn--invalid-.se.",
	} {
		if got := unicodeName(in); got != want {
			t.Errorf("unicodeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	if got, _ := Normalize("192.0.2.1", dns.TypePTR); got != "1.2.0.192.in-addr.arpa." {
		t.Errorf("PTR reverse: %q", got)
	}
	if _, err := Normalize("bad..name", dns.TypeA); err == nil {
		t.Error("expected error for invalid name")
	}
}

func TestMatch(t *testing.T) {
	row := Row{Status: "NOERROR", Type: "MX", Value: "10 Mail.Example."}
	cases := map[string]bool{
		"status=noerror":              true,
		"value=mail|smtp":             true,
		"value=smtp":                  false,
		"status=NOERROR&&type=mx":     true,
		"status=NOERROR&&type=a|aaaa": false,
	}
	for expr, want := range cases {
		m, err := ParseMatch([]string{expr})
		if err != nil {
			t.Fatal(err)
		}
		if m.Match(row) != want {
			t.Errorf("%s: want %v", expr, want)
		}
	}
	if _, err := ParseMatch([]string{"nosuchfield=x"}); err == nil {
		t.Error("expected unknown field error")
	}
}

func TestOutputs(t *testing.T) {
	fields, _ := SelectFields([]string{"status", "ttl", "authoritative"}, FieldOptions{})
	rows := []Row{{Status: "NOERROR", TTL: 60, HasTTL: true}, {Status: "true"}}
	var b bytes.Buffer
	if err := Write(&b, "json", fields, rows); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"status": "NOERROR",`) || !strings.Contains(b.String(), `"ttl": null`) {
		t.Errorf("json:\n%s", b.String())
	}
	b.Reset()
	if err := Write(&b, "yaml", fields, rows); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "- status: NOERROR\n  ttl: 60\n") || !strings.Contains(b.String(), `status: "true"`) {
		t.Errorf("yaml:\n%s", b.String())
	}
	for spec, want := range map[string]string{"": "text", "JSON": "json", "r.yml": "yaml", "out.CSV": "csv"} {
		if f, _, err := ResolveOutput(spec); err != nil || f != want {
			t.Errorf("ResolveOutput(%q) = %q, %v", spec, f, err)
		}
	}
	if _, _, err := ResolveOutput("out.pdf"); err == nil {
		t.Error("expected error for unknown extension")
	}
}

// BenchmarkLookup measures one uncached lookup against a local server,
// with tracing off.
func BenchmarkLookup(b *testing.B) {
	addr := startServer(b, zoneHandler)
	r := &Resolver{Servers: []string{addr}, Timeout: time.Second}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		r.Lookup(ctx, "www.example", dns.TypeA, false)
	}
}
