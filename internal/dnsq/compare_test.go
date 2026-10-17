package dnsq

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// answering returns a handler that answers every A query with addr and
// counts the queries. When the query carries a client subnet, the answer
// echoes it with that scope (RFC 7871 section 7.2.1).
func answering(addr string, queries *atomic.Int32) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		queries.Add(1)
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(addr)})
		}
		if opt := req.IsEdns0(); opt != nil {
			m.SetEdns0(ednsUDPSize, false)
			for _, o := range opt.Option {
				if e, ok := o.(*dns.EDNS0_SUBNET); ok {
					reply := *e
					reply.SourceScope = e.SourceNetmask
					m.IsEdns0().Option = append(m.IsEdns0().Option, &reply)
				}
			}
		}
		_ = w.WriteMsg(m)
	}
}

func TestCompareServers(t *testing.T) {
	var q1, q2, q3 atomic.Int32
	servers := []string{
		startServer(t, answering("192.0.2.1", &q1)),
		startServer(t, answering("192.0.2.66", &q2)), // the odd one out
		startServer(t, answering("192.0.2.1", &q3)),
		silentServer(t),
	}
	var trace bytes.Buffer
	r := &Resolver{Servers: servers, Timeout: 250 * time.Millisecond, Retries: 1, Cache: NewCache(100), Trace: NewTracer(&trace)}
	for range 2 {
		rows := r.CompareServers(context.Background(), "www.example", dns.TypeA)
		if len(rows) != 4 {
			t.Fatalf("got %d rows, want one per server", len(rows))
		}
		for i, row := range rows {
			if row.Server != servers[i] {
				t.Errorf("row %d: server %s, want %s (server order)", i, row.Server, servers[i])
			}
		}
		if rows[0].Value != "A 192.0.2.1" || rows[0].Check != "" || rows[2].Check != "" {
			t.Errorf("majority rows: %+v / %+v", rows[0], rows[2])
		}
		if rows[1].Value != "A 192.0.2.66" || rows[1].Check != "answer differs from 2 of 3 servers" {
			t.Errorf("odd server: value %q, check %q", rows[1].Value, rows[1].Check)
		}
		if rows[3].Status != StatusError || !strings.HasPrefix(rows[3].Check, "no usable reply") {
			t.Errorf("silent server: status %s, check %q", rows[3].Status, rows[3].Check)
		}
	}
	// Only the silent server's retries are counted: under load, a slow
	// answer from another server may time out too.
	if got := strings.Count(trace.String(), servers[3]+" timed out after 250ms; retry 1 of 1 follows"); got != 2 {
		t.Errorf("silent server retried %d times over two runs, want 2 (--retries 1); trace:\n%s", got, trace.String())
	}
	// The cache is bypassed: every server was asked both times.
	if q1.Load() != 2 || q2.Load() != 2 || q3.Load() != 2 {
		t.Errorf("queries per server %d, %d, %d; want 2 each", q1.Load(), q2.Load(), q3.Load())
	}

	bad := r.CompareServers(context.Background(), "a..b", dns.TypeA)
	if len(bad) != 1 || bad[0].Status != StatusError || bad[0].Check == "" {
		t.Errorf("invalid name: %+v", bad)
	}
}

func TestMarkDifferences(t *testing.T) {
	row := func(status, value, check string) Row { return Row{Status: status, Value: value, Check: check} }
	cases := []struct {
		name string
		in   []Row
		want []string
	}{
		{"all agree", []Row{row("NOERROR", "A 1", ""), row("NOERROR", "A 1", "")}, []string{"", ""}},
		{"no majority of two", []Row{row("NOERROR", "A 1", ""), row("NOERROR", "A 2", "")},
			[]string{"servers disagree: 2 different answers from 2 servers, none from a majority", "servers disagree: 2 different answers from 2 servers, none from a majority"}},
		{"status counts", []Row{row("NOERROR", "A 1", ""), row("NXDOMAIN", "", ""), row("NOERROR", "A 1", "")},
			[]string{"", "answer differs from 2 of 3 servers", ""}},
		{"failed servers left out", []Row{row("ERROR", "", "no usable reply: x"), row("NOERROR", "A 1", ""), row("NOERROR", "A 1", "")},
			[]string{"no usable reply: x", "", ""}},
	}
	for _, tc := range cases {
		markDifferences(tc.in)
		for i, r := range tc.in {
			if r.Check != tc.want[i] {
				t.Errorf("%s: row %d check %q, want %q", tc.name, i, r.Check, tc.want[i])
			}
		}
	}
}

func TestParseECS(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.77/24":     "192.0.2.0/24",
		"198.51.100.7":      "198.51.100.0/24",
		"2001:db8:1:2:3::1": "2001:db8:1::/56",
		"2001:db8::/32":     "2001:db8::/32",
		"0.0.0.0/0":         "0.0.0.0/0",
	} {
		e, err := ParseECS(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		bits := 32
		if e.Family == 2 {
			bits = 128
		}
		got := (&net.IPNet{IP: e.Address, Mask: net.CIDRMask(int(e.SourceNetmask), bits)}).String()
		if got != want {
			t.Errorf("ParseECS(%q) = %s, want %s", in, got, want)
		}
	}
	for _, in := range []string{"", "example.com", "192.0.2.0/33"} {
		if _, err := ParseECS(in); err == nil {
			t.Errorf("ParseECS(%q): want error", in)
		}
	}
}

// TestECSSentAndShown checks that --ecs reaches the server and that the
// scope it answers with is shown.
func TestECSSentAndShown(t *testing.T) {
	var n atomic.Int32
	ecs, _ := ParseECS("192.0.2.0/24")
	r := &Resolver{Servers: []string{startServer(t, answering("192.0.2.1", &n))}, Timeout: time.Second, ECS: ecs}
	row := r.Lookup(context.Background(), "www.example", dns.TypeA, false)[0]
	if row.ECS != "192.0.2.0/24 scope /24" {
		t.Errorf("ecs field %q", row.ECS)
	}
	r.ECS = nil
	r.Cache = nil
	if row := r.Lookup(context.Background(), "www.example", dns.TypeA, false)[0]; row.ECS != "" {
		t.Errorf("ecs field without --ecs: %q", row.ECS)
	}
}

// TestECSInNameserverCheck checks that --check-nameservers rows show the
// client subnet scope of each nameserver's answer.
func TestECSInNameserverCheck(t *testing.T) {
	var n atomic.Int32
	echo := answering("192.0.2.1", &n)
	auth := func(w dns.ResponseWriter, req *dns.Msg) {
		if req.Question[0].Qtype != dns.TypeSOA {
			echo(w, req)
			return
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		m.Answer = append(m.Answer, soa("example.", 300, 60))
		_ = w.WriteMsg(m)
	}
	host, port, _ := net.SplitHostPort(startServer(t, auth))
	ecs, _ := ParseECS("198.51.100.0/24")
	r := &Resolver{Timeout: time.Second, AuthPort: port, ECS: ecs}
	row := r.checkServer(context.Background(), Row{}, "example.", "www.example.", dns.TypeA, host)
	if row.Value != "A 192.0.2.1" || row.ECS != "198.51.100.0/24 scope /24" {
		t.Errorf("value %q, ecs %q, check %q", row.Value, row.ECS, row.Check)
	}
}
