package dnsq

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// authServer is a fake authoritative server for check.test.
type authServer struct {
	serial        uint32
	authoritative bool
	a             string // address answered for www.check.test
}

func (s authServer) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = s.authoritative
	if req.RecursionDesired {
		m.RecursionAvailable = false // authoritative only
	}
	q := req.Question[0]
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: "check.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns: "ns1.check.test.", Mbox: "admin.check.test.", Serial: s.serial, Minttl: 60}
	switch {
	case q.Name == "check.test." && q.Qtype == dns.TypeSOA:
		m.Answer = append(m.Answer, soa)
	case q.Name == "www.check.test." && q.Qtype == dns.TypeA:
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP(s.a)})
	default:
		m.Ns = append(m.Ns, soa)
	}
	_ = w.WriteMsg(m)
}

// startAuthServers starts one server per handler on 127.0.0.2, 127.0.0.3,
// ... all on the same port (direct queries use one port for every address)
// and returns the addresses and the port.
func startAuthServers(t *testing.T, handlers []dns.Handler) ([]string, string) {
	t.Helper()
	for range 20 {
		probe, err := net.ListenPacket("udp", "127.0.0.2:0")
		if err != nil {
			t.Skip("cannot bind extra loopback addresses: ", err)
		}
		_, port, _ := net.SplitHostPort(probe.LocalAddr().String())
		_ = probe.Close()
		var servers []*dns.Server
		var addrs []string
		ok := true
		for i, h := range handlers {
			addr := fmt.Sprintf("127.0.0.%d", i+2)
			pc, err := net.ListenPacket("udp", net.JoinHostPort(addr, port))
			if err != nil {
				ok = false
				break
			}
			l, err := net.Listen("tcp", net.JoinHostPort(addr, port))
			if err != nil {
				_ = pc.Close()
				ok = false
				break
			}
			var wg sync.WaitGroup
			wg.Add(2)
			u := &dns.Server{PacketConn: pc, Handler: h, NotifyStartedFunc: wg.Done}
			tc := &dns.Server{Listener: l, Handler: h, NotifyStartedFunc: wg.Done}
			go func() { _ = u.ActivateAndServe() }()
			go func() { _ = tc.ActivateAndServe() }()
			wg.Wait()
			servers = append(servers, u, tc)
			addrs = append(addrs, addr)
		}
		t.Cleanup(func() {
			for _, s := range servers {
				_ = s.Shutdown()
			}
		})
		if ok {
			return addrs, port
		}
	}
	t.Fatal("could not bind the same port on the test loopback addresses")
	return nil, ""
}

func TestCheckNameservers(t *testing.T) {
	good := authServer{serial: 5, authoritative: true, a: "192.0.2.1"}
	addrs, port := startAuthServers(t, []dns.Handler{
		good,                              // ns1
		good,                              // ns2
		authServer{5, true, "192.0.2.99"}, // ns3: different answer
		authServer{4, true, "192.0.2.1"},  // ns4: old serial
		authServer{5, false, "192.0.2.1"}, // ns5: lame
	})
	// The recursive resolver knows the delegation and the nameservers'
	// addresses; ns6 has none.
	recursive := func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		soa := &dns.SOA{Hdr: dns.RR_Header{Name: "check.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			Ns: "ns1.check.test.", Mbox: "admin.check.test.", Serial: 5, Minttl: 60}
		switch {
		case q.Name == "check.test." && q.Qtype == dns.TypeSOA:
			m.Answer = append(m.Answer, soa)
		case q.Name == "check.test." && q.Qtype == dns.TypeNS:
			for i := 1; i <= 6; i++ {
				m.Answer = append(m.Answer, &dns.NS{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns: fmt.Sprintf("ns%d.check.test.", i)})
			}
		case q.Qtype == dns.TypeA && strings.HasPrefix(q.Name, "ns") && q.Name != "ns6.check.test.":
			var i int
			_, _ = fmt.Sscanf(q.Name, "ns%d.", &i)
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A: net.ParseIP(addrs[i-1])})
		default:
			m.Ns = append(m.Ns, soa)
		}
		_ = w.WriteMsg(m)
	}
	var trace bytes.Buffer
	r := &Resolver{Servers: []string{startServer(t, recursive)}, Timeout: time.Second, AuthPort: port,
		Cache: NewCache(100), NSID: true, Trace: NewTracer(&trace)}
	rows := r.CheckNameservers(context.Background(), "www.check.test", dns.TypeA)

	want := map[string]string{
		"ns1.check.test.": "",
		"ns2.check.test.": "",
		"ns3.check.test.": "answer differs from 3 of 4 servers",
		"ns4.check.test.": "serial 4 differs from 5 on 3 of 4 servers (out of sync?)",
		"ns5.check.test.": "lame: not authoritative",
		"ns6.check.test.": "nameserver has no A or AAAA address",
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows: %+v", len(rows), rows)
	}
	for _, row := range rows {
		w, ok := want[row.NS]
		if !ok || w == "" && row.Check != "" || w != "" && !strings.Contains(row.Check, w) {
			t.Errorf("%s: check %q, want %q", row.NS, row.Check, w)
		}
		if row.Zone != "check.test." || Explain(row) == "" {
			t.Errorf("%s: zone %q", row.NS, row.Zone)
		}
	}
	if rows[0].Serial != 5 || !rows[0].Authoritative || rows[0].Value != "A 192.0.2.1" || rows[0].Server != addrs[0]+":"+port {
		t.Errorf("first row: %+v", rows[0])
	}
	for _, s := range []string{"check: zone check.test. has nameservers", "check.test. SOA -RD +NSID"} {
		if !strings.Contains(trace.String(), s) {
			t.Errorf("trace missing %q:\n%s", s, trace.String())
		}
	}

	// A name outside any zone the resolver knows fails as one row.
	if rows := r.CheckNameservers(context.Background(), "bad..name", dns.TypeA); len(rows) != 1 || rows[0].Status != StatusError {
		t.Errorf("invalid name: %+v", rows)
	}
}

func TestSkippedRowHasNoReplyFields(t *testing.T) {
	fields, _ := SelectFields([]string{"authoritative", "rtt_ms"}, FieldOptions{})
	row := Row{Status: StatusSkipped, Skipped: true}
	for _, f := range fields {
		if s := f.String(row); s != "" {
			t.Errorf("%s = %q for a server that was never reached, want empty", f.Name, s)
		}
	}
}

func TestLocalBlock(t *testing.T) {
	opErr := func(op string, errno syscall.Errno) error {
		return &net.OpError{Op: op, Net: "udp", Err: os.NewSyscallError(op, errno)}
	}
	cases := []struct {
		err  error
		want string
	}{
		{opErr("connect", syscall.ENETUNREACH), "no route to 192.0.2.1"},
		// A VPN kill switch: "write: operation not permitted".
		{opErr("write", syscall.EPERM), "firewall does not let DNS out to 192.0.2.1"},
		{opErr("write", syscall.EACCES), "firewall does not let DNS out"},
		{opErr("read", syscall.ECONNREFUSED), ""}, // the server's problem
	}
	for _, c := range cases {
		got := localBlock(c.err, "192.0.2.1")
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%v: got %q, want %q", c.err, got, c.want)
		}
	}
	if !Unchecked([]Row{{Skipped: true}, {Skipped: true}}) || Unchecked([]Row{{Skipped: true}, {}}) || Unchecked(nil) {
		t.Error("Unchecked must be true only when every row was skipped")
	}
}

func TestExtendedErrorsAndNSID(t *testing.T) {
	addr := startServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		m.SetEdns0(1232, false)
		opt := m.IsEdns0()
		opt.Option = append(opt.Option,
			&dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeBlocked, ExtraText: "listed by policy"},
			&dns.EDNS0_EDE{InfoCode: 4242})
		if q := req.IsEdns0(); q != nil {
			for _, o := range q.Option {
				if o.Option() == dns.EDNS0NSID {
					opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: fmt.Sprintf("%x", "resolver-7")})
				}
			}
		}
		_ = w.WriteMsg(m)
	})
	r := &Resolver{Servers: []string{addr}, Timeout: time.Second, NSID: true}
	row := r.Lookup(context.Background(), "blocked.test", dns.TypeA, false)[0]
	if row.EDE != "15 Blocked: listed by policy; 4242" || row.NSID != "resolver-7" {
		t.Errorf("EDE %q, NSID %q", row.EDE, row.NSID)
	}
	if !strings.Contains(Explain(row), "extended error (RFC 8914): 15 Blocked") {
		t.Errorf("explanation: %s", Explain(row))
	}
	r.NSID = false
	if row := r.Lookup(context.Background(), "blocked.test", dns.TypeA, false)[0]; row.NSID != "" {
		t.Errorf("NSID should only come back when asked for: %q", row.NSID)
	}
	// Non-printable identifiers are shown as hex.
	m := new(dns.Msg)
	m.SetEdns0(1232, false)
	m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "00ff"})
	if got := serverID(m); got != "00ff" {
		t.Errorf("binary NSID: %q", got)
	}
}

// TestCompareServersWithoutMajority checks that a tie flags every server
// and names the versions, instead of declaring one side "most servers".
func TestCompareServersWithoutMajority(t *testing.T) {
	row := func(serial uint32, value string) Row {
		return Row{Status: StatusNoError, Serial: serial, HasSerial: true, Value: value}
	}
	rows := []Row{row(10, "A 1"), row(20, "A 1"), row(20, "A 2"), row(10, "A 2"), {Check: "lame: x"}}
	compareServers(rows)
	want := "serials differ: 20 on 2 servers, 10 on 2; no majority (out of sync?); answers differ: 2 different answers from 4 servers, no majority"
	for i, r := range rows[:4] {
		if r.Check != want {
			t.Errorf("row %d: check %q\nwant %q", i, r.Check, want)
		}
	}
	if rows[4].Check != "lame: x" {
		t.Errorf("a row with its own problem changed: %q", rows[4].Check)
	}

	// Three versions, one on two servers of four: still no majority.
	rows = []Row{row(7, "A 1"), row(9, "A 1"), row(8, "A 1"), row(9, "A 1")}
	compareServers(rows)
	if want := "serials differ: 9 on 2 servers, 8 on 1, 7 on 1; no majority (out of sync?)"; rows[0].Check != want {
		t.Errorf("check %q\nwant %q", rows[0].Check, want)
	}
}

// TestCheckNameserversIPv4ByDefault checks that only IPv4 addresses are
// used unless IPv6 is set, and that a nameserver with only IPv6 addresses
// is skipped (not reported as having no address) when IPv6 is off.
func TestCheckNameserversIPv4ByDefault(t *testing.T) {
	addrs, port := startAuthServers(t, []dns.Handler{authServer{serial: 5, authoritative: true, a: "192.0.2.1"}})
	recursive := func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 300}
		switch {
		case q.Name == "check.test." && q.Qtype == dns.TypeSOA:
			m.Answer = append(m.Answer, &dns.SOA{Hdr: hdr, Ns: "ns1.check.test.", Mbox: "admin.check.test.", Serial: 5, Minttl: 60})
		case q.Name == "check.test." && q.Qtype == dns.TypeNS:
			m.Answer = append(m.Answer, &dns.NS{Hdr: hdr, Ns: "ns1.check.test."}, &dns.NS{Hdr: hdr, Ns: "ns2.check.test."})
		case q.Name == "ns1.check.test." && q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.ParseIP(addrs[0])})
		case q.Name == "ns1.check.test." && q.Qtype == dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::1")})
		case q.Name == "ns2.check.test." && q.Qtype == dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::2")})
		}
		_ = w.WriteMsg(m)
	}
	r := &Resolver{Servers: []string{startServer(t, recursive)}, Timeout: 200 * time.Millisecond, AuthPort: port, Cache: NewCache(100)}
	rows := r.CheckNameservers(context.Background(), "www.check.test", dns.TypeA)
	if len(rows) != 2 || rows[0].Server != net.JoinHostPort(addrs[0], port) || rows[0].Check != "" {
		t.Fatalf("IPv4 only: want ns1 over IPv4 and ns2 skipped, got %+v", rows)
	}
	if !rows[1].Skipped || rows[1].Check != "skipped: only IPv6 addresses (2001:db8::2); add --ipv6 to check them" {
		t.Errorf("ns2: skipped %v, check %q", rows[1].Skipped, rows[1].Check)
	}

	r.IPv6 = true
	var servers []string
	for _, row := range r.CheckNameservers(context.Background(), "www.check.test", dns.TypeA) {
		servers = append(servers, row.Server)
	}
	want := []string{net.JoinHostPort(addrs[0], port), "[2001:db8::1]:" + port, "[2001:db8::2]:" + port}
	if !slices.Equal(servers, want) {
		t.Errorf("with IPv6: servers %q, want %q", servers, want)
	}
}
