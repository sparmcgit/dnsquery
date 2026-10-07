package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/sparmcgit/dnsquery/internal/dnsq"
)

// startServer runs a UDP resolver on loopback that answers A and MX for any
// name under "test.", an SOA at "test." and NXDOMAIN for "missing.test.".
func startServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 600},
		Ns:  "ns1.test.", Mbox: "admin.test.", Serial: 7, Minttl: 60,
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 300}
		if strings.HasPrefix(q.Name, "slow") {
			// Finish out of order: later names are often answered first.
			time.Sleep(time.Duration(req.Id%7) * time.Millisecond)
		}
		switch {
		case q.Name == "drop.test.":
			return
		case q.Name == "missing.test.":
			m.Rcode = dns.RcodeNameError
			m.Ns = append(m.Ns, soa)
		case q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IPv4(192, 0, 2, 1)})
		case q.Qtype == dns.TypeMX:
			m.Answer = append(m.Answer, &dns.MX{Hdr: hdr, Preference: 10, Mx: "mail.test."})
		case q.Qtype == dns.TypeSOA && q.Name == "test.":
			m.Answer = append(m.Answer, soa)
		default:
			m.Ns = append(m.Ns, soa)
		}
		_ = w.WriteMsg(m)
	})
	var wg sync.WaitGroup
	wg.Add(1)
	srv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: wg.Done}
	go func() { _ = srv.ActivateAndServe() }()
	wg.Wait()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// resetState undoes flag and viper state left over from a previous Execute,
// since rootCmd and viper are package globals.
func resetState() {
	viper.Reset()
	cfgFile = ""
	for _, fs := range []*pflag.FlagSet{rootCmd.Flags(), rootCmd.PersistentFlags()} {
		fs.VisitAll(func(f *pflag.Flag) {
			if sv, ok := f.Value.(pflag.SliceValue); ok {
				_ = sv.Replace(nil)
			} else {
				_ = f.Value.Set(f.DefValue)
			}
			f.Changed = false
		})
	}
}

func execute(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	resetState()
	var out, errOut bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errOut)
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetArgs(args)
	err = rootCmd.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

func TestVersionAndAuthor(t *testing.T) {
	for args, want := range map[string]string{"version": "v0.0.1\n", "author": "Martin Haggstrom\n"} {
		out, _, err := execute(t, "", args)
		if err != nil || out != want {
			t.Errorf("%s: got %q, %v", args, out, err)
		}
	}
}

func TestQueryArgs(t *testing.T) {
	server := startServer(t)
	out, _, err := execute(t, "", "a.test", "missing.test", "--server", server, "--output", "json", "--select-fields", "query,status,value,ttl")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("invalid json %q: %v", out, err)
	}
	if len(rows) != 2 || rows[0]["value"] != "192.0.2.1" || rows[1]["status"] != "NXDOMAIN" || rows[1]["ttl"] != 60.0 {
		t.Errorf("unexpected rows %v", rows)
	}
}

func TestQueryStdinMatchExplainVerbose(t *testing.T) {
	server := startServer(t)
	stdin := "# comment\n\na.test extra\nb.test\nmissing.test\n"
	out, errOut, err := execute(t, stdin, "--server", server, "--type", "mx", "--explain",
		"--match-fields", "status=noerror&&query=a|b", "--verbose", "--progress", "--concurrency", "2")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "QUERY") || !strings.Contains(lines[1], "Mail for a.test is delivered to mail.test") {
		t.Errorf("unexpected output:\n%s", out)
	}
	for _, want := range []string{"servers:", "type:", "MX", "input:", "stdin", "match-fields:", "queried 3"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr missing %q:\n%s", want, errOut)
		}
	}
}

func TestQueryFileAndOutputs(t *testing.T) {
	server := startServer(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(in, []byte("b.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	names := []string{"out.txt", "out.yaml", "out.json", "out.csv"}
	formats := []string{"text", "yaml", "csv"}
	if dnsq.ExcelAvailable {
		names, formats = append(names, "out.xlsx"), append(formats, "excel")
	} else if _, _, err := execute(t, "", "a.test", "--server", server, "--output", "excel"); err == nil || !strings.Contains(err.Error(), "-tags excel") {
		t.Errorf("excel in a build without it: %v", err)
	}
	for _, name := range names {
		path := filepath.Join(dir, name)
		// Args plus an explicit --file combine both sources.
		if _, _, err := execute(t, "", "a.test", "--file", in, "--server", server, "--output", path); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			t.Fatalf("%s: empty output, %v", name, err)
		}
		if name != "out.xlsx" && (!bytes.Contains(data, []byte("a.test")) || !bytes.Contains(data, []byte("b.test"))) {
			t.Errorf("%s: missing queries:\n%s", name, data)
		}
	}
	for _, format := range formats {
		if out, _, err := execute(t, "", "a.test", "--server", server, "--output", format); err != nil || out == "" {
			t.Errorf("%s to stdout: %q, %v", format, out, err)
		}
	}
}

func TestSOAOptions(t *testing.T) {
	server := startServer(t)
	out, _, err := execute(t, "", "www.test", "--server", server, "--type", "SOA", "--try-to-resolve",
		"--is-authoritative", "ns1.test", "--select-fields", "query,zone", "--output", "csv", "--verbose")
	if err != nil || out != "query,zone\nwww.test,test.\n" {
		t.Errorf("got %q, %v", out, err)
	}
	out, _, err = execute(t, "", "test", "--server", server, "--type", "SOA", "--is-authoritative", "ns2.test", "--output", "csv")
	if err != nil || strings.Count(out, "\n") != 1 {
		t.Errorf("non-matching MNAME should leave only the header: %q, %v", out, err)
	}
}

func TestConfigFileAndEnv(t *testing.T) {
	server := startServer(t)
	cfg := filepath.Join(t.TempDir(), "dnsquery.yaml")
	if err := os.WriteFile(cfg, []byte("type: MX\nserver: "+server+"\noutput: csv\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, err := execute(t, "", "a.test", "--config", cfg, "--select-fields", "type")
	if err != nil || out != "type\nMX\n" {
		t.Errorf("config: got %q, %v", out, err)
	}
	t.Setenv("DNSQUERY_SERVER", server)
	t.Setenv("DNSQUERY_SELECT_FIELDS", "value")
	out, _, err = execute(t, "", "a.test", "--output", "csv")
	if err != nil || out != "value\n192.0.2.1\n" {
		t.Errorf("env: got %q, %v", out, err)
	}
}

func TestFailedQueriesExitStatus(t *testing.T) {
	server := startServer(t)
	out, errOut, err := execute(t, "", "a.test", "drop.test", "--server", server, "--timeout", "100ms",
		"--retries", "1", "--output", "csv", "--select-fields", "query,status", "--verbose")
	if !strings.Contains(errOut, "retries:     1") {
		t.Errorf("verbose output missing retries:\n%s", errOut)
	}
	if out != "query,status\na.test,NOERROR\ndrop.test,ERROR\n" {
		t.Errorf("results must still be written, got %q", out)
	}
	if err == nil || err.Error() != "1 of 2 queries failed (1 with status ERROR)" || exitCode(err) != 2 {
		t.Errorf("got %v (exit %d), want exit 2", err, exitCode(err))
	}
	// A filtered-out failure still counts.
	if _, _, err := execute(t, "", "drop.test", "--server", server, "--timeout", "100ms", "--retries", "0",
		"--match-fields", "status=NOERROR"); exitCode(err) != 2 {
		t.Errorf("filtered failure: got %v", err)
	}
	// NXDOMAIN is an answer, not a failure.
	if _, _, err := execute(t, "", "missing.test", "--server", server); err != nil {
		t.Errorf("NXDOMAIN: got %v", err)
	}
	if exitCode(errors.New("bad flag")) != 1 {
		t.Error("usage errors must exit 1")
	}
}

func TestServerListFailover(t *testing.T) {
	server := startServer(t)
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dead.Close() }()
	out, _, err := execute(t, "", "a.test", "--server", dead.LocalAddr().String()+","+server,
		"--timeout", "100ms", "--output", "csv", "--select-fields", "status,server")
	if err != nil || out != "status,server\nNOERROR,"+server+"\n" {
		t.Errorf("got %q, %v", out, err)
	}
}

func TestStreamKeepsOrder(t *testing.T) {
	server := startServer(t)
	var in strings.Builder
	var want strings.Builder
	want.WriteString("query\n")
	for i := range 300 {
		fmt.Fprintf(&in, "slow%d.test\n", i)
		fmt.Fprintf(&want, "slow%d.test\n", i)
	}
	out, _, err := execute(t, in.String(), "--server", server, "--concurrency", "16", "--rate", "0", "--output", "csv", "--select-fields", "query")
	if err != nil || out != want.String() {
		t.Errorf("output out of order or incomplete (err %v)", err)
	}
}

func TestLookupStreamIsBounded(t *testing.T) {
	server := startServer(t)
	res := &dnsq.Resolver{Servers: []string{server}, Timeout: time.Second}
	const workers = 4
	var mu sync.Mutex
	read := 0
	next := func() (string, bool) {
		mu.Lock()
		defer mu.Unlock()
		read++
		return "a.test", true // endless input
	}
	emitted := 0
	stopErr := errors.New("stop")
	lookup := func(ctx context.Context, input string) []dnsq.Row { return res.Lookup(ctx, input, dns.TypeA, false) }
	err := lookupStream(context.Background(), lookup, "a.test", next, workers, func([]dnsq.Row) error {
		emitted++
		mu.Lock()
		ahead := read - emitted
		mu.Unlock()
		// Jobs queued in pending, running in workers, and the one the
		// producer holds are the only inputs read ahead of emit.
		if limit := 3*workers + 2; ahead > limit {
			t.Fatalf("read %d inputs ahead of output, limit %d", ahead, limit)
		}
		if emitted == 200 {
			return stopErr
		}
		return nil
	})
	if !errors.Is(err, stopErr) {
		t.Errorf("got %v, want emit error", err)
	}
}

func TestRateLimit(t *testing.T) {
	server := startServer(t)
	domains := "a.test\nb.test\nc.test\nd.test\ne.test\n"
	start := time.Now()
	_, errOut, err := execute(t, domains, "--server", server, "--rate", "10", "--verbose")
	// Burst 1 at 10/s: the first query goes at once, the other four 100ms apart.
	if elapsed := time.Since(start); err != nil || elapsed < 380*time.Millisecond {
		t.Errorf("5 queries at --rate 10 took %v, want >= 400ms (err %v)", elapsed, err)
	}
	if !strings.Contains(errOut, "10 queries/s") {
		t.Errorf("verbose output missing rate:\n%s", errOut)
	}
	_, errOut, _ = execute(t, "a.test", "--server", server, "--rate", "0", "--verbose")
	if !strings.Contains(errOut, "unlimited") {
		t.Errorf("--rate 0 should be unlimited:\n%s", errOut)
	}
}

func TestDNSSECAgainstStrippingResolver(t *testing.T) {
	server := startServer(t)
	out, errOut, err := execute(t, "", "a.test", "--server", server, "--dnssec", "--verbose", "--output", "csv")
	if !strings.Contains(out, "query,status,name,type,ttl,value,dnssec\n") || !strings.Contains(out, ",bogus\n") {
		t.Errorf("default fields should include dnssec and report bogus:\n%s", out)
	}
	if exitCode(err) != 2 || err.Error() != "1 of 1 queries failed (1 DNSSEC bogus)" {
		t.Errorf("got %v (exit %d)", err, exitCode(err))
	}
	for _, want := range []string{"dnssec:      validating (built-in IANA root anchors)", "cache:       10000 responses"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("verbose missing %q:\n%s", want, errOut)
		}
	}
	out, _, _ = execute(t, "", "a.test", "--server", server, "--dnssec", "--explain", "--select-fields", "explanation")
	if !strings.Contains(out, "A validating resolver would refuse this answer") {
		t.Errorf("explanation should describe the bogus result:\n%s", out)
	}
}

func TestTraceFlag(t *testing.T) {
	server := startServer(t)
	out, errOut, err := execute(t, "", "a.test", "--server", server, "--trace", "--output", "csv", "--select-fields", "value")
	if err != nil || out != "value\n192.0.2.1\n" {
		t.Errorf("trace must not change stdout: %q, %v", out, err)
	}
	if !strings.Contains(errOut, "trace a.test: "+server+" udp a.test. A -> NOERROR, answer 1") {
		t.Errorf("trace missing from stderr:\n%s", errOut)
	}
	if _, errOut, _ = execute(t, "", "a.test", "--server", server); strings.Contains(errOut, "trace") {
		t.Errorf("no trace without --trace:\n%s", errOut)
	}
}

func TestCacheAnswersDuplicates(t *testing.T) {
	server := startServer(t)
	out, _, err := execute(t, "a.test\na.test\n", "--server", server, "--concurrency", "1", "--output", "csv", "--select-fields", "query,cached")
	if err != nil || out != "query,cached\na.test,false\na.test,true\n" {
		t.Errorf("got %q, %v", out, err)
	}
	out, errOut, err := execute(t, "a.test\na.test\n", "--server", server, "--concurrency", "1", "--cache-size", "0",
		"--output", "csv", "--select-fields", "cached", "--verbose")
	if err != nil || out != "cached\nfalse\nfalse\n" || !strings.Contains(errOut, "cache:       off") {
		t.Errorf("--cache-size 0: got %q, %v\n%s", out, err, errOut)
	}
}

func TestSelectFieldsAll(t *testing.T) {
	server := startServer(t)
	out, _, err := execute(t, "", "a.test", "--server", server, "--output", "csv", "--select-fields", "all")
	want := "query,qtype,status,name,name_unicode,type,ttl,value,zone,ns,serial,check,server,protocol,rtt_ms,authoritative,error,cached,ede,nsid,ecs,dnssec,dnssec_reason,explanation\n"
	if err != nil || !strings.HasPrefix(out, want) {
		t.Errorf("got %q, %v", out, err)
	}
}

func TestInternationalizedQuery(t *testing.T) {
	server := startServer(t)
	out, _, err := execute(t, "", "räksmörgås.test", "--server", server, "--output", "csv",
		"--select-fields", "query,status,name,name_unicode,value")
	want := "query,status,name,name_unicode,value\nräksmörgås.test,NOERROR,xn--rksmrgs-5wao1o.test.,räksmörgås.test.,192.0.2.1\n"
	if err != nil || out != want {
		t.Errorf("got %q, %v", out, err)
	}
}

func TestNoReplyLeavesReplyFieldsEmpty(t *testing.T) {
	server := startServer(t)
	out, _, _ := execute(t, "", "a.test", "drop.test", "--server", server, "--timeout", "100ms", "--retries", "0",
		"--output", "csv", "--select-fields", "query,status,authoritative,rtt_ms")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "a.test,NOERROR,false,") || lines[2] != "drop.test,ERROR,," {
		t.Errorf("got:\n%s", out)
	}
}

func TestQueryFailuresMessage(t *testing.T) {
	e := &queryFailuresError{nameservers: 1, unchecked: 2, total: 5}
	if got := e.Error(); got != "3 of 5 queries failed (1 with nameserver problems, 2 where no nameserver could be reached from this host)" || exitCode(e) != 2 {
		t.Errorf("got %q", got)
	}
}

func TestListFields(t *testing.T) {
	out, _, err := execute(t, "", "--list-fields")
	if err != nil || !strings.Contains(out, "rtt_ms") || !strings.Contains(out, "explanation") {
		t.Errorf("got %q, %v", out, err)
	}
}

func TestErrors(t *testing.T) {
	cases := map[string][]string{
		"unknown record type":           {"a.test", "--type", "BOGUS"},
		"require --type SOA":            {"a.test", "--try-to-resolve"},
		"--type SOA (alone)":            {"a.test", "--type", "SOA,A", "--try-to-resolve"},
		"unknown record type \"BOGUS\"": {"a.test", "--type", "A,BOGUS"},
		"no record type":                {"a.test", "--type", " , "},
		"needs at least two servers":    {"a.test", "--compare-servers", "--server", "192.0.2.1"},
		"--compare-servers cannot be":   {"a.test", "--compare-servers", "--server", "192.0.2.1,192.0.2.2", "--dnssec"},
		"invalid --ecs":                 {"a.test", "--ecs", "bogus"},
		"--dns-posture cannot be":       {"a.test", "--dns-posture", "--check-nameservers"},
		"leave out --type":              {"a.test", "--dns-posture", "--type", "MX"},
		"unknown field":                 {"a.test", "--select-fields", "nope"},
		"want field=value":              {"a.test", "--match-fields", "status"},
		"invalid --output":              {"a.test", "--output", "out.pdf"},
		"concurrency":                   {"a.test", "--concurrency", "0"},
		"timeout":                       {"a.test", "--timeout", "0s"},
		"retries":                       {"a.test", "--retries", "-1"},
		"rate":                          {"a.test", "--rate", "-1"},
		"cache-size":                    {"a.test", "--cache-size", "-1"},
		"cannot be combined":            {"a.test", "--check-nameservers", "--dnssec"},
		"only root zone":                {"a.test", "--dnssec", "--trust-anchor", "testdata/example-anchor.txt"},
		"no such file or directory":     {"a.test", "--dnssec", "--trust-anchor", "/nonexistent/anchors.txt"},
		"invalid server":                {"a.test", "--server", ":53"},
		"no such file":                  {"--file", "/nonexistent/domains.txt", "--server", "127.0.0.1"},
		"no domains given":              {"--server", "127.0.0.1"},
		"no such file or dir":           {"a.test", "--server", "127.0.0.1", "--output", "/nonexistent/dir/out.csv"},
	}
	for want, args := range cases {
		if _, _, err := execute(t, "", args...); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: want error containing %q, got %v", args, want, err)
		}
	}
}

func TestResolveServers(t *testing.T) {
	cases := map[string]string{
		"192.0.2.53":      "192.0.2.53:53",
		"192.0.2.53:5353": "192.0.2.53:5353",
		"2001:db8::1":     "[2001:db8::1]:53",
		"[2001:db8::1]":   "[2001:db8::1]:53",
		"[::1]:5353":      "[::1]:5353",
	}
	for in, want := range cases {
		if got, err := dnsq.ParseServer(in); err != nil || got != want {
			t.Errorf("ParseServer(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	got, err := resolveServers([]string{"192.0.2.1", " ", "192.0.2.2:5353"})
	if err != nil || strings.Join(got, " ") != "192.0.2.1:53 192.0.2.2:5353" {
		t.Errorf("resolveServers list: %v, %v", got, err)
	}
	if _, err := os.Stat("/etc/resolv.conf"); err == nil {
		if got, err := resolveServers(nil); err != nil || len(got) == 0 {
			t.Errorf("resolv.conf default: %v, %v", got, err)
		}
	}
}

// startDoH runs a DoH server with httptest's self-signed certificate that
// answers 192.0.2.7 for any A query.
func startDoH(t *testing.T) *httptest.Server {
	t.Helper()
	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req := new(dns.Msg)
		if req.Unpack(body) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 7)})
		wire, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	t.Cleanup(doh.Close)
	return doh
}

// TestTLSInsecure queries a DoH server with a self-signed certificate:
// rejected by default, accepted with --tls-insecure and a warning.
func TestTLSInsecure(t *testing.T) {
	server := startDoH(t).URL + "/dns-query"
	out, _, err := execute(t, "", "a.test", "--server", server, "--select-fields", "status,error")
	if !errors.As(err, new(*queryFailuresError)) || !strings.Contains(out, "certificate") {
		t.Errorf("without --tls-insecure: err %v, output %q", err, out)
	}
	out, errOut, err := execute(t, "", "a.test", "--server", server, "--tls-insecure", "--verbose", "--select-fields", "value,protocol")
	if err != nil || !strings.Contains(out, "192.0.2.7  https") {
		t.Errorf("with --tls-insecure: err %v, output %q", err, out)
	}
	if !strings.Contains(errOut, "warning: --tls-insecure") || !strings.Contains(errOut, "NOT checked") {
		t.Errorf("no warning on stderr: %q", errOut)
	}
	// Plain servers have no certificates to warn about.
	_, errOut, _ = execute(t, "", "a.test", "--server", startServer(t), "--tls-insecure")
	if strings.Contains(errOut, "warning") {
		t.Errorf("warning without encrypted servers: %q", errOut)
	}
}

// TestTLSCA trusts the DoH server's private certificate with --tls-ca,
// which keeps the certificate check on.
func TestTLSCA(t *testing.T) {
	doh := startDoH(t)
	server := doh.URL + "/dns-query"
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: doh.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, err := execute(t, "", "a.test", "--server", server, "--tls-ca", ca, "--verbose", "--select-fields", "value,protocol")
	if err != nil || !strings.Contains(out, "192.0.2.7  https") {
		t.Errorf("with --tls-ca: err %v, output %q", err, out)
	}
	if strings.Contains(errOut, "warning") || !strings.Contains(errOut, "checked (system CAs and "+ca+")") {
		t.Errorf("stderr %q", errOut)
	}
	// The check is still on: the certificate must match the server name.
	out, _, err = execute(t, "", "a.test", "--server", server+"#other.test", "--tls-ca", ca, "--select-fields", "status,error")
	if !errors.As(err, new(*queryFailuresError)) || !strings.Contains(out, "certificate") {
		t.Errorf("wrong name with --tls-ca: err %v, output %q", err, out)
	}

	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--tls-ca", filepath.Join(dir, "missing.pem")}, "no such file"},
		{[]string{"--tls-ca", notPEM}, "no PEM certificates"},
		{[]string{"--tls-ca", ca, "--tls-insecure"}, "cannot be combined"},
	} {
		_, _, err := execute(t, "", append([]string{"a.test", "--server", server}, tc.args...)...)
		if err == nil || !strings.Contains(err.Error(), tc.want) || exitCode(err) != 1 {
			t.Errorf("%v: want error containing %q, got %v", tc.args, tc.want, err)
		}
	}
}

func TestParseTypes(t *testing.T) {
	got, err := parseTypes([]string{"a, AAAA,,mx", "A", "TYPE65"})
	want := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, 65}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("parseTypes = %v, %v; want %v", got, err, want)
	}
}

// TestSeveralTypes checks that each input is queried for each type, with
// output grouped by input and types in the order given, even when answers
// arrive out of order.
func TestSeveralTypes(t *testing.T) {
	server := startServer(t)
	var in, want strings.Builder
	for i := range 30 {
		fmt.Fprintf(&in, "slow%d.test\n", i)
		for _, qt := range []string{"MX", "A", "TXT"} {
			fmt.Fprintf(&want, "slow%d.test,%s\n", i, qt)
		}
	}
	out, errOut, err := execute(t, in.String(), "--server", server, "--rate", "0", "--type", "mx,A,TXT,a",
		"--output", "csv", "--select-fields", "query,qtype", "--verbose")
	if err != nil || out != "query,qtype\n"+want.String() {
		t.Errorf("err %v, output:\n%s", err, out)
	}
	if !regexp.MustCompile(`(?m)^type: +MX,A,TXT$`).MatchString(errOut) {
		t.Errorf("verbose: %q", errOut)
	}

	// Each input and type is one query for the exit status.
	_, _, err = execute(t, "", "a..test", "a.test", "--server", server, "--type", "A,MX")
	var qf *queryFailuresError
	if !errors.As(err, &qf) || qf.Error() != "2 of 4 queries failed (2 with status ERROR)" {
		t.Errorf("got %v", err)
	}

	// A config file may list the types; the environment takes a string.
	cfg := filepath.Join(t.TempDir(), "dnsquery.yaml")
	if err := os.WriteFile(cfg, []byte("type: [A, MX]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, err = execute(t, "", "a.test", "--server", server, "--config", cfg, "--output", "csv", "--select-fields", "type")
	if err != nil || out != "type\nA\nMX\n" {
		t.Errorf("config list: got %q, %v", out, err)
	}
	t.Setenv("DNSQUERY_TYPE", "MX,A")
	out, _, err = execute(t, "", "a.test", "--server", server, "--output", "csv", "--select-fields", "type")
	if err != nil || out != "type\nMX\nA\n" {
		t.Errorf("env: got %q, %v", out, err)
	}
}

// TestCompareServersFlag compares a resolver with itself (agreement) and
// with an address where nothing answers (exit status 2).
func TestCompareServersFlag(t *testing.T) {
	a, b := startServer(t), startServer(t)
	out, errOut, err := execute(t, "", "a.test", "--compare-servers", "--server", a+","+b, "--ecs", "192.0.2.0/24", "--verbose", "--output", "csv")
	if err != nil || out != "query,qtype,server,status,value,check,ecs\na.test,A,"+a+",NOERROR,A 192.0.2.1,,\na.test,A,"+b+",NOERROR,A 192.0.2.1,,\n" {
		t.Errorf("agreeing servers: err %v, output:\n%s", err, out)
	}
	if !strings.Contains(errOut, "compare servers") || !strings.Contains(errOut, "192.0.2.0/24") {
		t.Errorf("verbose: %q", errOut)
	}

	out, _, err = execute(t, "", "a.test", "--compare-servers", "--server", a+","+closedServer(t), "--retries", "0", "--select-fields", "status,check")
	var qf *queryFailuresError
	if !errors.As(err, &qf) || qf.Error() != "1 of 1 queries failed (1 where servers disagreed or did not reply)" || !strings.Contains(out, "no usable reply") {
		t.Errorf("err %v, output:\n%s", err, out)
	}
}

// closedServer returns a UDP address with nothing listening.
func closedServer(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

// TestDNSPostureFlag runs the posture against the test resolver, which has
// MX records for a.test but no SPF, DMARC, DKIM, NS or CAA.
func TestDNSPostureFlag(t *testing.T) {
	server := startServer(t)
	out, errOut, err := execute(t, "", "a.test", "--dns-posture", "--server", server, "--rate", "0", "--verbose", "--output", "csv")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"query,qtype,status,name,value,check",
		"a.test,MX,NOERROR,a.test.,10 mail.test.,",
		`a.test,SPF,NODATA,a.test.,,"medium: no SPF record`,
		`a.test,DMARC,NODATA,_dmarc.a.test.,,"medium: no DMARC record`,
		`a.test,DKIM,NODATA,_domainkey.a.test.,,"low: no DKIM record`,
		"a.test,NS,NODATA,a.test.,,",
		"a.test,CAA,NODATA,a.test.,,low: no CAA record",
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != len(want) {
		t.Fatalf("got %d lines:\n%s", len(lines), out)
	}
	for i, w := range want {
		if !strings.HasPrefix(lines[i], w) {
			t.Errorf("line %d: %q, want prefix %q", i, lines[i], w)
		}
	}
	if !strings.Contains(errOut, "dns posture") {
		t.Errorf("verbose: %q", errOut)
	}
	// --type from the environment conflicts too.
	t.Setenv("DNSQUERY_TYPE", "TXT")
	if _, _, err := execute(t, "", "a.test", "--dns-posture", "--server", server); err == nil || !strings.Contains(err.Error(), "leave out --type") {
		t.Errorf("DNSQUERY_TYPE with --dns-posture: %v", err)
	}
}
