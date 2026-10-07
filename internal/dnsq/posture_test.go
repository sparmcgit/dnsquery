package dnsq

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// postureZone serves mail and zone records for the posture tests:
//
//	posture.test        MX, SPF (plus an unrelated TXT), NS, CAA
//	_dmarc.posture.test DMARC; selector1._domainkey: DKIM split in two strings
//	www.posture.test    alias (CNAME) of cdn.other.test, nothing of its own
//	nomail.test         MX only
//	nullmx.test         null MX (RFC 7505), nothing else
//	twospf.test         MX and two SPF records
//	broken.test         SERVFAIL for every name under it
func postureZone(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	q := req.Question[0]
	hdr := func(name string, t uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: 300}
	}
	txt := func(name string, s ...string) dns.RR { return &dns.TXT{Hdr: hdr(name, dns.TypeTXT), Txt: s} }
	mx := func(name, host string, pref uint16) dns.RR {
		return &dns.MX{Hdr: hdr(name, dns.TypeMX), Preference: pref, Mx: host}
	}
	add := func(rrs ...dns.RR) {
		for _, rr := range rrs {
			if rr.Header().Rrtype == q.Qtype || rr.Header().Rrtype == dns.TypeCNAME {
				m.Answer = append(m.Answer, rr)
			}
		}
	}
	switch strings.ToLower(q.Name) {
	case "posture.test.":
		add(mx(q.Name, "mx2.posture.test.", 20), mx(q.Name, "mx1.posture.test.", 10),
			txt(q.Name, "google-site-verification=abc"), txt(q.Name, "v=spf1 mx -all"),
			&dns.NS{Hdr: hdr(q.Name, dns.TypeNS), Ns: "ns1.posture.test."},
			&dns.CAA{Hdr: hdr(q.Name, dns.TypeCAA), Tag: "issue", Value: "letsencrypt.org"})
	case "_dmarc.posture.test.":
		add(txt(q.Name, "v=DMARC1; p=reject"))
	case "selector1._domainkey.posture.test.":
		add(txt(q.Name, "v=DKIM1; k=rsa; ", "p=MIIBIjAN"))
	case "www.posture.test.":
		// Resolvers follow the alias: an NS query returns the target's NS.
		add(&dns.CNAME{Hdr: hdr(q.Name, dns.TypeCNAME), Target: "cdn.other.test."},
			&dns.NS{Hdr: hdr("cdn.other.test.", dns.TypeNS), Ns: "ns.cdn.test."})
	case "nomail.test.":
		add(mx(q.Name, "mx.nomail.test.", 10))
	case "nullmx.test.":
		add(mx(q.Name, ".", 0))
	case "twospf.test.":
		add(mx(q.Name, "mx.twospf.test.", 10), txt(q.Name, "v=spf1 -all"), txt(q.Name, "v=spf1 mx -all"))
	default:
		m.Rcode = dns.RcodeNameError
		if strings.HasSuffix(q.Name, "broken.test.") {
			m.Rcode = dns.RcodeServerFailure
		}
	}
	_ = w.WriteMsg(m)
}

// postureRows runs DNSPosture and indexes the rows by kind.
func postureRows(t *testing.T, input string) map[string][]Row {
	t.Helper()
	r := &Resolver{Servers: []string{startServer(t, postureZone)}, Timeout: time.Second, Cache: NewCache(100)}
	out := map[string][]Row{}
	for _, row := range r.DNSPosture(context.Background(), input) {
		out[row.QType] = append(out[row.QType], row)
	}
	return out
}

func TestDNSPostureFallsBackToOrganizationalDomain(t *testing.T) {
	rows := postureRows(t, "www.posture.test")
	want := map[string][]string{
		"MX":    {"posture.test. 10 mx1.posture.test.", "posture.test. 20 mx2.posture.test."},
		"SPF":   {"posture.test. v=spf1 mx -all"},
		"DMARC": {"_dmarc.posture.test. v=DMARC1; p=reject"},
		"DKIM":  {"selector1._domainkey.posture.test. v=DKIM1; k=rsa; p=MIIBIjAN"},
		// Not the alias target's ns.cdn.test.
		"NS":  {"posture.test. ns1.posture.test."},
		"CAA": {`posture.test. 0 issue "letsencrypt.org"`},
	}
	for kind, values := range want {
		var got []string
		for _, r := range rows[kind] {
			got = append(got, r.Name+" "+r.Value)
			if r.Status != StatusNoError || r.Check != "" || r.Query != "www.posture.test" {
				t.Errorf("%s: status %s, check %q, query %q", kind, r.Status, r.Check, r.Query)
			}
		}
		if strings.Join(got, "|") != strings.Join(values, "|") {
			t.Errorf("%s: got %q, want %q", kind, got, values)
		}
	}
}

func TestDNSPostureFindings(t *testing.T) {
	rows := postureRows(t, "nomail.test")
	for kind, want := range map[string]string{
		"SPF":   "medium: no SPF record",
		"DMARC": "medium: no DMARC record",
		"DKIM":  "low: no DKIM record for the common selectors (default, google, k1, k2, selector1, selector2)",
		"CAA":   "low: no CAA record",
		"MX":    "",
	} {
		if len(rows[kind]) != 1 || !strings.HasPrefix(rows[kind][0].Check, want) || want == "" && rows[kind][0].Check != "" {
			t.Errorf("%s: %+v, want check starting %q", kind, rows[kind], want)
		}
	}
	if r := rows["DMARC"][0]; r.Status != "NXDOMAIN" || r.Name != "_dmarc.nomail.test." {
		t.Errorf("missing DMARC row: status %s, name %s", r.Status, r.Name)
	}
	if r := rows["DKIM"][0]; r.Status != StatusNoData || r.Name != "_domainkey.nomail.test." {
		t.Errorf("missing DKIM row: status %s, name %s", r.Status, r.Name)
	}

	// A null MX means the domain takes no mail: no mail findings.
	rows = postureRows(t, "nullmx.test")
	for _, kind := range []string{"SPF", "DMARC", "DKIM"} {
		if c := rows[kind][0].Check; c != "" {
			t.Errorf("null MX, %s: check %q", kind, c)
		}
	}

	rows = postureRows(t, "twospf.test")
	if len(rows["SPF"]) != 2 || !strings.HasPrefix(rows["SPF"][0].Check, "medium: 2 SPF records") {
		t.Errorf("two SPF records: %+v", rows["SPF"])
	}
}

func TestDNSPostureFailedLookupsAreNotFindings(t *testing.T) {
	for _, rows := range postureRows(t, "broken.test") {
		for _, r := range rows {
			if r.Status != StatusError || r.Check != "" || !strings.Contains(r.Error, "SERVFAIL") {
				t.Errorf("%s: status %s, check %q, error %q", r.QType, r.Status, r.Check, r.Error)
			}
		}
	}
	rows := postureRows(t, "bad..name")
	if len(rows["POSTURE"]) != 1 || rows["POSTURE"][0].Status != StatusError {
		t.Errorf("invalid name: %+v", rows)
	}
}

func TestOrganizationalDomain(t *testing.T) {
	for in, want := range map[string]string{
		"www.gp.se.":             "gp.se.",
		"gp.se.":                 "gp.se.",
		"a.b.example.co.uk.":     "example.co.uk.",
		"www.posture.test.":      "posture.test.",
		"se.":                    "se.",
		"192.0.2.1":              "192.0.2.1",
		"Www.Example.COM.":       "example.com.",
		"foo.blogspot.com.":      "foo.blogspot.com.",
		"xn--rksmrgs-5wao1o.se.": "xn--rksmrgs-5wao1o.se.",
	} {
		if got := OrganizationalDomain(in); got != want {
			t.Errorf("OrganizationalDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
