package dnsq

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestTakeoverProvider(t *testing.T) {
	for name, want := range map[string]string{
		"gone.azurewebsites.net.":                    "Azure App Service",
		"GONE.AzureWebsites.NET":                     "Azure App Service",
		"x.cloudapp.azure.com.":                      "Azure virtual machines",
		"bucket.s3.amazonaws.com.":                   "Amazon S3",
		"bucket.s3-website-eu-west-1.amazonaws.com.": "Amazon S3",
		"bucket.s3.eu-west-1.amazonaws.com.":         "Amazon S3",
		"user.github.io.":                            "GitHub Pages",
		"notazurewebsites.net.":                      "",
		"ec2-1-2-3-4.compute-1.amazonaws.com.":       "",
		"s3.example.com.":                            "",
		"example.org.":                               "",
	} {
		if got := takeoverProvider(name); got != want {
			t.Errorf("takeoverProvider(%s) = %q, want %q", name, got, want)
		}
	}
}

func TestAddFindings(t *testing.T) {
	cname := func(name, target, status string) Row {
		return Row{QType: "A", Status: status, Name: name, Type: "CNAME", Value: target}
	}
	addr := func(name, value string) Row {
		typ := "A"
		if strings.Contains(value, ":") {
			typ = "AAAA"
		}
		return Row{QType: typ, Status: StatusNoError, Name: name, Type: typ, Value: value}
	}
	cases := []struct {
		name string
		rows []Row
		want []string // check prefix per row; "" = none
	}{
		{"provider target", []Row{cname("shop.example.", "gone.azurewebsites.net.", "NXDOMAIN")},
			[]string{"high: dangling CNAME: shop.example points to gone.azurewebsites.net, which does not exist (NXDOMAIN); whoever creates that name at Azure App Service"}},
		{"chain, end dangles", []Row{cname("a.example.", "b.example.", "NXDOMAIN"), cname("b.example.", "gone.example.org.", "NXDOMAIN")},
			[]string{"", "medium: dangling CNAME: b.example points to gone.example.org"}},
		{"target exists", []Row{cname("a.example.", "b.example.", StatusNoError), addr("b.example.", "192.0.2.80")},
			[]string{"", "low: documentation address 192.0.2.80"}},
		{"NODATA target is not dangling", []Row{cname("a.example.", "b.example.", StatusNoData)}, []string{""}},
		{"CNAME query", []Row{{QType: "CNAME", Status: "NXDOMAIN", Name: "a.example.", Type: "CNAME", Value: "b.example."}}, []string{""}},
		{"existing check kept", []Row{{QType: "A", Status: StatusNoError, Name: "a.example.", Type: "A", Value: "10.0.0.1", Check: "other"}}, []string{"other"}},
		{"addresses", []Row{
			addr("a.example.", "10.1.2.3"), addr("a.example.", "172.16.0.1"), addr("a.example.", "192.168.1.1"),
			addr("a.example.", "172.32.0.1"), addr("a.example.", "127.0.0.1"), addr("a.example.", "0.0.0.0"),
			addr("a.example.", "169.254.169.254"), addr("a.example.", "100.64.1.1"), addr("a.example.", "240.0.0.1"),
			addr("a.example.", "224.0.0.1"), addr("a.example.", "8.8.8.8"), addr("a.example.", "fd00::1"),
			addr("a.example.", "fe80::1"), addr("a.example.", "::1"), addr("a.example.", "::"), addr("a.example.", "2001:db8::1"),
			addr("a.example.", "2606:4700::1"), addr("a.example.", "::ffff:10.0.0.1"),
		}, []string{
			"low: private address 10.1.2.3", "low: private address 172.16.0.1", "low: private address 192.168.1.1",
			"", "low: loopback", "low: unspecified", "low: link-local", "low: shared address", "low: reserved",
			"low: reserved", "", "low: private address fd00::1", "low: link-local", "low: loopback", "low: unspecified",
			"low: documentation", "", "low: private address 10.0.0.1",
		}},
		{"internal names", []Row{addr("nas.home.arpa.", "192.168.1.2"), addr("printer.local.", "10.0.0.9"), addr("db.corp.", "10.0.0.8")},
			[]string{"", "", ""}},
		{"NXDOMAIN without CNAME", []Row{{QType: "A", Status: "NXDOMAIN", Name: "nope.example."}}, []string{""}},
	}
	for _, tc := range cases {
		AddFindings(tc.rows)
		for i, w := range tc.want {
			got := tc.rows[i].Check
			if w == "" && got != "" || !strings.HasPrefix(got, w) {
				t.Errorf("%s: row %d (%s): check %q, want prefix %q", tc.name, i, tc.rows[i].Value, got, w)
			}
		}
	}
}

func TestFindingsFromLookup(t *testing.T) {
	hdr := func(name string, typ uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: typ, Class: dns.ClassINET, Ttl: 300}
	}
	server := startServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		switch req.Question[0].Name {
		case "shop.example.":
			// RFC 6604: the RCODE is that of the last name in the chain.
			m.Rcode = dns.RcodeNameError
			m.Answer = []dns.RR{
				&dns.CNAME{Hdr: hdr("shop.example.", dns.TypeCNAME), Target: "shop-cdn.example."},
				&dns.CNAME{Hdr: hdr("shop-cdn.example.", dns.TypeCNAME), Target: "old-shop.azurewebsites.net."},
			}
		case "intranet.example.":
			m.Answer = []dns.RR{&dns.A{Hdr: hdr("intranet.example.", dns.TypeA), A: net.ParseIP("10.20.30.40")}}
		}
		_ = w.WriteMsg(m)
	})
	r := &Resolver{Servers: []string{server}, Timeout: time.Second}
	rows := r.Lookup(context.Background(), "shop.example", dns.TypeA, false)
	AddFindings(rows)
	if len(rows) != 2 || rows[0].Check != "" || !strings.Contains(rows[1].Check, "high: dangling CNAME: shop-cdn.example points to old-shop.azurewebsites.net") {
		t.Fatalf("dangling chain: %+v", rows)
	}
	if e := Explain(rows[1]); !strings.Contains(e, "alias target does not exist") {
		t.Errorf("explanation: %s", e)
	}
	rows = r.Lookup(context.Background(), "intranet.example", dns.TypeA, false)
	AddFindings(rows)
	if !strings.HasPrefix(rows[0].Check, "low: private address 10.20.30.40") {
		t.Errorf("private address: %+v", rows[0])
	}
}
