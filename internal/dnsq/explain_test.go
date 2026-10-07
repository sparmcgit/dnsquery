package dnsq

import (
	"bytes"
	"strings"
	"testing"
)

func TestExplainRecordTypes(t *testing.T) {
	cases := []struct {
		row  Row
		want string
	}{
		{Row{Type: "A", Name: "a.test.", Value: "192.0.2.1"}, "a.test has IPv4 address 192.0.2.1."},
		{Row{Type: "AAAA", Name: "a.test.", Value: "2001:db8::1"}, "IPv6 address 2001:db8::1"},
		{Row{Type: "CNAME", Name: "www.test.", Value: "a.test."}, "www.test is an alias for a.test."},
		{Row{Type: "NS", Name: "test.", Value: "ns1.test."}, "served by name server ns1.test."},
		{Row{Type: "PTR", Name: "1.2.0.192.in-addr.arpa.", Value: "a.test."}, "points back to host name a.test"},
		{Row{Type: "SOA", Name: "test.", Value: "ns1.test. admin.test. 7 1 2 3 4"}, "primary server (MNAME) ns1.test, contact admin.test, serial 7"},
		{Row{Type: "TXT", Name: "test.", Value: `"v=spf1 -all"`}, "an SPF policy"},
		{Row{Type: "TXT", Name: "_dmarc.test.", Value: `"v=DMARC1; p=none"`}, "a DMARC policy"},
		{Row{Type: "TXT", Name: "k._domainkey.test.", Value: `"v=DKIM1; p=abc"`}, "a DKIM public key"},
		{Row{Type: "TXT", Name: "test.", Value: `"hello"`}, "publishes a text record"},
		{Row{Type: "SRV", Name: "_sip._tcp.test.", Value: "1 2 5060 sip.test."}, "provided by sip.test port 5060 (priority 1, weight 2)"},
		{Row{Type: "CAA", Name: "test.", Value: `0 issue "ca.example"`}, "restricts certificate issuance"},
		{Row{Type: "HINFO", Name: "test.", Value: `"cpu" "os"`}, "has a HINFO record"},
	}
	for _, c := range cases {
		c.row.Status = StatusNoError
		if got := Explain(c.row); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q does not contain %q", c.row.Type, got, c.want)
		}
	}
}

func TestExplainStatuses(t *testing.T) {
	cases := []struct {
		row  Row
		want string
	}{
		{Row{Status: StatusNoData, Name: "a.test.", Type: "MX", QType: "MX", TTL: 60, HasTTL: true, Zone: "test."}, "cache this negative answer for 60 seconds (zone test)"},
		{Row{Status: "SERVFAIL"}, "SERVFAIL"},
		{Row{Status: "REFUSED", Server: "192.0.2.53:53"}, "192.0.2.53:53 refused"},
		{Row{Status: StatusError, Name: "a.test.", Error: "i/o timeout"}, "i/o timeout"},
		{Row{Status: "NOTIMP"}, "response code NOTIMP"},
	}
	for _, c := range cases {
		if got := Explain(c.row); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q does not contain %q", c.row.Status, got, c.want)
		}
	}
	if host(".") != "." {
		t.Error("root name must stay as .")
	}
}

func TestStreamingWriters(t *testing.T) {
	fields, _ := SelectFields([]string{"name", "ttl"}, FieldOptions{})
	var b bytes.Buffer
	for format, want := range map[string]string{"json": "[]\n", "yaml": "[]\n", "csv": "name,ttl\n", "text": "NAME  TTL\n"} {
		b.Reset()
		if err := Write(&b, format, fields, nil); err != nil || b.String() != want {
			t.Errorf("%s with no rows: %q, %v", format, b.String(), err)
		}
	}
	rows := []Row{{Name: "a.", TTL: 1, HasTTL: true}, {Name: "b."}}
	b.Reset()
	if err := Write(&b, "json", fields, rows); err != nil {
		t.Fatal(err)
	}
	if want := "[\n  {\n    \"name\": \"a.\",\n    \"ttl\": 1\n  },\n  {\n    \"name\": \"b.\",\n    \"ttl\": null\n  }\n]\n"; b.String() != want {
		t.Errorf("json:\n%s", b.String())
	}
	b.Reset()
	if err := Write(&b, "yaml", fields, rows); err != nil || b.String() != "- name: a.\n  ttl: 1\n- name: b.\n  ttl: null\n" {
		t.Errorf("yaml: %q, %v", b.String(), err)
	}

	// Text output is flushed in blocks, so a long run is written before Close.
	b.Reset()
	rw, _ := NewWriter(&b, "text", fields)
	for range textBlockRows {
		_ = rw.WriteRow(Row{Name: "a."})
	}
	if n := strings.Count(b.String(), "\n"); n != textBlockRows+1 {
		t.Errorf("text wrote %d lines before Close, want %d", n, textBlockRows+1)
	}
	_ = rw.Close()
}

func TestDefaultFieldsFollowFlags(t *testing.T) {
	names := func(opts FieldOptions, explicit ...string) string {
		fields, err := SelectFields(explicit, opts)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, f := range fields {
			out = append(out, f.Name)
		}
		return strings.Join(out, ",")
	}
	cases := []struct {
		opts     FieldOptions
		explicit []string
		want     string
	}{
		{FieldOptions{}, nil, "query,status,name,type,ttl,value"},
		{FieldOptions{NSID: true}, nil, "query,status,name,type,ttl,value,nsid"},
		{FieldOptions{DNSSEC: true, NSID: true, Explain: true}, nil, "query,status,name,type,ttl,value,dnssec,nsid,explanation"},
		{FieldOptions{Defaults: CheckFields, NSID: true}, nil, "query,ns,server,status,serial,authoritative,value,check,nsid"},
		// Explicit names are used as given; only --explain still appends.
		{FieldOptions{DNSSEC: true, NSID: true}, []string{"query", "value"}, "query,value"},
		{FieldOptions{NSID: true, Explain: true}, []string{"query"}, "query,explanation"},
	}
	for _, c := range cases {
		if got := names(c.opts, c.explicit...); got != c.want {
			t.Errorf("%+v %v: got %s, want %s", c.opts, c.explicit, got, c.want)
		}
	}
}

func TestSelectAllFields(t *testing.T) {
	all, err := SelectFields([]string{"all"}, FieldOptions{})
	if err != nil || len(all) != len(Fields) {
		t.Fatalf("all: %d fields, %v", len(all), err)
	}
	for i, f := range all {
		if f.Name != Fields[i].Name {
			t.Errorf("all[%d] = %s, want %s", i, f.Name, Fields[i].Name)
		}
	}
	mixed, err := SelectFields([]string{"status", " ALL ", "query", "status"}, FieldOptions{Explain: true, DNSSEC: true})
	if err != nil || len(mixed) != len(Fields) || mixed[0].Name != "status" || mixed[1].Name != "query" {
		t.Errorf("mixed: %v, %v", mixed, err)
	}
	if _, err := SelectFields([]string{"nope"}, FieldOptions{}); err == nil || !strings.Contains(err.Error(), `use "all"`) {
		t.Errorf("unknown field error should mention all: %v", err)
	}
}

func TestParseType(t *testing.T) {
	for in, want := range map[string]uint16{"a": 1, " MX ": 15, "TYPE65": 65} {
		if got, err := ParseType(in); err != nil || got != want {
			t.Errorf("ParseType(%q) = %d, %v", in, got, err)
		}
	}
	for _, in := range []string{"BOGUS", "TYPE99999"} {
		if _, err := ParseType(in); err == nil {
			t.Errorf("ParseType(%q): expected error", in)
		}
	}
	if typeString(65) != "HTTPS" || typeString(65000) != "TYPE65000" {
		t.Error("typeString fallback")
	}
}

func TestTextAndCSV(t *testing.T) {
	fields, err := SelectFields([]string{"Name", "name", "rtt_ms", "value"}, FieldOptions{Explain: true})
	if err != nil || len(fields) != 4 {
		t.Fatalf("SelectFields dedupe/explain: %d fields, %v", len(fields), err)
	}
	rows := []Row{{Name: "a.test.", Value: "\"tab\there\""}}
	var b bytes.Buffer
	if err := Write(&b, "text", fields, rows); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), "NAME") || strings.Contains(b.String(), "tab\there") {
		t.Errorf("text:\n%s", b.String())
	}
	b.Reset()
	if err := Write(&b, "csv", fields, rows); err != nil || !strings.HasPrefix(b.String(), "name,rtt_ms,value,explanation\n") {
		t.Errorf("csv: %q, %v", b.String(), err)
	}
	if err := Write(&b, "pdf", fields, rows); err == nil {
		t.Error("expected unknown format error")
	}
}
