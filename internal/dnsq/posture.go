package dnsq

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// PostureFields is the default field selection for --dns-posture.
var PostureFields = []string{"query", "qtype", "status", "name", "value", "check"}

// DKIMSelectors are the selectors --dns-posture tries. A domain's real
// selector can be anything, so a missing DKIM record is only a hint.
var DKIMSelectors = []string{"default", "google", "k1", "k2", "selector1", "selector2"}

// postureItem is one kind of record the posture looks up at a name.
type postureItem struct {
	kind  string // shown in the qtype field
	qtype uint16
	// names returns the names to query under a candidate domain.
	names func(domain string) []string
	// match returns the value of rr when it is a record of this kind
	// owned by the queried name.
	match func(rr dns.RR, queried string) (string, bool)
}

var postureItems = []postureItem{
	{"MX", dns.TypeMX, self, rdataOf[*dns.MX]},
	{"SPF", dns.TypeTXT, self, txtWithPrefix("v=spf1")},
	{"DMARC", dns.TypeTXT, func(d string) []string { return []string{"_dmarc." + d} }, txtWithPrefix("v=dmarc1")},
	{"DKIM", dns.TypeTXT, dkimNames, dkimRecord},
	// An NS query for an alias (CNAME) returns the nameservers of the
	// alias target, such as a CDN's, so only NS records owned by the name
	// itself count.
	{"NS", dns.TypeNS, self, func(rr dns.RR, queried string) (string, bool) {
		if !equalName(rr.Header().Name, queried) {
			return "", false
		}
		return rdataOf[*dns.NS](rr, queried)
	}},
	{"CAA", dns.TypeCAA, self, rdataOf[*dns.CAA]},
}

func self(d string) []string { return []string{d} }

func dkimNames(d string) []string {
	names := make([]string, len(DKIMSelectors))
	for i, s := range DKIMSelectors {
		names[i] = s + "._domainkey." + d
	}
	return names
}

// rdataOf matches records of type T and returns their data as text.
func rdataOf[T dns.RR](rr dns.RR, _ string) (string, bool) {
	if _, ok := rr.(T); !ok {
		return "", false
	}
	return strings.TrimPrefix(rr.String(), rr.Header().String()), true
}

// txtText joins the strings of a TXT record, as SPF and DMARC require
// (RFC 7208 section 3.3).
func txtText(rr dns.RR) (string, bool) {
	t, ok := rr.(*dns.TXT)
	if !ok {
		return "", false
	}
	return strings.TrimSpace(strings.Join(t.Txt, "")), true
}

func txtWithPrefix(prefix string) func(dns.RR, string) (string, bool) {
	return func(rr dns.RR, _ string) (string, bool) {
		s, ok := txtText(rr)
		return s, ok && strings.HasPrefix(strings.ToLower(s), prefix)
	}
}

// dkimRecord matches a DKIM key record. Its v= tag is optional (RFC 6376
// section 3.6.1), so a public key tag counts too.
func dkimRecord(rr dns.RR, _ string) (string, bool) {
	s, ok := txtText(rr)
	l := strings.ToLower(s)
	return s, ok && (strings.Contains(l, "v=dkim1") || strings.HasPrefix(l, "p=") || strings.Contains(l, ";p=") || strings.Contains(l, "; p="))
}

// postureResult is what one item found at one candidate domain.
type postureResult struct {
	rows   []Row // found records
	status string
	err    error
}

// DNSPosture looks up the mail and zone records of input: MX, SPF, DMARC,
// DKIM (common selectors), NS and CAA. Each kind is looked up at the name
// itself first and, when nothing is found and the name is a subdomain, at
// its organizational domain (the registrable domain from the public
// suffix list: www.example.co.uk falls back to example.co.uk), since these
// records are usually published at the apex. It returns one row per record
// found, or one row per kind found nowhere, with the check field naming
// what is missing.
func (r *Resolver) DNSPosture(ctx context.Context, input string) []Row {
	ctx = withTraceLabel(ctx, input)
	base := Row{Query: input}
	name, err := Normalize(input, dns.TypeA)
	if err != nil {
		base.Name, base.Status, base.Error, base.QType = input, StatusError, err.Error(), "POSTURE"
		return []Row{base}
	}
	candidates := []string{name}
	if org := OrganizationalDomain(name); !equalName(org, name) {
		candidates = append(candidates, org)
		r.Trace.printf(ctx, "posture: falling back to the organizational domain %s", org)
	}

	results := make([]postureResult, len(postureItems))
	var wg sync.WaitGroup
	for i, item := range postureItems {
		wg.Go(func() { results[i] = r.lookupPosture(ctx, base, item, candidates) })
	}
	wg.Wait()

	mail := receivesMail(results[0])
	var rows []Row
	for i, item := range postureItems {
		res := results[i]
		if len(res.rows) > 0 {
			if n := len(res.rows); n > 1 && (item.kind == "SPF" || item.kind == "DMARC") {
				for j := range res.rows {
					res.rows[j].Check = multipleRecords(item.kind, n)
				}
			}
			rows = append(rows, res.rows...)
			continue
		}
		row := base
		row.QType, row.Type = item.kind, typeString(item.qtype)
		last := candidates[len(candidates)-1]
		row.Name = item.names(last)[0]
		if item.kind == "DKIM" {
			row.Name = "_domainkey." + last
		}
		row.Status = res.status
		if res.err != nil {
			row.Status, row.Error = StatusError, res.err.Error()
		} else {
			row.Check = missing(item.kind, mail)
		}
		rows = append(rows, row)
	}
	return rows
}

// lookupPosture tries item at each candidate in turn and returns the
// records of the first that has any. Without records, the status describes
// the last candidate (the name shown in the row): NXDOMAIN when that name
// does not exist, NODATA otherwise. A lookup that failed (no reply, or an
// rcode such as SERVFAIL) makes the result an error instead, since the
// record may exist.
func (r *Resolver) lookupPosture(ctx context.Context, base Row, item postureItem, candidates []string) postureResult {
	var status string
	var failure error
	for _, domain := range candidates {
		names := item.names(domain)
		found := make([][]Row, len(names))
		rcodes := make([]int, len(names))
		errs := make([]error, len(names))
		var wg sync.WaitGroup
		for i, n := range names {
			wg.Go(func() {
				resp, err := r.query(ctx, n, item.qtype)
				if err != nil {
					errs[i] = err
					return
				}
				rcodes[i] = resp.msg.Rcode
				for _, rr := range resp.msg.Answer {
					value, ok := item.match(rr, n)
					if !ok {
						continue
					}
					row := base
					row.QType, row.Type, row.Status = item.kind, typeString(rr.Header().Rrtype), StatusNoError
					row.Name, row.Value = n, value
					row.TTL, row.HasTTL = rr.Header().Ttl, true
					row.Server, row.Protocol, row.RTT, row.Cached, row.Replied = resp.server, resp.protocol, resp.rtt, resp.cached, true
					row.Authoritative = resp.msg.Authoritative
					found[i] = append(found[i], row)
				}
			})
		}
		wg.Wait()
		var rows []Row
		for i, f := range found {
			// Sorted, since servers vary the order of records.
			slices.SortFunc(f, func(a, b Row) int { return strings.Compare(a.Value, b.Value) })
			rows = append(rows, f...)
			switch {
			case errs[i] != nil:
				failure = fmt.Errorf("%s %s: %w", names[i], typeString(item.qtype), errs[i])
			case rcodes[i] != dns.RcodeSuccess && rcodes[i] != dns.RcodeNameError:
				failure = fmt.Errorf("%s %s: %s", names[i], typeString(item.qtype), rcodeString(rcodes[i]))
			}
		}
		if len(rows) > 0 {
			if domain != candidates[0] {
				r.Trace.printf(ctx, "posture: %s found at the organizational domain %s", item.kind, domain)
			}
			return postureResult{rows: rows, status: StatusNoError}
		}
		status = StatusNoData
		if len(names) == 1 && rcodes[0] == dns.RcodeNameError {
			status = "NXDOMAIN"
		}
	}
	if failure != nil {
		return postureResult{status: StatusError, err: failure}
	}
	return postureResult{status: status}
}

// receivesMail reports whether the MX lookup shows the domain accepts mail:
// it has MX records other than a null MX ("0 .", RFC 7505). It is false
// when the lookup failed, so no mail findings are made on missing data.
func receivesMail(mx postureResult) bool {
	for _, row := range mx.rows {
		if !strings.HasSuffix(row.Value, " .") {
			return true
		}
	}
	return false
}

// missing returns the finding for a kind of record that was not found, or
// "" when its absence is not a problem.
func missing(kind string, mail bool) string {
	switch {
	case kind == "SPF" && mail:
		return "medium: no SPF record, though the domain receives mail (MX); others can more easily send mail in its name"
	case kind == "DMARC" && mail:
		return "medium: no DMARC record, though the domain receives mail (MX); receivers get no policy for failed SPF/DKIM checks"
	case kind == "DKIM" && mail:
		return "low: no DKIM record for the common selectors (" + strings.Join(DKIMSelectors, ", ") + "); the domain's real selector may differ"
	case kind == "CAA":
		return "low: no CAA record; any certificate authority may issue certificates for the domain"
	}
	return ""
}

func multipleRecords(kind string, n int) string {
	if kind == "SPF" {
		return fmt.Sprintf("medium: %d SPF records; receivers treat this as an error and ignore SPF (RFC 7208 section 4.5)", n)
	}
	return fmt.Sprintf("medium: %d DMARC records; receivers ignore DMARC for the domain (RFC 7489 section 6.6.3)", n)
}

// OrganizationalDomain returns the registrable domain of name (the public
// suffix plus one label, such as example.co.uk. for www.example.co.uk.),
// fully qualified, or name itself when there is none.
func OrganizationalDomain(name string) string {
	host := strings.TrimSuffix(strings.ToLower(name), ".")
	if net.ParseIP(host) != nil {
		return name
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || d == "" {
		return name
	}
	return dns.Fqdn(d)
}
