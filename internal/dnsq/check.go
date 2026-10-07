package dnsq

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"syscall"

	"github.com/miekg/dns"
)

// CheckFields is the default field selection for --check-nameservers.
var CheckFields = []string{"query", "ns", "server", "status", "serial", "authoritative", "value", "check"}

// CheckNameservers asks every authoritative nameserver of the zone that
// holds input directly (recursion off) for the zone's SOA and for
// input/qtype, one row per nameserver address: IPv4 only, unless r.IPv6.
// The check field names what is wrong: a server that is not authoritative
// (lame), a serial or answer that differs from the majority (or every
// server's, when there is no majority), or one that does not reply.
// Addresses this host cannot reach at all (typically IPv6 without a
// route), and nameservers with only IPv6 addresses when r.IPv6 is off,
// are skipped, not counted as problems.
func (r *Resolver) CheckNameservers(ctx context.Context, input string, qtype uint16) []Row {
	ctx = withTraceLabel(ctx, input)
	base := Row{Query: input, QType: typeString(qtype), Type: typeString(qtype)}
	fail := func(err error) []Row {
		base.Status, base.Error, base.Check = StatusError, err.Error(), err.Error()
		return []Row{base}
	}
	name, err := Normalize(input, qtype)
	if err != nil {
		base.Name = input
		return fail(err)
	}
	base.Name = name
	zone, err := r.findZone(ctx, name)
	if err != nil {
		return fail(err)
	}
	base.Zone = zone
	hosts, err := r.nameservers(ctx, zone)
	if err != nil {
		return fail(err)
	}
	r.Trace.printf(ctx, "check: zone %s has nameservers %s", zone, strings.Join(hosts, ", "))

	var rows []Row
	for _, host := range hosts {
		addrs, ipv6Only := r.addresses(ctx, host)
		if len(addrs) == 0 && len(ipv6Only) > 0 {
			row := base
			row.NS, row.Status, row.Skipped = host, StatusSkipped, true
			row.Check = "skipped: only IPv6 addresses (" + strings.Join(ipv6Only, ", ") + "); add --ipv6 to check them"
			rows = append(rows, row)
			continue
		}
		if len(addrs) == 0 {
			row := base
			row.NS, row.Status, row.Check = host, StatusError, "nameserver has no A or AAAA address"
			rows = append(rows, row)
			continue
		}
		for _, addr := range addrs {
			row := base
			row.NS = host
			rows = append(rows, r.checkServer(ctx, row, zone, name, qtype, addr))
		}
	}
	compareServers(rows)
	return rows
}

// findZone returns the zone holding name: the closest ancestor (or name
// itself) that owns an SOA record.
func (r *Resolver) findZone(ctx context.Context, name string) (string, error) {
	for n := name; ; n = parent(n) {
		resp, err := r.query(ctx, n, dns.TypeSOA)
		if err != nil {
			return "", fmt.Errorf("finding the zone of %s: SOA %s: %w", name, n, err)
		}
		if soa := findRRset(resp.msg.Answer, n, dns.TypeSOA); soa != nil {
			return strings.ToLower(n), nil
		}
		if n == "." {
			return "", fmt.Errorf("no zone found for %s", name)
		}
	}
}

// nameservers returns the zone's NS targets, sorted.
func (r *Resolver) nameservers(ctx context.Context, zone string) ([]string, error) {
	resp, err := r.query(ctx, zone, dns.TypeNS)
	if err != nil {
		return nil, fmt.Errorf("NS %s: %w", zone, err)
	}
	var hosts []string
	for _, rr := range resp.msg.Answer {
		if ns, ok := rr.(*dns.NS); ok && equalName(ns.Hdr.Name, zone) {
			hosts = append(hosts, strings.ToLower(ns.Ns))
		}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no NS records for %s (%s)", zone, rcodeString(resp.msg.Rcode))
	}
	slices.Sort(hosts)
	return slices.Compact(hosts), nil
}

// addresses returns the IPv4 addresses of host and, with r.IPv6, its IPv6
// addresses. Without r.IPv6, a host with no IPv4 address has its IPv6
// addresses returned as ipv6Only, so it can be reported as skipped rather
// than as having no address.
func (r *Resolver) addresses(ctx context.Context, host string) (addrs, ipv6Only []string) {
	addrs = r.lookupAddrs(ctx, host, dns.TypeA)
	switch {
	case r.IPv6:
		addrs = append(addrs, r.lookupAddrs(ctx, host, dns.TypeAAAA)...)
	case len(addrs) == 0:
		ipv6Only = r.lookupAddrs(ctx, host, dns.TypeAAAA)
	}
	return addrs, ipv6Only
}

// lookupAddrs returns the addresses in host's A or AAAA records.
func (r *Resolver) lookupAddrs(ctx context.Context, host string, qtype uint16) []string {
	resp, err := r.query(ctx, host, qtype)
	if err != nil {
		return nil
	}
	var out []string
	for _, rr := range resp.msg.Answer {
		switch x := rr.(type) {
		case *dns.A:
			out = append(out, x.A.String())
		case *dns.AAAA:
			out = append(out, x.AAAA.String())
		}
	}
	return out
}

// checkServer queries one nameserver address for the zone's SOA and, when
// different, for name/qtype.
func (r *Resolver) checkServer(ctx context.Context, row Row, zone, name string, qtype uint16, addr string) Row {
	port := r.AuthPort
	if port == "" {
		port = "53"
	}
	server := net.JoinHostPort(addr, port)
	row.Server = server
	soa, err := r.direct(ctx, server, zone, dns.TypeSOA)
	if err != nil {
		row.Status, row.Error = StatusError, err.Error()
		if why := localBlock(err, addr); why != "" {
			row.Status, row.Skipped = StatusSkipped, true
			row.Check = "skipped: " + why
		} else {
			row.Check = "no usable reply: " + err.Error()
		}
		return row
	}
	m := soa.msg
	row.Protocol, row.RTT, row.Authoritative, row.Replied = soa.protocol, soa.rtt, m.Authoritative, true
	row.EDE, row.NSID = extendedErrors(m), serverID(m)
	if s := findRRset(m.Answer, zone, dns.TypeSOA); s != nil {
		row.Serial, row.HasSerial = s.rrs[0].(*dns.SOA).Serial, true
	}
	switch {
	case m.Rcode != dns.RcodeSuccess:
		row.Status = rcodeString(m.Rcode)
		row.Check = fmt.Sprintf("lame: answers %s for its own zone %s", row.Status, zone)
		return row
	case !m.Authoritative:
		row.Status = rcodeString(m.Rcode)
		row.Check = "lame: not authoritative for " + zone + " (AA flag not set)"
		return row
	case !row.HasSerial:
		row.Status = classify(m, dns.TypeSOA)
		row.Check = "no SOA record for " + zone
		return row
	}

	ans := soa
	if qtype != dns.TypeSOA || !equalName(name, zone) {
		if ans, err = r.direct(ctx, server, name, qtype); err != nil {
			row.Status, row.Error, row.Check = StatusError, err.Error(), "no usable reply for "+name+": "+err.Error()
			return row
		}
	}
	row.Status = classify(ans.msg, qtype)
	row.Value = answerSummary(ans.msg)
	row.ECS = clientSubnet(ans.msg)
	if row.Status == StatusNoError || row.Status == StatusNoData || row.Status == "NXDOMAIN" {
		if !ans.msg.Authoritative {
			row.Check = "lame: answer for " + name + " is not authoritative"
		}
	} else {
		row.Check = fmt.Sprintf("answers %s for %s", row.Status, name)
	}
	return row
}

// direct sends name/qtype straight to one server with recursion off,
// bypassing the cache and failover; timeouts are retried up to r.Retries
// times.
func (r *Resolver) direct(ctx context.Context, server, name string, qtype uint16) (*response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := r.exchangeOnce(ctx, server, name, qtype, false)
		if err == nil || ctx.Err() != nil || !isTimeout(err) || attempt >= r.Retries {
			return resp, err
		}
	}
}

// answerSummary renders the answer section's data sorted, so answers from
// different servers compare equal regardless of record order or TTL.
func answerSummary(m *dns.Msg) string {
	var vals []string
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		vals = append(vals, typeString(rr.Header().Rrtype)+" "+strings.TrimPrefix(rr.String(), rr.Header().String()))
	}
	slices.Sort(vals)
	return strings.Join(vals, " | ")
}

// compareServers flags serials and answers that differ between the
// servers that replied without other problems. When one value is held by a
// strict majority, the others are flagged; when none is, every server is,
// since there is no telling which side is right.
func compareServers(rows []Row) {
	serials := map[uint32]int{}
	answers := map[string]int{}
	replied := 0
	for _, r := range rows {
		if r.Check == "" {
			serials[r.Serial]++
			answers[r.Status+" "+r.Value]++
			replied++
		}
	}
	serial, ns := majority(serials)
	answer, na := majority(answers)
	for i := range rows {
		r := &rows[i]
		if r.Check != "" {
			continue
		}
		var problems []string
		switch {
		case len(serials) < 2:
		case 2*ns <= replied:
			problems = append(problems, "serials differ: "+serialCounts(serials)+"; no majority (out of sync?)")
		case r.Serial != serial:
			problems = append(problems, fmt.Sprintf("serial %d differs from %d on %d of %d servers (out of sync?)", r.Serial, serial, ns, replied))
		}
		switch {
		case len(answers) < 2:
		case 2*na <= replied:
			problems = append(problems, fmt.Sprintf("answers differ: %d different answers from %d servers, no majority", len(answers), replied))
		case r.Status+" "+r.Value != answer:
			problems = append(problems, fmt.Sprintf("answer differs from %d of %d servers", na, replied))
		}
		r.Check = strings.Join(problems, "; ")
	}
}

// serialCounts lists serials with their number of servers, most common
// first and, among equals, the highest (usually newest) serial first:
// "993584781 on 2 servers, 993157628 on 2".
func serialCounts(counts map[uint32]int) string {
	serials := slices.Collect(maps.Keys(counts))
	slices.SortFunc(serials, func(a, b uint32) int {
		if c := cmp.Compare(counts[b], counts[a]); c != 0 {
			return c
		}
		return cmp.Compare(b, a)
	})
	parts := make([]string, len(serials))
	for i, s := range serials {
		parts[i] = fmt.Sprintf("%d on %d", s, counts[s])
		if i == 0 {
			parts[i] += " servers"
		}
	}
	return strings.Join(parts, ", ")
}

// majority returns the most common key (ties broken by the smallest key,
// for stable output) and its count.
func majority[K interface{ ~string | ~uint32 }](counts map[K]int) (K, int) {
	var best K
	n := 0
	for k, c := range counts {
		if c > n || c == n && k < best {
			best, n = k, c
		}
	}
	return best, n
}

// localBlock explains errors meaning the query never left this host, so
// they say nothing about the server: no route to the address (typically
// IPv6), or a local firewall refusing to send it (typically a VPN that
// only allows DNS to its own resolver). It returns "" for other errors.
func localBlock(err error, addr string) string {
	switch {
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EADDRNOTAVAIL), errors.Is(err, syscall.EAFNOSUPPORT):
		return "this host has no route to " + addr
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		return "this host's firewall does not let DNS out to " + addr +
			" (operation not permitted); a VPN may be blocking DNS to servers other than its own"
	}
	return ""
}

// Unchecked reports whether a --check-nameservers result reached no
// nameserver at all: every address was skipped, so nothing was checked.
func Unchecked(rows []Row) bool {
	for _, r := range rows {
		if !r.Skipped {
			return false
		}
	}
	return len(rows) > 0
}
