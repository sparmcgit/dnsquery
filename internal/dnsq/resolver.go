// Package dnsq implements the DNS stub-client queries, result rows,
// filtering and output formatting used by the dnsquery commands.
package dnsq

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

// Status values beyond the RCODE mnemonics of RFC 1035.
const (
	StatusNoError = "NOERROR"
	StatusNoData  = "NODATA"  // RFC 2308 section 2.2
	StatusError   = "ERROR"   // no usable response (timeout, network, mismatch)
	StatusSkipped = "SKIPPED" // --check-nameservers: address unreachable from this host
)

// ednsUDPSize is the advertised EDNS(0) UDP payload size (RFC 6891),
// following the DNS Flag Day 2020 recommendation to avoid fragmentation.
const ednsUDPSize = 1232

// Row is one output row: an answer record, or a single row describing a
// negative or failed response.
type Row struct {
	Query         string
	QType         string
	Status        string
	Name          string
	Type          string
	TTL           uint32
	HasTTL        bool
	Value         string
	Zone          string
	Server        string
	Protocol      string
	RTT           time.Duration
	Authoritative bool
	Replied       bool // a response was received; RTT and AA are meaningful
	Error         string
	Explanation   string
	DNSSEC        string // secure, insecure or bogus, with --dnssec
	DNSSECReason  string
	Cached        bool
	EDE           string // extended DNS errors from the server (RFC 8914)
	NSID          string // server identifier, when requested (RFC 5001)
	ECS           string // client subnet option of the response (RFC 7871)
	NS            string // nameserver host, with --check-nameservers
	Serial        uint32 // SOA serial
	HasSerial     bool
	Check         string // nameserver check problem; empty when fine
	Skipped       bool   // nameserver address unreachable from this host

	soaMName string
}

// Resolver sends recursive queries to upstream recursive resolvers. Servers
// are tried in order: a stub resolver must be able to use redundant
// recursive servers (RFC 1123 section 6.1.3.1).
type Resolver struct {
	// Servers are plain ip:port addresses or tls://, https:// or quic://
	// URLs, as returned by ParseServer.
	Servers []string
	TCP     bool // plain DNS over TCP instead of UDP
	// TLSConfig, when set, is the base TLS configuration for encrypted
	// servers (for example, other root CAs).
	TLSConfig *tls.Config
	Timeout   time.Duration
	Retries   int // extra rounds for servers that timed out
	// Limiter, when set, paces every transmission, including retries,
	// failover to another server and TCP/EDNS fallbacks.
	Limiter *rate.Limiter
	// Cache, when set, answers repeated queries during the run.
	Cache *Cache
	// Validator, when set, requests DNSSEC data (DO and CD bits) and
	// validates every response.
	Validator *Validator
	// Trace, when set, logs every query, response and DNSSEC step.
	Trace *Tracer
	// NSID asks each server to identify itself (RFC 5001).
	NSID bool
	// ECS, when set, is sent as the client subnet of every query
	// (RFC 7871).
	ECS *dns.EDNS0_SUBNET
	// AuthPort is the port for direct queries to authoritative
	// nameservers (default 53).
	AuthPort string
	// IPv6 also uses the IPv6 addresses of the nameservers that
	// CheckNameservers looks up; by default only IPv4 is used.
	IPv6 bool

	flight singleflight.Group

	transportsMu sync.Mutex
	transports   map[string]transport // per encrypted server, see transportFor
}

type response struct {
	msg      *dns.Msg
	server   string
	protocol string
	rtt      time.Duration
	cached   bool
}

// ParseType converts a record type mnemonic (or TYPEnnn, RFC 3597) to its code.
func ParseType(s string) (uint16, error) {
	up := strings.ToUpper(strings.TrimSpace(s))
	if t, ok := dns.StringToType[up]; ok {
		return t, nil
	}
	if n, ok := strings.CutPrefix(up, "TYPE"); ok {
		if v, err := strconv.ParseUint(n, 10, 16); err == nil {
			return uint16(v), nil
		}
	}
	return 0, fmt.Errorf("unknown record type %q", s)
}

// Normalize turns user input into a fully qualified query name. For PTR
// queries an IP address is converted to its in-addr.arpa/ip6.arpa name.
// Internationalized names are converted to their ASCII (xn--) form.
func Normalize(input string, qtype uint16) (string, error) {
	s := strings.TrimSpace(input)
	if qtype == dns.TypePTR && net.ParseIP(s) != nil {
		return dns.ReverseAddr(s)
	}
	s, err := toASCII(s)
	if err != nil {
		return "", err
	}
	if _, ok := dns.IsDomainName(s); !ok || s == "" {
		return "", fmt.Errorf("invalid domain name %q", input)
	}
	return dns.Fqdn(s), nil
}

// idnaDots are the label separators UTS #46 maps to "." (ideographic and
// fullwidth full stops).
var idnaDots = strings.NewReplacer("\u3002", ".", "\uff0e", ".", "\uff61", ".")

// toASCII converts internationalized labels of name to their ASCII (xn--)
// form with the IDNA lookup profile (RFC 5891 with UTS #46 mapping, as
// browsers and dig do): räksmörgås.se becomes xn--rksmrgs-5wao1o.se.
// ASCII labels are left untouched, so names such as _dmarc.example that
// IDNA itself would reject keep working.
func toASCII(name string) (string, error) {
	if isASCII(name) {
		return name, nil
	}
	labels := strings.Split(idnaDots.Replace(name), ".")
	for i, l := range labels {
		if isASCII(l) {
			continue
		}
		a, err := idna.Lookup.ToASCII(l)
		if err != nil {
			return "", fmt.Errorf("invalid internationalized domain name %q: %v", name, err)
		}
		labels[i] = a
	}
	return strings.Join(labels, "."), nil
}

// unicodeName shows the xn-- labels of name in Unicode; labels that do not
// decode are left as they are.
func unicodeName(name string) string {
	if !strings.Contains(strings.ToLower(name), "xn--") {
		return name
	}
	labels := strings.Split(name, ".")
	for i, l := range labels {
		if strings.HasPrefix(strings.ToLower(l), "xn--") {
			if u, err := idna.Punycode.ToUnicode(l); err == nil {
				labels[i] = u
			}
		}
	}
	return strings.Join(labels, ".")
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// Lookup queries input and returns its result rows. With tryParents set and
// an SOA query answered with NODATA, parent names are tried until an SOA is
// found or the root is reached.
func (r *Resolver) Lookup(ctx context.Context, input string, qtype uint16, tryParents bool) []Row {
	ctx = withTraceLabel(ctx, input)
	base := Row{Query: input, QType: typeString(qtype), Type: typeString(qtype), Server: strings.Join(r.Servers, ",")}
	name, err := Normalize(input, qtype)
	if err != nil {
		base.Name, base.Status, base.Error = input, StatusError, err.Error()
		return []Row{base}
	}
	for {
		base.Name = name
		resp, err := r.query(ctx, name, qtype)
		if err != nil {
			base.Status, base.Error = StatusError, err.Error()
			return []Row{base}
		}
		rows := buildRows(base, resp, qtype)
		if tryParents && qtype == dns.TypeSOA && rows[0].Status == StatusNoData && name != "." {
			name = parent(name)
			continue
		}
		if r.Validator != nil {
			vd := r.Validator.Validate(ctx, r, name, qtype, resp.msg)
			for i := range rows {
				t, _ := ParseType(rows[i].Type)
				rows[i].DNSSEC, rows[i].DNSSECReason = vd.ForRRset(rows[i].Name, t)
			}
		}
		return rows
	}
}

// query returns the response for name/qtype from the cache or, on a miss,
// from the servers. Concurrent identical queries share one exchange.
func (r *Resolver) query(ctx context.Context, name string, qtype uint16) (*response, error) {
	key := strings.ToLower(name) + " " + strconv.Itoa(int(qtype))
	if resp, err, ok := r.Cache.get(key); ok {
		if err != nil {
			r.Trace.printf(ctx, "cache hit %s %s: cached failure: %v", name, typeString(qtype), err)
		} else {
			r.Trace.printf(ctx, "cache hit %s %s: %s", name, typeString(qtype), rcodeString(resp.msg.Rcode))
		}
		return resp, err
	}
	v, err, shared := r.flight.Do(key, func() (any, error) {
		resp, err := r.exchange(ctx, name, qtype)
		r.Cache.put(key, resp, err)
		return resp, err
	})
	if shared {
		r.Trace.printf(ctx, "%s %s: answered by an identical query already in flight", name, typeString(qtype))
	}
	resp, _ := v.(*response)
	return resp, err
}

// exchange asks each server in turn, as in RFC 1035 section 7.2. A server
// that times out is retried in up to r.Retries further rounds; one that
// fails otherwise, or answers SERVFAIL, REFUSED or NOTIMP, is skipped from
// then on. If no server gives a usable answer, the last such answer is
// returned, or else the last error.
func (r *Resolver) exchange(ctx context.Context, name string, qtype uint16) (*response, error) {
	var last *response
	var lastErr error
	attempts := 0
	pending := r.Servers
	for round := 0; round <= r.Retries && len(pending) > 0; round++ {
		var timedOut []string
		for _, server := range pending {
			attempts++
			resp, err := r.exchangeWith(ctx, server, name, qtype)
			switch {
			case err == nil && !tryNextServer(resp.msg.Rcode):
				return resp, nil
			case ctx.Err() != nil:
				return nil, ctx.Err()
			case err == nil:
				r.Trace.printf(ctx, "%s answered %s: asking the next server (RFC 1035 section 7.2)", server, rcodeString(resp.msg.Rcode))
				last = resp
			case isTimeout(err):
				if round < r.Retries {
					r.Trace.printf(ctx, "%s timed out after %s; retry %d of %d follows", server, r.Timeout, round+1, r.Retries)
				} else {
					r.Trace.printf(ctx, "%s timed out after %s; no retries left", server, r.Timeout)
				}
				timedOut = append(timedOut, server)
				lastErr = err
			default:
				r.Trace.printf(ctx, "%s failed: %v; asking the next server", server, err)
				lastErr = err
			}
		}
		pending = timedOut
	}
	if last != nil {
		return last, nil
	}
	if attempts > 1 {
		return nil, fmt.Errorf("no usable response after %d attempts to %d server(s): %w", attempts, len(r.Servers), lastErr)
	}
	return nil, lastErr
}

// tryNextServer reports whether an answer with rcode is a server problem
// worth asking another server about (RFC 1035 section 7.2, as glibc does).
func tryNextServer(rcode int) bool {
	return rcode == dns.RcodeServerFailure || rcode == dns.RcodeRefused || rcode == dns.RcodeNotImplemented
}

// exchangeWith sends one recursive query to server.
func (r *Resolver) exchangeWith(ctx context.Context, server, name string, qtype uint16) (*response, error) {
	return r.exchangeOnce(ctx, server, name, qtype, true)
}

// exchangeOnce sends one query to server, falling back to TCP on truncation
// or an unreadable UDP answer, and to plain DNS when EDNS is rejected. rd
// sets the recursion desired bit.
func (r *Resolver) exchangeOnce(ctx context.Context, server, name string, qtype uint16, rd bool) (*response, error) {
	protocol, enc, err := r.transportFor(server)
	if err != nil {
		return nil, err
	}
	edns := true
	var total time.Duration
	var udpErr error // why a UDP answer could not be read
	for range 4 {
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		m.RecursionDesired = rd
		if edns {
			// DO asks for RRSIGs; CD makes the resolver return data it
			// considers bogus so the validator can judge it (RFC 4035
			// section 4.9.2).
			m.SetEdns0(ednsUDPSize, r.Validator != nil)
			m.CheckingDisabled = r.Validator != nil
			if r.NSID {
				// An empty NSID option asks the server to identify itself.
				opt := m.IsEdns0()
				opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})
			}
			if r.ECS != nil {
				opt := m.IsEdns0()
				opt.Option = append(opt.Option, r.ECS)
			}
			if enc != nil {
				pad(m)
			}
		}
		if protocol == ProtoHTTPS || protocol == ProtoQUIC {
			// RFC 8484 section 4.1, RFC 9250 section 4.2.1: the stream
			// matches the answer to the query, so the ID is 0.
			m.Id = 0
		}
		// Wait before the exchange so pacing does not eat into the timeout.
		waited := ""
		if r.Limiter != nil {
			start := time.Now()
			if err := r.Limiter.Wait(ctx); err != nil {
				return nil, err
			}
			if d := time.Since(start); d >= time.Millisecond && r.Trace.on() {
				waited = fmt.Sprintf(" (waited %s for --rate)", d.Round(time.Millisecond))
			}
		}
		var resp *dns.Msg
		var rtt time.Duration
		if enc != nil {
			resp, rtt, err = r.exchangeEncrypted(ctx, enc, m)
		} else {
			c := &dns.Client{Net: protocol, Timeout: r.Timeout}
			resp, rtt, err = c.ExchangeContext(ctx, m, server)
		}
		total += rtt
		if err != nil {
			if r.Trace.on() {
				r.Trace.printf(ctx, "%s %s %s%s -> %v", server, protocol, describeQuery(m), waited, err)
			}
			var parseErr *dns.Error
			if protocol == "udp" && errors.As(err, &parseErr) {
				// The datagram could not be parsed, usually because the
				// server sent more than the EDNS payload size we asked for
				// without setting TC (RFC 6891 section 6.2.3), so it was cut
				// off. Retry over TCP, which has no such limit.
				udpErr = err
				r.Trace.printf(ctx, "UDP answer unreadable, probably larger than the %d bytes requested and not marked truncated; retrying over TCP", ednsUDPSize)
				protocol = "tcp"
				continue
			}
			if udpErr != nil {
				return nil, fmt.Errorf("UDP answer unreadable (%v), probably larger than the %d bytes requested and not marked truncated; TCP retry failed: %w", udpErr, ednsUDPSize, err)
			}
			return nil, err
		}
		if r.Trace.on() {
			r.Trace.printf(ctx, "%s %s %s%s -> %s, %s", server, protocol, describeQuery(m), waited, describeResponse(resp), rtt.Round(10*time.Microsecond))
		}
		switch {
		case resp.Truncated && protocol == "udp":
			// RFC 7766 section 5: retry a truncated UDP response over TCP.
			r.Trace.printf(ctx, "answer truncated (TC); retrying over TCP")
			protocol = "tcp"
			continue
		case edns && resp.Rcode == dns.RcodeFormatError && resp.IsEdns0() == nil:
			// RFC 6891 section 7: a responder without EDNS support answers
			// FORMERR without an OPT record; retry without EDNS.
			r.Trace.printf(ctx, "FORMERR without OPT: server does not support EDNS; retrying without EDNS (no DNSSEC data)")
			edns = false
			continue
		}
		if r.Validator != nil && edns && (resp.IsEdns0() == nil || !resp.IsEdns0().Do()) {
			r.Trace.printf(ctx, "note: the answer does not echo the DO bit; this server may not return DNSSEC data")
		}
		if err := checkQuestion(resp, name, qtype); err != nil {
			return nil, err
		}
		return &response{msg: resp, server: server, protocol: protocol, rtt: total}, nil
	}
	return nil, errors.New("no usable response after EDNS/TCP fallback")
}

// exchangeEncrypted sends m over an encrypted transport within r.Timeout,
// which covers connecting and the TLS or QUIC handshake when no
// connection is open yet.
func (r *Resolver) exchangeEncrypted(ctx context.Context, t transport, m *dns.Msg) (*dns.Msg, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	start := time.Now()
	resp, err := t.exchange(ctx, m)
	return resp, time.Since(start), err
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded)
}

// checkQuestion rejects responses whose question section does not echo the
// query (RFC 1035 section 7.3). An empty question section is tolerated since
// some servers omit it on error responses.
func checkQuestion(m *dns.Msg, name string, qtype uint16) error {
	if len(m.Question) == 0 {
		return nil
	}
	q := m.Question[0]
	if len(m.Question) != 1 || !strings.EqualFold(q.Name, name) || q.Qtype != qtype {
		return fmt.Errorf("response question %s %s does not match query", q.Name, typeString(q.Qtype))
	}
	return nil
}

func buildRows(base Row, resp *response, qtype uint16) []Row {
	m := resp.msg
	base.Server = resp.server
	base.Protocol = resp.protocol
	base.RTT = resp.rtt
	base.Cached = resp.cached
	base.Replied = true
	base.Authoritative = m.Authoritative
	base.EDE = extendedErrors(m)
	base.NSID = serverID(m)
	base.ECS = clientSubnet(m)
	base.Status = classify(m, qtype)

	if len(m.Answer) == 0 {
		row := base
		if soa := authoritySOA(m); soa != nil {
			row.Zone = soa.Hdr.Name
			if row.Status == StatusNoData || row.Status == "NXDOMAIN" {
				// RFC 2308 section 5: negative TTL is min(SOA TTL, SOA MINIMUM).
				row.TTL, row.HasTTL = min(soa.Hdr.Ttl, soa.Minttl), true
			}
		}
		return []Row{row}
	}

	rows := make([]Row, 0, len(m.Answer))
	for _, rr := range m.Answer {
		h := rr.Header()
		if h.Rrtype == dns.TypeRRSIG && qtype != dns.TypeRRSIG && qtype != dns.TypeANY {
			continue // DNSSEC signatures, shown only when asked for
		}
		row := base
		row.Name = h.Name
		row.Type = typeString(h.Rrtype)
		row.TTL, row.HasTTL = h.Ttl, true
		row.Value = strings.TrimPrefix(rr.String(), h.String())
		if soa, ok := rr.(*dns.SOA); ok {
			row.Zone = soa.Hdr.Name
			row.soaMName = strings.ToLower(soa.Ns)
			row.Serial, row.HasSerial = soa.Serial, true
		}
		rows = append(rows, row)
	}
	return rows
}

// classify maps a response to a status. A NOERROR response without records
// of the queried type (possibly after a CNAME chain) is NODATA (RFC 2308).
func classify(m *dns.Msg, qtype uint16) string {
	if m.Rcode != dns.RcodeSuccess {
		if s, ok := dns.RcodeToString[m.Rcode]; ok {
			return s
		}
		return fmt.Sprintf("RCODE%d", m.Rcode)
	}
	for _, rr := range m.Answer {
		if t := rr.Header().Rrtype; t == qtype || qtype == dns.TypeANY {
			return StatusNoError
		}
	}
	return StatusNoData
}

// extendedErrors renders the Extended DNS Error options of m (RFC 8914) as
// "CODE Name: extra text", joined with "; ".
func extendedErrors(m *dns.Msg) string {
	opt := m.IsEdns0()
	if opt == nil {
		return ""
	}
	var out []string
	for _, o := range opt.Option {
		e, ok := o.(*dns.EDNS0_EDE)
		if !ok {
			continue
		}
		s := strconv.Itoa(int(e.InfoCode))
		if name, ok := dns.ExtendedErrorCodeToString[e.InfoCode]; ok {
			s += " " + name
		}
		if text := strings.TrimSpace(e.ExtraText); text != "" {
			s += ": " + text
		}
		out = append(out, s)
	}
	return strings.Join(out, "; ")
}

// serverID returns the NSID option of m (RFC 5001) as text when it is
// printable, or as hex.
func serverID(m *dns.Msg) string {
	opt := m.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		n, ok := o.(*dns.EDNS0_NSID)
		if !ok || n.Nsid == "" {
			continue
		}
		raw, err := hex.DecodeString(n.Nsid)
		if err != nil {
			return n.Nsid
		}
		for _, c := range raw {
			if c < 0x20 || c > 0x7e {
				return n.Nsid
			}
		}
		return string(raw)
	}
	return ""
}

func authoritySOA(m *dns.Msg) *dns.SOA {
	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}

func parent(name string) string {
	i, end := dns.NextLabel(name, 0)
	if end || i >= len(name) {
		return "."
	}
	return name[i:]
}

// TypeString returns the mnemonic of a record type, or TYPEnnn (RFC 3597).
func TypeString(t uint16) string { return typeString(t) }

func typeString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

// FilterAuthoritative keeps only SOA answer rows whose MNAME is one of servers.
func FilterAuthoritative(rows []Row, servers []string) []Row {
	want := make(map[string]bool, len(servers))
	for _, s := range servers {
		want[strings.ToLower(dns.Fqdn(strings.TrimSpace(s)))] = true
	}
	out := rows[:0]
	for _, r := range rows {
		if r.soaMName != "" && want[r.soaMName] {
			out = append(out, r)
		}
	}
	return out
}
