package dnsq

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// DNSSEC security statuses (RFC 4033 section 5).
const (
	SecSecure   = "secure"   // validated from the trust anchor
	SecInsecure = "insecure" // provably unsigned (or unsupported algorithm)
	SecBogus    = "bogus"    // should be signed but does not validate
)

// RootAnchors are the IANA root zone trust anchors, KSK-2017 and KSK-2024,
// from https://data.iana.org/root-anchors/root-anchors.xml.
const RootAnchors = `. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
. IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
`

// maxNSEC3Iterations is the iteration count above which NSEC3 proofs are
// treated as insecure (RFC 9276 section 3.2).
const maxNSEC3Iterations = 150

// supportedAlgorithms are the DNSKEY algorithms this validator can verify
// (RFC 8624 section 3.1, minus RSAMD5, DSA and ED448).
var supportedAlgorithms = map[uint8]bool{
	dns.RSASHA1:          true,
	dns.RSASHA1NSEC3SHA1: true,
	dns.RSASHA256:        true,
	dns.RSASHA512:        true,
	dns.ECDSAP256SHA256:  true,
	dns.ECDSAP384SHA384:  true,
	dns.ED25519:          true,
}

var supportedDigests = map[uint8]bool{dns.SHA1: true, dns.SHA256: true, dns.SHA384: true}

// ParseTrustAnchors reads root zone trust anchors as DS or DNSKEY records
// in zone file syntax. DNSKEYs are converted to SHA-256 DS records.
func ParseTrustAnchors(r io.Reader, file string) ([]*dns.DS, error) {
	zp := dns.NewZoneParser(r, ".", file)
	var out []*dns.DS
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if rr.Header().Name != "." {
			return nil, fmt.Errorf("%s: only root zone (.) trust anchors are supported, got %s", file, rr.Header().Name)
		}
		switch x := rr.(type) {
		case *dns.DS:
			out = append(out, x)
		case *dns.DNSKEY:
			out = append(out, x.ToDS(dns.SHA256))
		default:
			return nil, fmt.Errorf("%s: trust anchors must be DS or DNSKEY records, got %s", file, typeString(rr.Header().Rrtype))
		}
	}
	if err := zp.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no trust anchors", file)
	}
	return out, nil
}

// Validator authenticates responses as a validating stub resolver (RFC 4035
// section 4.9): it builds the chain of trust from the root trust anchors
// through DS and DNSKEY lookups, then checks RRSIGs on the answer and the
// NSEC/NSEC3 proofs of negative answers.
type Validator struct {
	anchors []*dns.DS
	now     func() time.Time
	chains  *lru[chainResult]
	flight  singleflight.Group
}

// NewValidator returns a validator trusting anchors, remembering up to
// cacheSize validated zone chains.
func NewValidator(anchors []*dns.DS, cacheSize int) *Validator {
	return &Validator{anchors: anchors, now: time.Now, chains: newLRU[chainResult](cacheSize)}
}

// chainResult is the chain of trust down to the deepest zone enclosing a
// name.
type chainResult struct {
	zone    string        // deepest zone cut found
	keys    []*dns.DNSKEY // validated DNSKEYs of zone, when secure
	status  string
	reason  string
	stop    bool // a name on the way down does not exist
	expires time.Time
	detail  string // how a secure zone's keys were trusted, for --trace
}

// rrset is one RRset of a message section with the RRSIGs covering it.
type rrset struct {
	name  string
	rtype uint16
	rrs   []dns.RR
	sigs  []*dns.RRSIG
}

// groupRRsets splits a section into RRsets, attaching RRSIGs to the RRset
// they cover, in order of first appearance.
func groupRRsets(section []dns.RR) []*rrset {
	var sets []*rrset
	find := func(name string, t uint16) *rrset {
		for _, s := range sets {
			if s.rtype == t && equalName(s.name, name) {
				return s
			}
		}
		return nil
	}
	for _, rr := range section {
		if h := rr.Header(); h.Rrtype != dns.TypeRRSIG && h.Rrtype != dns.TypeOPT {
			if s := find(h.Name, h.Rrtype); s != nil {
				s.rrs = append(s.rrs, rr)
			} else {
				sets = append(sets, &rrset{name: h.Name, rtype: h.Rrtype, rrs: []dns.RR{rr}})
			}
		}
	}
	for _, rr := range section {
		if sig, ok := rr.(*dns.RRSIG); ok {
			if s := find(sig.Hdr.Name, sig.TypeCovered); s != nil {
				s.sigs = append(s.sigs, sig)
			}
		}
	}
	return sets
}

func findRRset(section []dns.RR, name string, t uint16) *rrset {
	for _, s := range groupRRsets(section) {
		if s.rtype == t && equalName(s.name, name) {
			return s
		}
	}
	return nil
}

// Verdict is the DNSSEC result for one response.
type Verdict struct {
	// Status and Reason are for the response as a whole: the worst of its
	// RRsets and of any proof of non-existence.
	Status, Reason string
	rrsets         map[string]secResult
	denial         *secResult
}

type secResult struct{ status, reason string }

func rrsetKey(name string, rtype uint16) string {
	return strings.ToLower(dns.Fqdn(name)) + " " + typeString(rtype)
}

// ForRRset returns the status for the answer RRset name/rtype. In a
// negative answer (NODATA or NXDOMAIN after a CNAME chain), a worse proof
// of non-existence overrides it. Unknown RRsets get the overall status.
func (vd Verdict) ForRRset(name string, rtype uint16) (string, string) {
	res, ok := vd.rrsets[rrsetKey(name, rtype)]
	if !ok {
		return vd.Status, vd.Reason
	}
	if vd.denial != nil && rank(vd.denial.status) > rank(res.status) {
		return vd.denial.status, vd.denial.reason
	}
	return res.status, res.reason
}

// Validate returns the DNSSEC verdict for a response to name/qtype, per
// answer RRset and overall. Responses with an RCODE other than NOERROR or
// NXDOMAIN carry no data to validate and get an empty status.
func (v *Validator) Validate(ctx context.Context, r *Resolver, name string, qtype uint16, m *dns.Msg) Verdict {
	vd := Verdict{rrsets: map[string]secResult{}}
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return vd
	}
	vd.Status = SecSecure
	record := func(key, s, why string) {
		vd.rrsets[key] = secResult{s, why}
		if rank(s) > rank(vd.Status) {
			vd.Status, vd.Reason = s, why
		}
	}
	sets := groupRRsets(m.Answer)
	var synthesized []*rrset
	for _, s := range sets {
		if s.rtype == dns.TypeCNAME && len(s.sigs) == 0 {
			if ok, err := synthesizedFromDNAME(s, sets); ok {
				synthesized = append(synthesized, s) // judged by its DNAME
				continue
			} else if err != nil {
				record(rrsetKey(s.name, s.rtype), SecBogus, err.Error())
				continue
			}
		}
		status, reason := v.validateRRset(ctx, r, s, m)
		record(rrsetKey(s.name, s.rtype), status, reason)
	}
	for _, c := range synthesized {
		for _, d := range sets {
			if d.rtype == dns.TypeDNAME && dns.IsSubDomain(d.name, c.name) {
				vd.rrsets[rrsetKey(c.name, c.rtype)] = vd.rrsets[rrsetKey(d.name, d.rtype)]
			}
		}
	}
	// A NOERROR answer without the queried type at the end of any CNAME
	// chain is NODATA; that and NXDOMAIN need a proof of non-existence.
	target := name
	if qtype != dns.TypeCNAME {
		target = chase(name, m.Answer)
	}
	if m.Rcode == dns.RcodeNameError || findRRset(m.Answer, target, qtype) == nil && qtype != dns.TypeANY {
		status, reason := v.validateDenial(ctx, r, target, qtype, m)
		vd.denial = &secResult{status, reason}
		if rank(status) > rank(vd.Status) {
			vd.Status, vd.Reason = status, reason
		}
	}
	return vd
}

func rank(status string) int {
	switch status {
	case SecSecure:
		return 0
	case SecInsecure:
		return 1
	}
	return 2
}

// signingChain returns the chain for the zone that signs name/rtype. DS
// records, and proofs of their absence, live in the parent of the zone they
// delegate to, so they are judged by the parent's chain whatever the
// child's own status.
func (v *Validator) signingChain(ctx context.Context, r *Resolver, name string, rtype uint16) chainResult {
	ch := v.chain(ctx, r, name)
	if rtype == dns.TypeDS && equalName(ch.zone, name) && name != "." {
		return v.chain(ctx, r, parent(name))
	}
	return ch
}

func (v *Validator) validateRRset(ctx context.Context, r *Resolver, s *rrset, m *dns.Msg) (string, string) {
	what := fmt.Sprintf("%s %s", s.name, typeString(s.rtype))
	ch := v.signingChain(ctx, r, s.name, s.rtype)
	if ch.status != SecSecure {
		r.Trace.printf(ctx, "dnssec %s: %s: %s", what, ch.status, ch.reason)
		return ch.status, ch.reason
	}
	sig, err := v.verify(s, ch)
	if err != nil {
		r.Trace.printf(ctx, "dnssec %s: bogus: %v", what, err)
		return SecBogus, what + ": " + err.Error()
	}
	wildcard := ""
	if int(sig.Labels) < dns.CountLabel(s.name) {
		// RFC 4035 section 5.3.4: a wildcard expansion needs proof that
		// the name itself does not exist.
		if err := v.wildcardProof(s.name, int(sig.Labels), m, ch); err != nil {
			r.Trace.printf(ctx, "dnssec %s: bogus: wildcard answer without proof: %v", what, err)
			return SecBogus, what + ": wildcard answer without proof: " + err.Error()
		}
		wildcard = ", expanded from a wildcard with proof that no closer name exists"
	}
	if r.Trace.on() {
		r.Trace.printf(ctx, "dnssec %s: RRSIG by %s key %d verifies (valid until %s)%s: secure",
			what, sig.SignerName, sig.KeyTag, dns.TimeToString(sig.Expiration), wildcard)
	}
	return SecSecure, ""
}

// verify checks an RRset's signatures with the chain's zone keys and
// returns the RRSIG that validated it.
func (v *Validator) verify(s *rrset, ch chainResult) (*dns.RRSIG, error) {
	if len(s.sigs) == 0 {
		return nil, errors.New("missing RRSIG")
	}
	now := v.now()
	var err error
	for _, sig := range s.sigs {
		switch {
		case !equalName(sig.SignerName, ch.zone):
			err = fmt.Errorf("signed by %s, but the zone is %s", sig.SignerName, ch.zone)
			continue
		case !supportedAlgorithms[sig.Algorithm]:
			err = fmt.Errorf("unsupported algorithm %d", sig.Algorithm)
			continue
		case !sig.ValidityPeriod(now):
			err = fmt.Errorf("signature not valid now (valid %s to %s)",
				dns.TimeToString(sig.Inception), dns.TimeToString(sig.Expiration))
			continue
		}
		matched := false
		for _, k := range ch.keys {
			if k.KeyTag() != sig.KeyTag || k.Algorithm != sig.Algorithm {
				continue
			}
			matched = true
			if e := sig.Verify(k, s.rrs); e == nil {
				return sig, nil
			} else {
				err = fmt.Errorf("signature does not verify: %w", e)
			}
		}
		if !matched {
			err = fmt.Errorf("no DNSKEY with key tag %d", sig.KeyTag)
		}
	}
	return nil, err
}

// synthesizedFromDNAME reports whether an unsigned CNAME was synthesized
// from a DNAME in the same answer (RFC 6672 section 5.3.3). The target is
// checked, so a forged CNAME cannot redirect to another signed zone.
func synthesizedFromDNAME(c *rrset, sets []*rrset) (bool, error) {
	for _, s := range sets {
		if s.rtype != dns.TypeDNAME || !dns.IsSubDomain(s.name, c.name) || equalName(s.name, c.name) {
			continue
		}
		d := s.rrs[0].(*dns.DNAME)
		cname := c.rrs[0].(*dns.CNAME)
		prefix := strings.ToLower(c.name)[:len(c.name)-len(s.name)]
		if want := prefix + d.Target; !equalName(cname.Target, want) {
			return false, fmt.Errorf("CNAME %s -> %s does not match DNAME %s -> %s", c.name, cname.Target, s.name, d.Target)
		}
		return true, nil
	}
	return false, nil
}

// chase follows CNAME records in answer from name to the final target.
func chase(name string, answer []dns.RR) string {
	for range 16 {
		next := ""
		for _, rr := range answer {
			if c, ok := rr.(*dns.CNAME); ok && equalName(c.Hdr.Name, name) {
				next = c.Target
				break
			}
		}
		if next == "" {
			break
		}
		name = next
	}
	return name
}

// chain returns the chain of trust down to the deepest zone enclosing
// name, walking down from the root one label at a time (RFC 4035 section
// 5). Results are cached and concurrent lookups for a name are shared.
func (v *Validator) chain(ctx context.Context, r *Resolver, name string) chainResult {
	name = strings.ToLower(dns.Fqdn(name))
	if res, ok := v.chains.get(name, v.now()); ok {
		r.Trace.printf(ctx, "dnssec %s: chain of trust cached (zone %s, %s)", name, res.zone, res.status)
		return res
	}
	out, _, _ := v.flight.Do(name, func() (any, error) {
		var res chainResult
		if name == "." {
			res = v.rootKeys(ctx, r)
			v.traceStep(ctx, r, name, res)
		} else if up := v.chain(ctx, r, parent(name)); up.status != SecSecure || up.stop {
			res = up
		} else {
			res = v.descend(ctx, r, up, name)
			v.traceStep(ctx, r, name, res)
		}
		if ctx.Err() == nil {
			v.chains.put(name, res, res.expires)
		}
		return res, nil
	})
	return out.(chainResult)
}

// traceStep logs the outcome of one step down the chain of trust.
func (v *Validator) traceStep(ctx context.Context, r *Resolver, name string, res chainResult) {
	switch {
	case res.status != SecSecure:
		r.Trace.printf(ctx, "dnssec %s: %s: %s", name, res.status, res.reason)
	case res.stop:
		r.Trace.printf(ctx, "dnssec %s: does not exist (DS query NXDOMAIN); chain stays at %s", name, res.zone)
	case res.zone != name:
		r.Trace.printf(ctx, "dnssec %s: no DS and a signed proof that it is not a zone cut; stays in zone %s", name, res.zone)
	default:
		r.Trace.printf(ctx, "dnssec %s: secure zone: %s", name, res.detail)
	}
}

func (v *Validator) bogus(zone, reason string) chainResult {
	return chainResult{zone: zone, status: SecBogus, reason: reason, expires: v.now().Add(failureTTL)}
}

// rootKeys validates the root DNSKEY RRset against the trust anchors.
func (v *Validator) rootKeys(ctx context.Context, r *Resolver) chainResult {
	resp, err := r.query(ctx, ".", dns.TypeDNSKEY)
	if err != nil {
		return v.bogus(".", "DNSKEY . lookup failed: "+err.Error())
	}
	keys := findRRset(resp.msg.Answer, ".", dns.TypeDNSKEY)
	if keys == nil {
		return v.bogus(".", "no DNSKEY records for the root zone; the resolver may strip DNSSEC data")
	}
	return v.trustKeys(".", keys, v.anchors, resp.msg)
}

// descend moves the chain of trust from up to child by looking up child's
// DS RRset in up's zone.
func (v *Validator) descend(ctx context.Context, r *Resolver, up chainResult, child string) chainResult {
	resp, err := r.query(ctx, child, dns.TypeDS)
	if err != nil {
		return v.bogus(child, "DS "+child+" lookup failed: "+err.Error())
	}
	m := resp.msg
	expires := minTime(up.expires, v.now().Add(max(cacheTTL(resp, nil), time.Second)))
	switch {
	case m.Rcode == dns.RcodeNameError:
		// child does not exist; the answer's own denial proves it.
		up.stop, up.expires = true, expires
		return up
	case m.Rcode != dns.RcodeSuccess:
		return v.bogus(child, fmt.Sprintf("DS %s lookup: %s", child, rcodeString(m.Rcode)))
	}
	if ds := findRRset(m.Answer, child, dns.TypeDS); ds != nil {
		if _, err := v.verify(ds, up); err != nil {
			return v.bogus(child, "DS "+child+": "+err.Error())
		}
		var dsRRs []*dns.DS
		for _, rr := range ds.rrs {
			dsRRs = append(dsRRs, rr.(*dns.DS))
		}
		if len(usableDS(dsRRs)) == 0 {
			// RFC 4035 section 5.2: only unsupported algorithms means insecure.
			return chainResult{zone: child, status: SecInsecure, expires: expires,
				reason: "DS for " + child + " uses only unsupported algorithms or digests"}
		}
		keys, err := r.query(ctx, child, dns.TypeDNSKEY)
		if err != nil {
			return v.bogus(child, "DNSKEY "+child+" lookup failed: "+err.Error())
		}
		dnskeys := findRRset(keys.msg.Answer, child, dns.TypeDNSKEY)
		if dnskeys == nil {
			return v.bogus(child, "DS exists but no DNSKEY records for "+child)
		}
		res := v.trustKeys(child, dnskeys, dsRRs, keys.msg)
		res.expires = minTime(res.expires, expires)
		return res
	}
	if findRRset(m.Answer, child, dns.TypeCNAME) != nil {
		// A zone cut cannot own a CNAME, so child is inside up's zone.
		up.expires = expires
		return up
	}
	cut, err := v.proveNoDS(child, m, up)
	switch {
	case err != nil:
		return v.bogus(child, "no DS for "+child+" and no valid proof of absence: "+err.Error())
	case cut == cutInsecure:
		return chainResult{zone: child, status: SecInsecure, reason: "insecure delegation: " + child + " has no DS in " + up.zone, expires: expires}
	}
	up.expires = expires
	return up
}

// trustKeys validates a zone's DNSKEY RRset: a key matching one of the DS
// records (or root trust anchors) must sign it (RFC 4035 section 5.2).
func (v *Validator) trustKeys(zone string, keys *rrset, dsSet []*dns.DS, m *dns.Msg) chainResult {
	usable := usableDS(dsSet)
	if len(usable) == 0 {
		return v.bogus(zone, "no trust anchor or DS for "+zone+" uses a supported algorithm and digest")
	}
	strong := false
	for _, ds := range usable {
		strong = strong || ds.DigestType != dns.SHA1
	}
	var all, trusted []*dns.DNSKEY
	for _, rr := range keys.rrs {
		k := rr.(*dns.DNSKEY)
		if k.Flags&dns.ZONE == 0 || k.Flags&dns.REVOKE != 0 {
			continue
		}
		all = append(all, k)
		for _, ds := range usable {
			// RFC 4509 section 3: ignore SHA-1 DS when a stronger one exists.
			if strong && ds.DigestType == dns.SHA1 {
				continue
			}
			if k.KeyTag() == ds.KeyTag && k.Algorithm == ds.Algorithm {
				if d := k.ToDS(ds.DigestType); d != nil && strings.EqualFold(d.Digest, ds.Digest) {
					trusted = append(trusted, k)
					break
				}
			}
		}
	}
	if len(trusted) == 0 {
		return v.bogus(zone, "no DNSKEY for "+zone+" matches its DS records or trust anchors")
	}
	sig, err := v.verify(keys, chainResult{zone: zone, keys: trusted})
	if err != nil {
		return v.bogus(zone, "DNSKEY "+zone+": "+err.Error())
	}
	source := "its DS in the parent"
	if zone == "." {
		source = "the trust anchor"
	}
	ttl := min(cacheTTL(&response{msg: m}, nil), time.Hour)
	return chainResult{zone: zone, keys: all, status: SecSecure, expires: v.now().Add(max(ttl, time.Second)),
		detail: fmt.Sprintf("%d DNSKEYs; key %d matches %s and signs the DNSKEY set", len(all), sig.KeyTag, source)}
}

// usableDS returns the DS records with an algorithm and digest type this
// validator supports.
func usableDS(dsSet []*dns.DS) []*dns.DS {
	var out []*dns.DS
	for _, ds := range dsSet {
		if supportedAlgorithms[ds.Algorithm] && supportedDigests[ds.DigestType] {
			out = append(out, ds)
		}
	}
	return out
}

type cutKind int

const (
	notCut cutKind = iota
	cutInsecure
)

// proveNoDS checks the authenticated denial of a DS RRset for child in
// up's zone. It reports whether child is an unsigned delegation (insecure)
// or not a zone cut at all.
func (v *Validator) proveNoDS(child string, m *dns.Msg, up chainResult) (cutKind, error) {
	nsecs, nsec3s, err := v.denialRecords(m, up)
	if err != nil {
		return 0, err
	}
	for _, n := range nsecs {
		if equalName(n.Hdr.Name, child) {
			switch {
			case hasType(n.TypeBitMap, dns.TypeDS):
				return 0, errors.New("NSEC says a DS exists")
			case hasType(n.TypeBitMap, dns.TypeSOA):
				return 0, errors.New("NSEC is from the child zone, not the parent")
			case hasType(n.TypeBitMap, dns.TypeNS):
				return cutInsecure, nil
			}
			return notCut, nil
		}
	}
	if len(nsecs) > 0 && nsecNoData(child, dns.TypeDS, nsecs) {
		return notCut, nil // empty non-terminal or wildcard without DS
	}
	if len(nsec3s) > 0 {
		if insecure, why := nsec3Unusable(nsec3s); insecure {
			return 0, errors.New(why)
		}
		if n := nsec3Match(nsec3s, child); n != nil {
			switch {
			case hasType(n.TypeBitMap, dns.TypeDS):
				return 0, errors.New("NSEC3 says a DS exists")
			case hasType(n.TypeBitMap, dns.TypeSOA):
				return 0, errors.New("NSEC3 is from the child zone, not the parent")
			case hasType(n.TypeBitMap, dns.TypeNS):
				return cutInsecure, nil
			}
			return notCut, nil
		}
		// RFC 5155 section 8.6: an opt-out span over the next closer name
		// may hide an unsigned delegation.
		switch nsec3NoData(child, dns.TypeDS, nsec3s) {
		case SecInsecure:
			return cutInsecure, nil
		case SecSecure:
			return notCut, nil // wildcard without DS
		}
	}
	return 0, errors.New("no NSEC or NSEC3 record proves it")
}

// denialRecords returns the NSEC and NSEC3 records in m's authority
// section, each of whose RRsets must validate with ch's keys.
func (v *Validator) denialRecords(m *dns.Msg, ch chainResult) ([]*dns.NSEC, []*dns.NSEC3, error) {
	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	for _, s := range groupRRsets(m.Ns) {
		if s.rtype != dns.TypeNSEC && s.rtype != dns.TypeNSEC3 && s.rtype != dns.TypeSOA {
			continue
		}
		if _, err := v.verify(s, ch); err != nil {
			return nil, nil, fmt.Errorf("%s %s: %w", s.name, typeString(s.rtype), err)
		}
		for _, rr := range s.rrs {
			switch x := rr.(type) {
			case *dns.NSEC:
				nsecs = append(nsecs, x)
			case *dns.NSEC3:
				nsec3s = append(nsec3s, x)
			}
		}
	}
	return nsecs, nsec3s, nil
}

// validateDenial checks the proof that name has no qtype data (NODATA) or
// does not exist (NXDOMAIN), per RFC 4035 section 5.4 and RFC 5155
// section 8.
func (v *Validator) validateDenial(ctx context.Context, r *Resolver, name string, qtype uint16, m *dns.Msg) (string, string) {
	status, reason, how := v.denial(ctx, r, name, qtype, m)
	if status == SecSecure {
		r.Trace.printf(ctx, "dnssec %s %s: %s: secure", name, typeString(qtype), how)
	} else {
		r.Trace.printf(ctx, "dnssec %s %s: %s: %s", name, typeString(qtype), status, reason)
	}
	return status, reason
}

// denial does the work of validateDenial and also describes the proof.
func (v *Validator) denial(ctx context.Context, r *Resolver, name string, qtype uint16, m *dns.Msg) (string, string, string) {
	ch := v.signingChain(ctx, r, name, qtype)
	if ch.status != SecSecure {
		return ch.status, ch.reason, ""
	}
	nx := m.Rcode == dns.RcodeNameError
	what := "NODATA"
	if nx {
		what = "NXDOMAIN"
	}
	nsecs, nsec3s, err := v.denialRecords(m, ch)
	if err != nil {
		return SecBogus, what + " proof: " + err.Error(), ""
	}
	switch {
	case len(nsecs) > 0:
		ok := nx && nsecNXDomain(name, nsecs) || !nx && nsecNoData(name, qtype, nsecs)
		if ok {
			return SecSecure, "", what + " proven by NSEC"
		}
		return SecBogus, fmt.Sprintf("NSEC records do not prove %s for %s", what, name), ""
	case len(nsec3s) > 0:
		if insecure, why := nsec3Unusable(nsec3s); insecure {
			return SecInsecure, why, ""
		}
		var status string
		if nx {
			status = nsec3NXDomain(name, nsec3s)
		} else {
			status = nsec3NoData(name, qtype, nsec3s)
		}
		if status == SecBogus {
			return SecBogus, fmt.Sprintf("NSEC3 records do not prove %s for %s", what, name), ""
		}
		if status == SecInsecure {
			return SecInsecure, "NSEC3 opt-out: " + name + " may be an unsigned delegation", ""
		}
		return SecSecure, "", what + " proven by NSEC3"
	}
	return SecBogus, what + " for " + name + " without NSEC or NSEC3 proof", ""
}

// wildcardProof checks that an answer synthesized from a wildcard with
// labels labels was needed: no closer name exists (RFC 4035 section 5.3.4,
// RFC 5155 section 8.8).
func (v *Validator) wildcardProof(name string, labels int, m *dns.Msg, ch chainResult) error {
	nsecs, nsec3s, err := v.denialRecords(m, ch)
	if err != nil {
		return err
	}
	for _, n := range nsecs {
		if nsecCovers(n, name) {
			return nil
		}
	}
	if len(nsec3s) > 0 {
		idx := dns.Split(name)
		nextCloser := name[idx[len(idx)-labels-1]:]
		if nsec3Cover(nsec3s, nextCloser) != nil {
			return nil
		}
	}
	return errors.New("no NSEC or NSEC3 record covers " + name)
}

// nsecNoData: an NSEC at name without qtype or CNAME, an empty
// non-terminal, or a wildcard without qtype (RFC 4035 section 3.1.3).
func nsecNoData(name string, qtype uint16, nsecs []*dns.NSEC) bool {
	lacks := func(n *dns.NSEC) bool {
		return !hasType(n.TypeBitMap, qtype) && !hasType(n.TypeBitMap, dns.TypeCNAME)
	}
	for _, n := range nsecs {
		if equalName(n.Hdr.Name, name) {
			return lacks(n)
		}
		if nsecCovers(n, name) && dns.IsSubDomain(name, n.NextDomain) {
			return true // empty non-terminal
		}
	}
	for _, n := range nsecs {
		if nsecCovers(n, name) {
			wild := wildcardOf(nsecClosestEncloser(name, n))
			for _, w := range nsecs {
				if equalName(w.Hdr.Name, wild) {
					return lacks(w)
				}
			}
		}
	}
	return false
}

// nsecNXDomain: an NSEC covers name, and another covers the wildcard at
// its closest encloser (RFC 4035 section 5.4).
func nsecNXDomain(name string, nsecs []*dns.NSEC) bool {
	for _, n := range nsecs {
		if !nsecCovers(n, name) || dns.IsSubDomain(name, n.NextDomain) {
			continue
		}
		wild := wildcardOf(nsecClosestEncloser(name, n))
		for _, w := range nsecs {
			if nsecCovers(w, wild) {
				return true
			}
		}
	}
	return false
}

// nsecClosestEncloser is the longest ancestor of name shared with the
// owner or next name of the NSEC covering it.
func nsecClosestEncloser(name string, n *dns.NSEC) string {
	common := max(dns.CompareDomainName(name, n.Hdr.Name), dns.CompareDomainName(name, n.NextDomain))
	idx := dns.Split(name)
	switch {
	case common == 0:
		return "."
	case common >= len(idx):
		return name
	}
	return name[idx[len(idx)-common]:]
}

// wildcardOf returns the wildcard name at the closest encloser ce.
func wildcardOf(ce string) string {
	if ce == "." {
		return "*."
	}
	return "*." + ce
}

// nsecCovers reports whether name falls strictly between the NSEC owner
// and next name in canonical order (the last NSEC wraps to the apex).
func nsecCovers(n *dns.NSEC, name string) bool {
	owner, next := n.Hdr.Name, n.NextDomain
	if canonicalCompare(owner, name) >= 0 {
		return false
	}
	if canonicalCompare(next, owner) <= 0 {
		return dns.IsSubDomain(next, name)
	}
	return canonicalCompare(name, next) < 0
}

// nsec3Unusable reports NSEC3 parameters a validator treats as insecure:
// an unknown hash (RFC 5155 section 8.1) or too many iterations (RFC 9276).
func nsec3Unusable(nsec3s []*dns.NSEC3) (bool, string) {
	for _, n := range nsec3s {
		if n.Hash != dns.SHA1 {
			return true, fmt.Sprintf("NSEC3 uses unknown hash algorithm %d", n.Hash)
		}
		if n.Iterations > maxNSEC3Iterations {
			return true, fmt.Sprintf("NSEC3 uses %d iterations (more than %d, RFC 9276)", n.Iterations, maxNSEC3Iterations)
		}
	}
	return false, ""
}

func nsec3Match(nsec3s []*dns.NSEC3, name string) *dns.NSEC3 {
	for _, n := range nsec3s {
		if n.Match(name) {
			return n
		}
	}
	return nil
}

func nsec3Cover(nsec3s []*dns.NSEC3, name string) *dns.NSEC3 {
	for _, n := range nsec3s {
		if n.Cover(name) {
			return n
		}
	}
	return nil
}

// closestEncloser finds the closest encloser proof for name (RFC 5155
// section 8.3): the longest existing ancestor, and the NSEC3 covering the
// next closer name.
func closestEncloser(name string, nsec3s []*dns.NSEC3) (string, *dns.NSEC3, error) {
	for nextCloser := name; nextCloser != "."; nextCloser = parent(nextCloser) {
		ce := parent(nextCloser)
		if nsec3Match(nsec3s, ce) != nil {
			if cover := nsec3Cover(nsec3s, nextCloser); cover != nil {
				return ce, cover, nil
			}
			return "", nil, errors.New("next closer name " + nextCloser + " is not covered")
		}
	}
	return "", nil, errors.New("no closest encloser for " + name)
}

// nsec3NXDomain: closest encloser proof plus a covered wildcard (RFC 5155
// section 8.4). An opt-out span over the next closer name makes the answer
// insecure: the name may exist as an unsigned delegation (section 9.2).
func nsec3NXDomain(name string, nsec3s []*dns.NSEC3) string {
	ce, cover, err := closestEncloser(name, nsec3s)
	if err != nil || nsec3Cover(nsec3s, wildcardOf(ce)) == nil {
		return SecBogus
	}
	if cover.Flags&1 == 1 {
		return SecInsecure
	}
	return SecSecure
}

// nsec3NoData: an NSEC3 matching name without qtype or CNAME, an opt-out
// span for a DS query (insecure, RFC 5155 sections 8.6 and 9.2), or a
// matching wildcard without qtype (sections 8.5 and 8.7).
func nsec3NoData(name string, qtype uint16, nsec3s []*dns.NSEC3) string {
	lacks := func(n *dns.NSEC3) bool {
		return !hasType(n.TypeBitMap, qtype) && !hasType(n.TypeBitMap, dns.TypeCNAME)
	}
	if n := nsec3Match(nsec3s, name); n != nil {
		if lacks(n) {
			return SecSecure
		}
		return SecBogus
	}
	ce, cover, err := closestEncloser(name, nsec3s)
	if err != nil {
		return SecBogus
	}
	if qtype == dns.TypeDS && cover.Flags&1 == 1 {
		return SecInsecure
	}
	if w := nsec3Match(nsec3s, wildcardOf(ce)); w != nil && lacks(w) {
		return SecSecure
	}
	return SecBogus
}

func hasType(bitmap []uint16, t uint16) bool {
	for _, b := range bitmap {
		if b == t {
			return true
		}
	}
	return false
}

// canonicalCompare orders names as in RFC 4034 section 6.1: label by label
// from the right, comparing lower-cased label bytes.
func canonicalCompare(a, b string) int {
	la, lb := canonicalLabels(a), canonicalLabels(b)
	for i := 1; i <= len(la) && i <= len(lb); i++ {
		if c := bytes.Compare(la[len(la)-i], lb[len(lb)-i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(la), len(lb))
}

// canonicalLabels splits name into lower-cased labels with \DDD and \X
// escapes decoded.
func canonicalLabels(name string) [][]byte {
	var out [][]byte
	for _, label := range dns.SplitDomainName(name) {
		var b []byte
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c == '\\' && i+1 < len(label) {
				if i+3 < len(label) && isDigits(label[i+1:i+4]) {
					n, _ := strconv.Atoi(label[i+1 : i+4])
					c, i = byte(n), i+3
				} else {
					c, i = label[i+1], i+1
				}
			}
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			b = append(b, c)
		}
		out = append(out, b)
	}
	return out
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func equalName(a, b string) bool {
	return strings.EqualFold(dns.Fqdn(a), dns.Fqdn(b))
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func rcodeString(rcode int) string {
	if s, ok := dns.RcodeToString[rcode]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", rcode)
}
