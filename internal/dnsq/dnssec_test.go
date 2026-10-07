package dnsq

import (
	"bytes"
	"context"
	"crypto"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testZone is a small zone signed with one ECDSA key, with an NSEC or
// NSEC3 chain, used to exercise the validator end to end.
type testZone struct {
	origin     string
	signed     bool
	mode       string // "nsec", "nsec3" or "nsec3-optout"
	iterations uint16
	key        *dns.DNSKEY
	priv       crypto.Signer
	inception  uint32
	expiration uint32
	data       map[string]map[uint16][]dns.RR
	sigs       map[string]map[uint16]*dns.RRSIG
	nsecs      []*dns.NSEC
	nsec3s     []*dns.NSEC3
	cuts       map[string]bool // unsigned delegations
}

func newTestZone(t *testing.T, origin string, signed bool, mode string) *testZone {
	t.Helper()
	now := time.Now()
	z := &testZone{
		origin: origin, signed: signed, mode: mode,
		inception:  uint32(now.Add(-time.Hour).Unix()),
		expiration: uint32(now.Add(24 * time.Hour).Unix()),
		data:       map[string]map[uint16][]dns.RR{},
		sigs:       map[string]map[uint16]*dns.RRSIG{},
		cuts:       map[string]bool{},
	}
	z.add(t, origin+" 3600 IN SOA ns.example. admin.example. 1 7200 3600 1209600 300")
	z.add(t, origin+" 3600 IN NS ns.example.")
	if signed {
		z.key = &dns.DNSKEY{Hdr: dns.RR_Header{Name: origin, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
		priv, err := z.key.Generate(256)
		if err != nil {
			t.Fatal(err)
		}
		z.priv = priv.(crypto.Signer)
		z.addRR(z.key)
	}
	return z
}

func (z *testZone) add(t *testing.T, lines ...string) {
	t.Helper()
	for _, l := range lines {
		rr, err := dns.NewRR(l)
		if err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		z.addRR(rr)
	}
}

func (z *testZone) addRR(rr dns.RR) {
	h := rr.Header()
	name := strings.ToLower(h.Name)
	if z.data[name] == nil {
		z.data[name] = map[uint16][]dns.RR{}
	}
	z.data[name][h.Rrtype] = append(z.data[name][h.Rrtype], rr)
}

// delegate adds child's NS and, when signed, a DS for its key (or ds).
func (z *testZone) delegate(t *testing.T, child *testZone, ds ...*dns.DS) {
	z.add(t, child.origin+" 3600 IN NS ns.example.")
	switch {
	case len(ds) > 0:
		for _, d := range ds {
			z.addRR(d)
		}
	case child.signed:
		d := child.key.ToDS(dns.SHA256)
		d.Hdr.Ttl = 3600
		z.addRR(d)
	default:
		z.cuts[child.origin] = true
	}
}

func (z *testZone) signRRset(t *testing.T, rrs []dns.RR) *dns.RRSIG {
	h := rrs[0].Header()
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: h.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: h.Ttl},
		Inception: z.inception, Expiration: z.expiration, KeyTag: z.key.KeyTag(),
		SignerName: z.origin, Algorithm: z.key.Algorithm}
	if err := sig.Sign(z.priv, rrs); err != nil {
		t.Fatal(err)
	}
	return sig
}

func (z *testZone) setSig(name string, rt uint16, sig *dns.RRSIG) {
	if z.sigs[name] == nil {
		z.sigs[name] = map[uint16]*dns.RRSIG{}
	}
	z.sigs[name][rt] = sig
}

// isCut reports whether name is a delegation point below the apex.
func (z *testZone) isCut(name string) bool {
	return name != z.origin && len(z.data[name][dns.TypeNS]) > 0
}

// exists reports whether name owns data or is an empty non-terminal.
func (z *testZone) exists(name string) bool {
	if z.data[name] != nil {
		return true
	}
	for owner := range z.data {
		if owner != name && dns.IsSubDomain(name, owner) {
			return true
		}
	}
	return false
}

// sign signs every authoritative RRset and builds the denial chain.
func (z *testZone) sign(t *testing.T) {
	if !z.signed {
		return
	}
	for name, types := range z.data {
		for rt, rrs := range types {
			if rt == dns.TypeNS && z.isCut(name) {
				continue // delegation NS records are not signed
			}
			z.setSig(name, rt, z.signRRset(t, rrs))
		}
	}
	bitmap := func(name string) []uint16 {
		var types []uint16
		for rt := range z.data[name] {
			types = append(types, rt)
		}
		if len(z.sigs[name]) > 0 || z.mode == "nsec" {
			types = append(types, dns.TypeRRSIG)
		}
		if z.mode == "nsec" {
			types = append(types, dns.TypeNSEC)
		}
		slices.Sort(types)
		return types
	}
	if z.mode == "nsec" {
		var owners []string
		for name := range z.data {
			owners = append(owners, name)
		}
		sort.Slice(owners, func(i, j int) bool { return canonicalCompare(owners[i], owners[j]) < 0 })
		for i, name := range owners {
			n := &dns.NSEC{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: owners[(i+1)%len(owners)], TypeBitMap: bitmap(name)}
			z.nsecs = append(z.nsecs, n)
			z.setSig(name, dns.TypeNSEC, z.signRRset(t, []dns.RR{n}))
		}
		return
	}
	// NSEC3: every owner and empty non-terminal, minus opted-out cuts.
	names := map[string]bool{}
	for owner := range z.data {
		for n := owner; dns.IsSubDomain(z.origin, n); n = parent(n) {
			names[n] = true
			if n == z.origin {
				break
			}
		}
	}
	type hashed struct {
		hash string
		name string
	}
	var hs []hashed
	for name := range names {
		if z.mode == "nsec3-optout" && z.cuts[name] {
			continue
		}
		hs = append(hs, hashed{dns.HashName(name, dns.SHA1, z.iterations, ""), name})
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].hash < hs[j].hash })
	var flags uint8
	if z.mode == "nsec3-optout" {
		flags = 1
	}
	for i, h := range hs {
		owner := strings.ToLower(h.hash) + "." + z.origin
		if z.origin == "." {
			owner = strings.ToLower(h.hash) + "."
		}
		n := &dns.NSEC3{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
			Hash: dns.SHA1, Flags: flags, Iterations: z.iterations, HashLength: 20,
			NextDomain: hs[(i+1)%len(hs)].hash, TypeBitMap: bitmap(h.name)}
		z.nsec3s = append(z.nsec3s, n)
		z.setSig(owner, dns.TypeNSEC3, z.signRRset(t, []dns.RR{n}))
	}
}

// withSig returns the RRset at name/rt followed by its RRSIG.
func (z *testZone) withSig(name string, rt uint16) []dns.RR {
	out := append([]dns.RR{}, z.data[name][rt]...)
	if sig := z.sigs[name][rt]; sig != nil {
		out = append(out, sig)
	}
	return out
}

const (
	proofNoData = iota
	proofNXDomain
	proofWildcardAnswer
	proofWildcardNoData
)

// proof returns the NSEC or NSEC3 records (with RRSIGs) a server would
// include for name.
func (z *testZone) proof(kind int, name string) []dns.RR {
	if !z.signed {
		return nil
	}
	var out []dns.RR
	seen := map[string]bool{}
	add := func(rr dns.RR) {
		if rr == nil || seen[rr.Header().Name] {
			return
		}
		seen[rr.Header().Name] = true
		out = append(out, rr, z.sigs[strings.ToLower(rr.Header().Name)][rr.Header().Rrtype])
	}
	if z.mode == "nsec" {
		at := func(n string) dns.RR {
			for _, x := range z.nsecs {
				if equalName(x.Hdr.Name, n) {
					return x
				}
			}
			return nil
		}
		covering := func(n string) dns.RR {
			for _, x := range z.nsecs {
				if nsecCovers(x, n) {
					return x
				}
			}
			return nil
		}
		ce := parent(name)
		for !z.exists(ce) {
			ce = parent(ce)
		}
		switch kind {
		case proofNoData:
			if n := at(name); n != nil {
				add(n)
			} else {
				add(covering(name)) // empty non-terminal
			}
		case proofNXDomain:
			add(covering(name))
			add(covering(wildcardOf(ce)))
		case proofWildcardAnswer:
			add(covering(name))
		case proofWildcardNoData:
			add(covering(name))
			add(at(wildcardOf(ce)))
		}
		return out
	}
	match := func(n string) dns.RR {
		if x := nsec3Match(z.nsec3s, n); x != nil {
			return x
		}
		return nil
	}
	cover := func(n string) dns.RR {
		if x := nsec3Cover(z.nsec3s, n); x != nil {
			return x
		}
		return nil
	}
	ce := parent(name)
	for match(ce) == nil {
		ce = parent(ce)
	}
	idx := dns.Split(name)
	nextCloser := name[idx[len(idx)-dns.CountLabel(ce)-1]:]
	switch kind {
	case proofNoData:
		if n := match(name); n != nil {
			add(n)
		} else {
			add(match(ce)) // opt-out: closest provable encloser
			add(cover(nextCloser))
		}
	case proofNXDomain:
		add(match(ce))
		add(cover(nextCloser))
		add(cover(wildcardOf(ce)))
	case proofWildcardAnswer:
		add(cover(nextCloser))
	case proofWildcardNoData:
		add(match(ce))
		add(cover(nextCloser))
		add(match(wildcardOf(ce)))
	}
	return out
}

// testWorld answers like a recursive resolver over a set of test zones.
type testWorld struct {
	zones  []*testZone
	tamper func(q dns.Question, m *dns.Msg)

	mu      sync.Mutex
	queries map[string]int
}

func (w *testWorld) zoneFor(name string, qtype uint16) *testZone {
	var best *testZone
	for _, z := range w.zones {
		if !dns.IsSubDomain(z.origin, name) {
			continue
		}
		if qtype == dns.TypeDS && equalName(z.origin, name) && name != "." {
			continue // DS is served by the parent
		}
		if best == nil || dns.CountLabel(z.origin) > dns.CountLabel(best.origin) {
			best = z
		}
	}
	return best
}

func (w *testWorld) count(name string, qtype uint16) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.queries[strings.ToLower(name)+" "+typeString(qtype)]
}

func (w *testWorld) ServeDNS(rw dns.ResponseWriter, req *dns.Msg) {
	q := req.Question[0]
	w.mu.Lock()
	if w.queries == nil {
		w.queries = map[string]int{}
	}
	w.queries[strings.ToLower(q.Name)+" "+typeString(q.Qtype)]++
	w.mu.Unlock()
	m := new(dns.Msg)
	m.SetReply(req)
	if opt := req.IsEdns0(); opt != nil {
		m.SetEdns0(4096, opt.Do())
	}
	w.resolve(m, strings.ToLower(q.Name), q.Qtype, 0)
	if w.tamper != nil {
		// The response shares record objects with the zone; tamper with a
		// deep copy so the zone stays intact and goroutines serving other
		// queries never see a write.
		m = m.Copy()
		w.tamper(q, m)
	}
	_ = rw.WriteMsg(m)
}

func (w *testWorld) resolve(m *dns.Msg, name string, qtype uint16, depth int) {
	z := w.zoneFor(name, qtype)
	if z == nil || depth > 8 {
		m.Rcode = dns.RcodeServerFailure
		return
	}
	// DNAME at an ancestor within the zone.
	for anc := parent(name); anc != z.origin && dns.IsSubDomain(z.origin, anc); anc = parent(anc) {
		if d := z.data[anc][dns.TypeDNAME]; len(d) > 0 {
			target := strings.TrimSuffix(name, anc) + d[0].(*dns.DNAME).Target
			m.Answer = append(m.Answer, z.withSig(anc, dns.TypeDNAME)...)
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: target})
			w.resolve(m, target, qtype, depth+1)
			return
		}
	}
	if len(z.data[name][qtype]) > 0 {
		m.Answer = append(m.Answer, z.withSig(name, qtype)...)
		return
	}
	if c := z.data[name][dns.TypeCNAME]; len(c) > 0 && qtype != dns.TypeCNAME {
		m.Answer = append(m.Answer, z.withSig(name, dns.TypeCNAME)...)
		w.resolve(m, c[0].(*dns.CNAME).Target, qtype, depth+1)
		return
	}
	soa := z.withSig(z.origin, dns.TypeSOA)
	if z.exists(name) {
		m.Ns = append(append(m.Ns, soa...), z.proof(proofNoData, name)...)
		return
	}
	ce := parent(name)
	for !z.exists(ce) {
		ce = parent(ce)
	}
	wild := wildcardOf(ce)
	if z.data[wild] != nil {
		if rrs := z.data[wild][qtype]; len(rrs) > 0 {
			for _, rr := range rrs {
				c := dns.Copy(rr)
				c.Header().Name = name
				m.Answer = append(m.Answer, c)
			}
			if sig := z.sigs[wild][qtype]; sig != nil {
				c := dns.Copy(sig)
				c.Header().Name = name
				m.Answer = append(m.Answer, c)
			}
			m.Ns = append(m.Ns, z.proof(proofWildcardAnswer, name)...)
			return
		}
		m.Ns = append(append(m.Ns, soa...), z.proof(proofWildcardNoData, name)...)
		return
	}
	m.Rcode = dns.RcodeNameError
	m.Ns = append(append(m.Ns, soa...), z.proof(proofNXDomain, name)...)
}

// newTestWorld builds the signed test hierarchy and returns it with the
// root trust anchor.
func newTestWorld(t *testing.T) (*testWorld, []*dns.DS) {
	t.Helper()
	root := newTestZone(t, ".", true, "nsec")
	tld := newTestZone(t, "test.", true, "nsec3")
	sec := newTestZone(t, "sec.test.", true, "nsec")
	insec := newTestZone(t, "insec.test.", false, "")
	unsig := newTestZone(t, "unsig.sec.test.", false, "")
	broken := newTestZone(t, "broken.test.", true, "nsec")
	expired := newTestZone(t, "expired.test.", true, "nsec")
	expired.inception = uint32(time.Now().Add(-48 * time.Hour).Unix())
	expired.expiration = uint32(time.Now().Add(-24 * time.Hour).Unix())
	ed448 := newTestZone(t, "ed448.test.", false, "")
	badDigest := newTestZone(t, "baddigest.test.", true, "nsec")
	revoked := newTestZone(t, "revoked.test.", true, "nsec")
	revoked.key.Flags |= dns.REVOKE // RFC 5011: must not be trusted
	iter := newTestZone(t, "iter.test.", true, "nsec3")
	iter.iterations = 200
	opt := newTestZone(t, "opt.", true, "nsec3-optout")
	unsignedUnderOpt := newTestZone(t, "u.opt.", false, "")
	signedUnderOpt := newTestZone(t, "s.opt.", true, "nsec")

	sec.add(t,
		"www.sec.test. 300 IN A 192.0.2.1",
		"alias.sec.test. 300 IN CNAME www.sec.test.",
		"mail.sec.test. 300 IN MX 10 www.sec.test.",
		"a.b.sec.test. 300 IN A 192.0.2.2",
		"*.wild.sec.test. 300 IN A 192.0.2.3",
		"dn.sec.test. 300 IN DNAME sec.test.",
	)
	tld.add(t,
		"*.w3.test. 300 IN A 192.0.2.4",
		"host.test. 300 IN A 192.0.2.5",
	)
	for _, z := range []*testZone{insec, unsig, badDigest, revoked, broken, expired, ed448, iter, unsignedUnderOpt, signedUnderOpt} {
		z.add(t, "www."+z.origin+" 300 IN A 192.0.2.10")
	}
	wrongKey := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "broken.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	if _, err := wrongKey.Generate(256); err != nil {
		t.Fatal(err)
	}
	wrongDS := wrongKey.ToDS(dns.SHA256)
	wrongDS.Hdr.Ttl = 3600
	ed448DS, _ := dns.NewRR("ed448.test. 3600 IN DS 12345 16 2 0000000000000000000000000000000000000000000000000000000000000000")

	root.delegate(t, tld)
	root.delegate(t, opt)
	tld.delegate(t, sec)
	sec.delegate(t, unsig)
	tld.delegate(t, insec)
	tld.delegate(t, broken, wrongDS)
	tld.delegate(t, expired)
	tld.delegate(t, ed448, ed448DS.(*dns.DS))
	// Right key tag and algorithm, wrong digest.
	bad := badDigest.key.ToDS(dns.SHA256)
	bad.Hdr.Ttl = 3600
	bad.Digest = strings.Repeat("0", len(bad.Digest))
	tld.delegate(t, badDigest, bad)
	tld.delegate(t, revoked)
	tld.delegate(t, iter)
	opt.delegate(t, unsignedUnderOpt)
	opt.delegate(t, signedUnderOpt)

	zones := []*testZone{root, tld, sec, insec, unsig, badDigest, revoked, broken, expired, ed448, iter, opt, unsignedUnderOpt, signedUnderOpt}
	for _, z := range zones {
		z.sign(t)
	}
	return &testWorld{zones: zones}, []*dns.DS{root.key.ToDS(dns.SHA256)}
}

func newValidatingResolver(t *testing.T, w *testWorld, anchors []*dns.DS) *Resolver {
	t.Helper()
	addr := startServer(t, w.ServeDNS)
	// TCP keeps signed responses clear of UDP size limits.
	return &Resolver{Servers: []string{addr}, TCP: true, Timeout: 2 * time.Second,
		Cache: NewCache(1000), Validator: NewValidator(anchors, 1000)}
}

func TestDNSSECValidation(t *testing.T) {
	w, anchors := newTestWorld(t)
	r := newValidatingResolver(t, w, anchors)
	cases := []struct {
		name, qtype, status, dnssec, reason string
	}{
		{"www.sec.test", "A", StatusNoError, SecSecure, ""},
		{"alias.sec.test", "A", StatusNoError, SecSecure, ""},
		{"alias.sec.test", "CNAME", StatusNoError, SecSecure, ""},
		{"nope.sec.test", "A", "NXDOMAIN", SecSecure, ""},
		{"mail.sec.test", "A", StatusNoData, SecSecure, ""},
		{"b.sec.test", "A", StatusNoData, SecSecure, ""}, // empty non-terminal
		{"foo.wild.sec.test", "A", StatusNoError, SecSecure, ""},
		{"foo.wild.sec.test", "MX", StatusNoData, SecSecure, ""},
		{"www.dn.sec.test", "A", StatusNoError, SecSecure, ""}, // DNAME
		{"sec.test", "DNSKEY", StatusNoError, SecSecure, ""},
		{"sec.test", "DS", StatusNoError, SecSecure, ""},
		{"host.test", "A", StatusNoError, SecSecure, ""},
		{"nope.test", "A", "NXDOMAIN", SecSecure, ""},      // NSEC3
		{"host.test", "MX", StatusNoData, SecSecure, ""},   // NSEC3
		{"foo.w3.test", "A", StatusNoError, SecSecure, ""}, // NSEC3 wildcard
		{"foo.w3.test", "MX", StatusNoData, SecSecure, ""},
		{"www.insec.test", "A", StatusNoError, SecInsecure, "insecure delegation"},
		{"www.unsig.sec.test", "A", StatusNoError, SecInsecure, "insecure delegation"}, // NSEC parent
		{"unsig.sec.test", "DS", StatusNoData, SecSecure, ""},
		{"insec.test", "DS", StatusNoData, SecSecure, ""}, // proven absent, no opt-out
		{"www.broken.test", "A", StatusNoError, SecBogus, "matches its DS"},
		{"broken.test", "DS", StatusNoError, SecSecure, ""}, // the DS itself is authentic
		{"www.expired.test", "A", StatusNoError, SecBogus, "not valid now"},
		{"www.baddigest.test", "A", StatusNoError, SecBogus, "matches its DS"},
		{"www.revoked.test", "A", StatusNoError, SecBogus, "matches its DS"},
		{"www.ed448.test", "A", StatusNoError, SecInsecure, "unsupported algorithms"},
		{"nope.iter.test", "A", "NXDOMAIN", SecInsecure, "iterations"},
		{"www.u.opt", "A", StatusNoError, SecInsecure, "insecure delegation"},
		{"u.opt", "DS", StatusNoData, SecInsecure, "opt-out"},
		{"nope.opt", "A", "NXDOMAIN", SecInsecure, "opt-out"},
		{"www.s.opt", "A", StatusNoError, SecSecure, ""},
	}
	for _, c := range cases {
		qt, _ := ParseType(c.qtype)
		row := r.Lookup(context.Background(), c.name, qt, false)[0]
		if row.Status != c.status || row.DNSSEC != c.dnssec || !strings.Contains(row.DNSSECReason, c.reason) {
			t.Errorf("%s %s: got %s/%s %q, want %s/%s containing %q",
				c.name, c.qtype, row.Status, row.DNSSEC, row.DNSSECReason, c.status, c.dnssec, c.reason)
		}
	}
}

func TestDNSSECTampering(t *testing.T) {
	stripAuthority := func(q dns.Question, m *dns.Msg) {
		if q.Qtype == dns.TypeA {
			m.Ns = nil
		}
	}
	cases := []struct {
		name, qtype string
		tamper      func(q dns.Question, m *dns.Msg)
		reason      string
	}{
		{"foo.wild.sec.test", "A", stripAuthority, "wildcard answer without proof"}, // NSEC
		{"foo.w3.test", "A", stripAuthority, "wildcard answer without proof"},       // NSEC3
		{"www.sec.test", "A", func(q dns.Question, m *dns.Msg) {
			if q.Qtype == dns.TypeA {
				m.Answer[0].(*dns.A).A = net.IPv4(203, 0, 113, 66)
			}
		}, "does not verify"},
		{"www.sec.test", "A", func(q dns.Question, m *dns.Msg) {
			if q.Qtype == dns.TypeA {
				m.Answer = m.Answer[:1] // strip the RRSIG
			}
		}, "missing RRSIG"},
		{"nope.sec.test", "A", func(q dns.Question, m *dns.Msg) {
			if q.Qtype == dns.TypeA {
				m.Ns = m.Ns[:2] // keep the SOA, drop the NSEC proof
			}
		}, "without NSEC or NSEC3 proof"},
		{"www.sec.test", "A", func(q dns.Question, m *dns.Msg) {
			if q.Qtype == dns.TypeA { // forged unsigned NXDOMAIN
				m.Rcode, m.Answer, m.Ns = dns.RcodeNameError, nil, nil
			}
		}, "without NSEC or NSEC3 proof"},
		{"www.dn.sec.test", "A", func(q dns.Question, m *dns.Msg) {
			for _, rr := range m.Answer {
				if c, ok := rr.(*dns.CNAME); ok {
					c.Target = "www.evil.test."
				}
			}
		}, "does not match DNAME"},
		{"www.insec.test", "A", func(q dns.Question, m *dns.Msg) {
			if q.Qtype == dns.TypeDS && q.Name == "insec.test." {
				m.Ns = nil // hide the proof that insec.test is unsigned
			}
		}, "no valid proof of absence"},
		{"www.sec.test", "A", func(q dns.Question, m *dns.Msg) {
			if q.Qtype == dns.TypeDNSKEY && q.Name == "." {
				m.Answer = nil // a resolver that strips DNSSEC data
			}
		}, "may strip DNSSEC data"},
		{"www.sec.test", "A", nil, "signed by test., but the zone is sec.test."},
		{"nope.sec.test", "A", func(q dns.Question, m *dns.Msg) {
			for _, rr := range m.Ns {
				if n, ok := rr.(*dns.NSEC); ok {
					n.NextDomain = "zzzz.sec.test." // still covers, but no longer signed
				}
			}
		}, "does not verify"},
		{"nope.sec.test", "A", func(q dns.Question, m *dns.Msg) {
			// Keep the wildcard proof, drop the NSEC covering the name.
			var ns []dns.RR
			for _, rr := range m.Ns {
				if !strings.EqualFold(rr.Header().Name, "mail.sec.test.") {
					ns = append(ns, rr)
				}
			}
			m.Ns = ns
		}, "do not prove NXDOMAIN"},
	}
	// A forged NODATA using the real, validly signed NSEC or NSEC3 at a
	// name that does have the type.
	for _, c := range []struct{ name, zone string }{{"www.sec.test.", "sec.test."}, {"host.test.", "test."}} {
		w, anchors := newTestWorld(t)
		var z *testZone
		for _, x := range w.zones {
			if x.origin == c.zone {
				z = x
			}
		}
		w.tamper = func(q dns.Question, m *dns.Msg) {
			if q.Qtype == dns.TypeA && q.Name == c.name {
				m.Answer = nil
				m.Ns = append(z.withSig(z.origin, dns.TypeSOA), z.proof(proofNoData, c.name)...)
			}
		}
		r := newValidatingResolver(t, w, anchors)
		row := r.Lookup(context.Background(), c.name, dns.TypeA, false)[0]
		if row.Status != StatusNoData || row.DNSSEC != SecBogus || !strings.Contains(row.DNSSECReason, "do not prove NODATA") {
			t.Errorf("forged NODATA for %s: got %s/%s %q", c.name, row.Status, row.DNSSEC, row.DNSSECReason)
		}
	}

	for _, c := range cases {
		w, anchors := newTestWorld(t)
		w.tamper = c.tamper
		if c.tamper == nil { // re-sign the answer with the parent zone's key
			tld := w.zones[1]
			w.tamper = func(q dns.Question, m *dns.Msg) {
				if q.Qtype == dns.TypeA && q.Name == "www.sec.test." {
					m.Answer = []dns.RR{m.Answer[0], tld.signRRset(t, m.Answer[:1])}
				}
			}
		}
		r := newValidatingResolver(t, w, anchors)
		qt, _ := ParseType(c.qtype)
		rows := r.Lookup(context.Background(), c.name, qt, false)
		if !slices.ContainsFunc(rows, func(row Row) bool {
			return row.DNSSEC == SecBogus && strings.Contains(row.DNSSECReason, c.reason)
		}) {
			t.Errorf("%s tampered: no bogus row with %q in %+v", c.name, c.reason, rows)
		}
	}
}

func TestDNSSECStatusPerRRset(t *testing.T) {
	w, anchors := newTestWorld(t)
	sec := w.zones[2]
	// A signed CNAME into an unsigned zone: the CNAME row is secure, the
	// target's data is insecure, and the response as a whole is insecure.
	sec.add(t, "out.sec.test. 300 IN CNAME www.insec.test.")
	sec.add(t, "gone.sec.test. 300 IN CNAME nope.insec.test.")
	sec.sigs, sec.nsecs = map[string]map[uint16]*dns.RRSIG{}, nil
	sec.sign(t)
	r := newValidatingResolver(t, w, anchors)
	rows := r.Lookup(context.Background(), "out.sec.test", dns.TypeA, false)
	if len(rows) != 2 || rows[0].Type != "CNAME" || rows[0].DNSSEC != SecSecure || rows[1].DNSSEC != SecInsecure {
		t.Errorf("per-RRset status: %+v", rows)
	}
	// NXDOMAIN after the CNAME: the denial's status applies to the CNAME row.
	rows = r.Lookup(context.Background(), "gone.sec.test", dns.TypeA, false)
	if len(rows) != 1 || rows[0].Status != "NXDOMAIN" || rows[0].DNSSEC != SecInsecure {
		t.Errorf("negative answer after CNAME: %+v", rows)
	}
}

func TestTraceShowsQueriesAndDNSSECSteps(t *testing.T) {
	w, anchors := newTestWorld(t)
	r := newValidatingResolver(t, w, anchors)
	var trace bytes.Buffer
	r.Trace = NewTracer(&trace)
	ctx := context.Background()
	r.Lookup(ctx, "www.sec.test", dns.TypeA, false)
	r.Lookup(ctx, "www.insec.test", dns.TypeA, false)
	r.Lookup(ctx, "nope.test", dns.TypeA, false)
	r.Lookup(ctx, "www.sec.test", dns.TypeA, false)
	out := trace.String()
	for _, want := range []string{
		"trace www.sec.test: ",            // labelled by input
		"tcp . DNSKEY +DO +CD -> NOERROR", // the packet and response
		"RRSIGs, flags [",                 // response summary
		"dnssec .: secure zone: 1 DNSKEYs; key ",
		"matches the trust anchor and signs the DNSKEY set",
		"dnssec sec.test.: secure zone: ",
		"matches its DS in the parent",
		"dnssec www.sec.test. A: RRSIG by sec.test. key",
		"dnssec insec.test.: insecure: insecure delegation",
		"dnssec nope.test. A: NXDOMAIN proven by NSEC3: secure",
		"cache hit www.sec.test. A: NOERROR",
		"dnssec test.: chain of trust cached (zone test., secure)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("trace missing %q", want)
		}
	}
	if t.Failed() {
		t.Log(out)
	}
}

// TestConcurrentValidatingLookups runs many lookups at once through one
// validating, caching resolver, as dnsquery's workers do, so the race
// detector can check the shared cache, chain memo and singleflight paths.
func TestConcurrentValidatingLookups(t *testing.T) {
	w, anchors := newTestWorld(t)
	r := newValidatingResolver(t, w, anchors)
	names := []string{"www.sec.test", "alias.sec.test", "nope.sec.test", "foo.wild.sec.test", "www.dn.sec.test",
		"www.insec.test", "www.broken.test", "nope.test", "foo.w3.test", "www.u.opt", "www.s.opt", "nope.opt"}
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			for j := range len(names) {
				name := names[(i+j)%len(names)]
				if row := r.Lookup(context.Background(), name, dns.TypeA, false)[0]; row.DNSSEC == "" {
					t.Errorf("%s: no DNSSEC status", name)
				}
			}
		})
	}
	wg.Wait()
}

func TestDNSSECWrongTrustAnchor(t *testing.T) {
	w, _ := newTestWorld(t)
	wrong := &dns.DNSKEY{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	if _, err := wrong.Generate(256); err != nil {
		t.Fatal(err)
	}
	r := newValidatingResolver(t, w, []*dns.DS{wrong.ToDS(dns.SHA256)})
	row := r.Lookup(context.Background(), "www.sec.test", dns.TypeA, false)[0]
	if row.DNSSEC != SecBogus || !strings.Contains(row.DNSSECReason, "trust anchors") {
		t.Errorf("got %s %q", row.DNSSEC, row.DNSSECReason)
	}
}

func TestDNSSECChainIsCached(t *testing.T) {
	w, anchors := newTestWorld(t)
	r := newValidatingResolver(t, w, anchors)
	for _, name := range []string{"www.sec.test", "mail.sec.test", "alias.sec.test", "www.sec.test"} {
		if row := r.Lookup(context.Background(), name, dns.TypeA, false)[0]; row.DNSSEC != SecSecure {
			t.Fatalf("%s: %s %s", name, row.DNSSEC, row.DNSSECReason)
		}
	}
	for _, q := range []struct {
		name  string
		qtype uint16
	}{{".", dns.TypeDNSKEY}, {"test.", dns.TypeDS}, {"sec.test.", dns.TypeDNSKEY}, {"www.sec.test.", dns.TypeA}} {
		if n := w.count(q.name, q.qtype); n != 1 {
			t.Errorf("%s %s sent %d times, want 1", q.name, typeString(q.qtype), n)
		}
	}
}

func TestCanonicalOrder(t *testing.T) {
	// RFC 4034 section 6.1.
	ordered := []string{
		"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.",
		"zABC.a.EXAMPLE.", "z.example.", `\001.z.example.`, "*.z.example.", `\200.z.example.`,
	}
	for i := 1; i < len(ordered); i++ {
		if canonicalCompare(ordered[i-1], ordered[i]) >= 0 || canonicalCompare(ordered[i], ordered[i-1]) <= 0 {
			t.Errorf("%s should sort before %s", ordered[i-1], ordered[i])
		}
	}
	if canonicalCompare("Example.", "eXample.") != 0 {
		t.Error("comparison must ignore case")
	}
}

func TestParseTrustAnchors(t *testing.T) {
	if a, err := ParseTrustAnchors(strings.NewReader(RootAnchors), "built-in"); err != nil || len(a) != 2 {
		t.Fatalf("built-in anchors: %v, %v", a, err)
	}
	key := ". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="
	a, err := ParseTrustAnchors(strings.NewReader(key), "key")
	if err != nil || len(a) != 1 || a[0].KeyTag != 20326 || !strings.EqualFold(a[0].Digest, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D") {
		t.Errorf("DNSKEY anchor should become the KSK-2017 DS: %v, %v", a, err)
	}
	for in, want := range map[string]string{
		"example. IN DS 1 8 2 00":         "only root zone",
		". IN A 192.0.2.1":                "must be DS or DNSKEY",
		"":                                "no trust anchors",
		". IN DS not-a-number 8 2 00ff00": "bad DS",
	} {
		if _, err := ParseTrustAnchors(strings.NewReader(in), "f"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", in, err, want)
		}
	}
}

func TestCache(t *testing.T) {
	w, _ := newTestWorld(t)
	addr := startServer(t, w.ServeDNS)
	c := NewCache(2)
	now := time.Now()
	c.now = func() time.Time { return now }
	r := &Resolver{Servers: []string{addr}, TCP: true, Timeout: time.Second, Cache: c}
	ctx := context.Background()

	first := r.Lookup(ctx, "www.sec.test", dns.TypeA, false)[0]
	now = now.Add(100 * time.Second)
	again := r.Lookup(ctx, "www.sec.test", dns.TypeA, false)[0]
	if first.Cached || !again.Cached || again.TTL != first.TTL-100 || w.count("www.sec.test.", dns.TypeA) != 1 {
		t.Errorf("cache hit: first cached=%v ttl=%d, again cached=%v ttl=%d, queries=%d",
			first.Cached, first.TTL, again.Cached, again.TTL, w.count("www.sec.test.", dns.TypeA))
	}
	now = now.Add(time.Duration(again.TTL) * time.Second)
	if r.Lookup(ctx, "www.sec.test", dns.TypeA, false)[0].Cached {
		t.Error("entry should have expired with its TTL")
	}

	// Negative answers are cached for min(SOA TTL, MINIMUM) = 300s.
	r.Lookup(ctx, "nope.sec.test", dns.TypeA, false)
	now = now.Add(299 * time.Second)
	if row := r.Lookup(ctx, "nope.sec.test", dns.TypeA, false)[0]; !row.Cached || row.Status != "NXDOMAIN" {
		t.Errorf("negative answer should be cached: %+v", row)
	}

	// Size 2: a third name evicts the least recently used one.
	r.Lookup(ctx, "mail.sec.test", dns.TypeMX, false)
	r.Lookup(ctx, "host.test", dns.TypeA, false)
	if r.Lookup(ctx, "nope.sec.test", dns.TypeA, false)[0].Cached {
		t.Error("oldest entry should have been evicted")
	}

	// Failures are cached for failureTTL.
	dead := &Resolver{Servers: []string{silentServer(t)}, Timeout: 50 * time.Millisecond, Cache: c}
	if row := dead.Lookup(ctx, "x.test", dns.TypeA, false)[0]; row.Status != StatusError {
		t.Fatalf("got %s", row.Status)
	}
	start := time.Now()
	if row := dead.Lookup(ctx, "x.test", dns.TypeA, false)[0]; row.Status != StatusError || time.Since(start) > 40*time.Millisecond {
		t.Error("cached failure should return at once")
	}

	if NewCache(0) != nil {
		t.Error("size 0 must disable the cache")
	}
	var none *Cache
	none.put("k", nil, nil)
	if _, _, ok := none.get("k"); ok {
		t.Error("nil cache must be empty")
	}
}

func TestConcurrentQueriesShareOneExchange(t *testing.T) {
	w, _ := newTestWorld(t)
	r := &Resolver{Servers: []string{startServer(t, w.ServeDNS)}, TCP: true, Timeout: time.Second}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { r.Lookup(context.Background(), "www.sec.test", dns.TypeA, false) })
	}
	wg.Wait()
	if n := w.count("www.sec.test.", dns.TypeA); n > 5 {
		t.Errorf("20 concurrent identical lookups sent %d queries", n)
	}
}
