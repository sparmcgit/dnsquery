package dnsq

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Tracer writes one line per query, response and DNSSEC step, labelled
// with the input being looked up. A nil *Tracer writes nothing.
type Tracer struct {
	mu sync.Mutex
	w  io.Writer
}

// NewTracer returns a tracer writing to w.
func NewTracer(w io.Writer) *Tracer { return &Tracer{w: w} }

type traceLabelKey struct{}

// withTraceLabel tags ctx with the input a lookup was made for, so trace
// lines from concurrent workers can be told apart.
func withTraceLabel(ctx context.Context, label string) context.Context {
	return context.WithValue(ctx, traceLabelKey{}, label)
}

// on reports whether tracing is enabled. Callers whose trace arguments are
// costly to build (message summaries, time formatting) check it first, so
// a run without --trace does none of that work.
func (t *Tracer) on() bool { return t != nil }

func (t *Tracer) printf(ctx context.Context, format string, args ...any) {
	if t == nil {
		return
	}
	label, _ := ctx.Value(traceLabelKey{}).(string)
	line := fmt.Sprintf(format, args...)
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintf(t.w, "trace %s: %s\n", label, line)
}

// describeQuery renders a query as "NAME TYPE +DO +CD".
func describeQuery(m *dns.Msg) string {
	q := m.Question[0]
	s := q.Name + " " + typeString(q.Qtype)
	if opt := m.IsEdns0(); opt != nil && opt.Do() {
		s += " +DO"
	}
	if m.CheckingDisabled {
		s += " +CD"
	}
	if m.IsEdns0() == nil {
		s += " (no EDNS)"
	}
	if !m.RecursionDesired {
		s += " -RD"
	}
	for _, o := range optionsOf(m) {
		if o.Option() == dns.EDNS0NSID {
			s += " +NSID"
		}
	}
	return s
}

func optionsOf(m *dns.Msg) []dns.EDNS0 {
	if opt := m.IsEdns0(); opt != nil {
		return opt.Option
	}
	return nil
}

// describeResponse summarizes a response: RCODE, section counts, RRSIGs,
// header flags, EDNS and size.
func describeResponse(m *dns.Msg) string {
	sigs, extra := 0, 0
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeRRSIG {
				sigs++
			}
		}
	}
	for _, rr := range m.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra++
		}
	}
	var flags []string
	for _, f := range []struct {
		on   bool
		name string
	}{{m.Authoritative, "aa"}, {m.Truncated, "tc"}, {m.RecursionAvailable, "ra"}, {m.AuthenticatedData, "ad"}, {m.CheckingDisabled, "cd"}} {
		if f.on {
			flags = append(flags, f.name)
		}
	}
	edns := "no EDNS"
	if opt := m.IsEdns0(); opt != nil {
		edns = fmt.Sprintf("EDNS %d", opt.UDPSize())
		if opt.Do() {
			edns += " DO"
		}
	}
	s := fmt.Sprintf("%s, answer %d, authority %d, additional %d, %d RRSIGs, flags [%s], %s, ~%d bytes",
		rcodeString(m.Rcode), len(m.Answer), len(m.Ns), extra, sigs, strings.Join(flags, " "), edns, m.Len())
	if ede := extendedErrors(m); ede != "" {
		s += ", EDE " + ede
	}
	if id := serverID(m); id != "" {
		s += ", NSID " + id
	}
	return s
}
