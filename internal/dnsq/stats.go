package dnsq

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/miekg/dns"
)

// DirectServers is the Stats key for --check-nameservers' direct queries,
// counted together: a large run asks thousands of nameservers.
const DirectServers = "authoritative nameservers (direct)"

// Stats collects a run summary (--stats): queries and rows by status, cache
// use, and per server the queries sent and how they ended, with response
// times. Memory stays flat: times go into fixed histograms. Safe for
// concurrent use; a nil *Stats records nothing.
type Stats struct {
	mu        sync.Mutex
	queries   int
	failed    int
	statuses  map[string]int
	dnssec    map[string]int
	lookups   int
	cacheHits int
	merged    int
	all       histogram
	servers   map[string]*serverStats
	order     []string // servers in first-use order
}

type serverStats struct {
	sent, replies, timeouts, errors int
	rcodes                          map[string]int // server-problem rcodes
	rtt                             histogram
}

// NewStats returns empty Stats.
func NewStats() *Stats {
	return &Stats{statuses: map[string]int{}, dnssec: map[string]int{}, servers: map[string]*serverStats{}}
}

// lookup records a Resolver.query: answered from the cache, merged into an
// identical query in flight, or sent.
func (s *Stats) lookup(hit, merged bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookups++
	if hit {
		s.cacheHits++
	}
	if merged {
		s.merged++
	}
}

// exchanged records one query to server (with its TCP/EDNS fallbacks) and
// how it ended. Queries cut short by cancellation are not counted.
func (s *Stats) exchanged(ctx context.Context, server string, rd bool, resp *response, err error) {
	if s == nil || err != nil && ctx.Err() != nil {
		return
	}
	if !rd {
		server = DirectServers
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.servers[server]
	if st == nil {
		st = &serverStats{rcodes: map[string]int{}}
		s.servers[server] = st
		s.order = append(s.order, server)
	}
	st.sent++
	switch {
	case err == nil:
		st.replies++
		st.rtt.add(resp.rtt)
		s.all.add(resp.rtt)
		if rc := resp.msg.Rcode; rc != dns.RcodeSuccess && rc != dns.RcodeNameError {
			st.rcodes[rcodeString(rc)]++
		}
	case isTimeout(err):
		st.timeouts++
	default:
		st.errors++
	}
}

// AddResult records the rows of one query (one input and type), before
// any filtering; failed reports whether it counts toward exit status 2.
func (s *Stats) AddResult(rows []Row, failed bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries++
	if failed {
		s.failed++
	}
	for _, r := range rows {
		s.statuses[r.Status]++
		if r.DNSSEC != "" {
			s.dnssec[r.DNSSEC]++
		}
	}
}

// Write prints the summary; elapsed is the run's duration and cache
// whether the response cache was on.
func (s *Stats) Write(w io.Writer, elapsed time.Duration, cache bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tw := tabwriter.NewWriter(w, 0, 0, 1, ' ', 0)
	fmt.Fprintf(tw, "stats:\n")
	line := fmt.Sprintf("%d in %s", s.queries, elapsed.Round(time.Millisecond))
	if secs := elapsed.Seconds(); secs > 0 {
		line += fmt.Sprintf(" (%.1f/s)", float64(s.queries)/secs)
	}
	fmt.Fprintf(tw, "  queries:\t%s, %d failed\n", line, s.failed)
	fmt.Fprintf(tw, "  rows:\t%s\n", byCount(s.statuses))
	if len(s.dnssec) > 0 {
		fmt.Fprintf(tw, "  dnssec:\t%s\n", byCount(s.dnssec))
	}
	if cache && s.lookups > 0 {
		fmt.Fprintf(tw, "  cache:\t%d hits of %d lookups (%.1f%%)", s.cacheHits, s.lookups, 100*float64(s.cacheHits)/float64(s.lookups))
		if s.merged > 0 {
			fmt.Fprintf(tw, "; %d merged with an identical query in flight", s.merged)
		}
		fmt.Fprintln(tw)
	} else if !cache {
		fmt.Fprintf(tw, "  cache:\toff")
		if s.merged > 0 {
			fmt.Fprintf(tw, "; %d of %d lookups merged with an identical query in flight", s.merged, s.lookups)
		}
		fmt.Fprintln(tw)
	}
	if s.all.n > 0 {
		fmt.Fprintf(tw, "  response time:\t%s (%d replies)\n", s.all.summary(), s.all.n)
	}
	for _, name := range s.order {
		st := s.servers[name]
		line := fmt.Sprintf("%d sent: %d replies, %d timeouts, %d errors", st.sent, st.replies, st.timeouts, st.errors)
		if len(st.rcodes) > 0 {
			line += "; " + byCount(st.rcodes)
		}
		if st.rtt.n > 0 {
			line += "; " + st.rtt.summary()
		}
		fmt.Fprintf(tw, "  %s:\t%s\n", name, line)
	}
	return tw.Flush()
}

// byCount renders counts as "A 3, B 1", largest first.
func byCount(m map[string]int) string {
	keys := slices.SortedFunc(maps.Keys(m), func(a, b string) int {
		return cmp.Or(cmp.Compare(m[b], m[a]), cmp.Compare(a, b))
	})
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", k, m[k])
	}
	return strings.Join(parts, ", ")
}

// histogram counts durations in buckets 5% wide from 1µs to about five
// minutes, so quantiles are within 5% using fixed memory.
type histogram struct {
	n      int
	max    time.Duration
	counts [histBuckets]int
}

const (
	histBuckets = 400
	histGrowth  = 1.05
	histMin     = time.Microsecond
)

func (h *histogram) add(d time.Duration) {
	h.n++
	h.max = max(h.max, d)
	i := 0
	if d > histMin {
		i = min(int(math.Log(float64(d)/float64(histMin))/math.Log(histGrowth))+1, histBuckets-1)
	}
	h.counts[i]++
}

// quantile returns the upper bound of the bucket holding the q quantile,
// at most the largest duration seen; the last bucket, which holds
// everything longer, gives the largest.
func (h *histogram) quantile(q float64) time.Duration {
	target := max(int(math.Ceil(q*float64(h.n))), 1)
	seen := 0
	for i, c := range h.counts {
		if seen += c; seen >= target && i < histBuckets-1 {
			return min(time.Duration(float64(histMin)*math.Pow(histGrowth, float64(i))), h.max)
		}
	}
	return h.max
}

func (h *histogram) summary() string {
	r := func(d time.Duration) time.Duration {
		if d >= 10*time.Millisecond {
			return d.Round(time.Millisecond)
		}
		return d.Round(10 * time.Microsecond)
	}
	return fmt.Sprintf("median %s, p95 %s, max %s", r(h.quantile(0.5)), r(h.quantile(0.95)), r(h.max))
}
