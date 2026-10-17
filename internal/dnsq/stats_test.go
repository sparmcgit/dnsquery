package dnsq

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestHistogramQuantiles(t *testing.T) {
	var h histogram
	for i := 1; i <= 1000; i++ {
		h.add(time.Duration(i) * time.Millisecond)
	}
	near := func(got, want time.Duration) bool {
		return got >= want && float64(got) <= float64(want)*histGrowth
	}
	if got := h.quantile(0.5); !near(got, 500*time.Millisecond) {
		t.Errorf("median %s, want 500ms (+5%%)", got)
	}
	if got := h.quantile(0.95); !near(got, 950*time.Millisecond) {
		t.Errorf("p95 %s, want 950ms (+5%%)", got)
	}
	if h.max != time.Second || h.quantile(1) != time.Second {
		t.Errorf("max %s, quantile(1) %s", h.max, h.quantile(1))
	}

	// Never above the largest value seen, and extremes stay in range.
	var one histogram
	one.add(1234 * time.Microsecond)
	if got := one.quantile(0.5); got != 1234*time.Microsecond {
		t.Errorf("single value: median %s", got)
	}
	var edge histogram
	edge.add(0)
	edge.add(time.Hour)
	if edge.quantile(0.5) > histMin || edge.quantile(1) != time.Hour {
		t.Errorf("edges: %s %s", edge.quantile(0.5), edge.quantile(1))
	}
}

func TestStatsCountsExchanges(t *testing.T) {
	servfail, silent, closed, good := rcodeServer(t, dns.RcodeServerFailure), silentServer(t), closedPort(t), startServer(t, zoneHandler)
	st := NewStats()
	r := &Resolver{Servers: []string{servfail, silent, closed, good}, Timeout: 100 * time.Millisecond,
		Cache: NewCache(10), Stats: st}
	ctx := context.Background()
	for range 2 {
		rows := r.Lookup(ctx, "www.example", dns.TypeA, false)
		st.AddResult(rows, false)
	}
	st.AddResult([]Row{{Status: StatusError}}, true)
	if _, err := r.exchangeOnce(ctx, good, "www.example.", dns.TypeA, false); err != nil {
		t.Fatal(err)
	}

	want := map[string]serverStats{
		servfail:      {sent: 1, replies: 1},
		silent:        {sent: 1, timeouts: 1},
		closed:        {sent: 1, errors: 1},
		good:          {sent: 1, replies: 1},
		DirectServers: {sent: 1, replies: 1},
	}
	for name, w := range want {
		got := st.servers[name]
		if got == nil || got.sent != w.sent || got.replies != w.replies || got.timeouts != w.timeouts || got.errors != w.errors || got.rtt.n != w.replies {
			t.Errorf("%s: %+v, want %+v", name, got, w)
		}
	}
	if st.servers[servfail].rcodes["SERVFAIL"] != 1 || len(st.servers[good].rcodes) != 0 {
		t.Errorf("rcodes: servfail %v, good %v", st.servers[servfail].rcodes, st.servers[good].rcodes)
	}
	if st.lookups != 2 || st.cacheHits != 1 || st.queries != 3 || st.failed != 1 || st.statuses[StatusNoError] != 2 || st.all.n != 3 {
		t.Errorf("lookups %d hits %d queries %d failed %d statuses %v replies %d", st.lookups, st.cacheHits, st.queries, st.failed, st.statuses, st.all.n)
	}

	var out strings.Builder
	if err := st.Write(&out, 2*time.Second, true); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"3 in 2s (1.5/s), 1 failed",
		"rows:",
		"NOERROR 2, ERROR 1",
		"1 hits of 2 lookups (50.0%)",
		servfail + ":",
		"1 sent: 1 replies, 0 timeouts, 0 errors; SERVFAIL 1; median",
		"1 sent: 0 replies, 1 timeouts, 0 errors\n",
		DirectServers + ":",
	} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("summary missing %q:\n%s", s, out.String())
		}
	}
	if i, j := strings.Index(out.String(), servfail+":"), strings.Index(out.String(), good+":"); i > j {
		t.Errorf("servers not in first-use order:\n%s", out.String())
	}

	out.Reset()
	if err := st.Write(&out, 0, false); err != nil || !strings.Contains(out.String(), "cache:") || !strings.Contains(out.String(), "off") {
		t.Errorf("cache off: %v\n%s", err, out.String())
	}
}

func TestStatsIgnoresCancelledQueries(t *testing.T) {
	st := NewStats()
	r := &Resolver{Servers: []string{silentServer(t)}, Timeout: time.Second, Stats: st}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r.Lookup(ctx, "www.example", dns.TypeA, false)
	if len(st.servers) != 0 {
		t.Errorf("cancelled query counted: %v", st.order)
	}
	var nilStats *Stats
	nilStats.AddResult([]Row{{}}, true) // must not panic
}
