package dnsq

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// CompareFields is the default field selection for --compare-servers.
var CompareFields = []string{"query", "qtype", "server", "status", "value", "check"}

// CompareServers asks every server for input/qtype at once, instead of
// failing over, and returns one row per server, in server order. The value
// is the server's whole answer (sorted, without TTLs) so answers compare
// directly. The check field flags servers whose answer differs from most
// others, all servers when there is no majority, and servers that give no
// usable reply. The cache is bypassed: each server is asked itself.
func (r *Resolver) CompareServers(ctx context.Context, input string, qtype uint16) []Row {
	ctx = withTraceLabel(ctx, input)
	base := Row{Query: input, QType: typeString(qtype), Type: typeString(qtype)}
	name, err := Normalize(input, qtype)
	if err != nil {
		base.Name, base.Status, base.Error = input, StatusError, err.Error()
		base.Check = err.Error()
		return []Row{base}
	}
	base.Name = name
	rows := make([]Row, len(r.Servers))
	var wg sync.WaitGroup
	for i, server := range r.Servers {
		wg.Go(func() {
			row := base
			row.Server = server
			resp, err := r.askServer(ctx, server, name, qtype)
			if err != nil {
				row.Status, row.Error, row.Check = StatusError, err.Error(), "no usable reply: "+err.Error()
				rows[i] = row
				return
			}
			m := resp.msg
			row.Protocol, row.RTT, row.Replied, row.Authoritative = resp.protocol, resp.rtt, true, m.Authoritative
			row.EDE, row.NSID, row.ECS = extendedErrors(m), serverID(m), clientSubnet(m)
			row.Status = classify(m, qtype)
			row.Value = answerSummary(m)
			rows[i] = row
		})
	}
	wg.Wait()
	markDifferences(rows)
	return rows
}

// askServer sends one recursive query to server, without cache or
// failover; timeouts are retried up to r.Retries times.
func (r *Resolver) askServer(ctx context.Context, server, name string, qtype uint16) (*response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := r.exchangeOnce(ctx, server, name, qtype, true)
		if err == nil || ctx.Err() != nil || !isTimeout(err) || attempt >= r.Retries {
			return resp, err
		}
		r.Trace.printf(ctx, "%s timed out after %s; retry %d of %d follows", server, r.Timeout, attempt+1, r.Retries)
	}
}

// markDifferences sets the check field of rows whose answer (status and
// value) differs from the strict majority of the servers that replied, or
// of every replying row when no answer has a strict majority.
func markDifferences(rows []Row) {
	counts := map[string]int{}
	replied := 0
	for _, r := range rows {
		if r.Check == "" {
			counts[r.Status+" "+r.Value]++
			replied++
		}
	}
	if len(counts) < 2 {
		return
	}
	best, n := majority(counts)
	for i := range rows {
		r := &rows[i]
		switch {
		case r.Check != "":
		case 2*n <= replied:
			r.Check = fmt.Sprintf("servers disagree: %d different answers from %d servers, none from a majority", len(counts), replied)
		case r.Status+" "+r.Value != best:
			r.Check = fmt.Sprintf("answer differs from %d of %d servers", n, replied)
		}
	}
}

// ParseECS reads an --ecs value: a subnet such as 192.0.2.0/24 or
// 2001:db8::/56, or a bare address, which is shortened to the prefix
// lengths RFC 7871 section 11.1 recommends (/24 and /56). "0.0.0.0/0" or
// "::/0" asks resolvers not to send any client subnet (section 7.1.2).
func ParseECS(s string) (*dns.EDNS0_SUBNET, error) {
	s = strings.TrimSpace(s)
	var ip net.IP
	var bits int
	if strings.Contains(s, "/") {
		addr, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid --ecs %q: %v", s, err)
		}
		ip = addr
		bits, _ = n.Mask.Size()
	} else if ip = net.ParseIP(s); ip == nil {
		return nil, fmt.Errorf("invalid --ecs %q: want a subnet such as 192.0.2.0/24 or an address", s)
	}
	e := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET}
	if v4 := ip.To4(); v4 != nil {
		e.Family = 1
		if !strings.Contains(s, "/") {
			bits = 24
		}
		e.Address = v4.Mask(net.CIDRMask(bits, 32))
	} else {
		e.Family = 2
		if !strings.Contains(s, "/") {
			bits = 56
		}
		e.Address = ip.Mask(net.CIDRMask(bits, 128))
	}
	// Bits beyond the prefix must be zero (RFC 7871 section 6).
	e.SourceNetmask = uint8(bits)
	return e, nil
}

// clientSubnet renders the ECS option of a response (RFC 7871) as
// "subnet scope /n": the scope says which clients the answer is for. It
// is empty when the server returned no ECS option, which usually means
// it ignored the one we sent.
func clientSubnet(m *dns.Msg) string {
	opt := m.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_SUBNET); ok {
			return fmt.Sprintf("%s/%d scope /%d", e.Address, e.SourceNetmask, e.SourceScope)
		}
	}
	return ""
}
