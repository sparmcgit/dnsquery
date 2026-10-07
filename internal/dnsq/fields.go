package dnsq

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Field is a selectable output column.
type Field struct {
	Name        string
	Description string
	get         func(Row) any
}

// Fields lists every output field in default display order.
var Fields = []Field{
	{"query", "input as given", func(r Row) any { return r.Query }},
	{"qtype", "queried record type", func(r Row) any { return r.QType }},
	{"status", "NOERROR, NODATA, NXDOMAIN, SERVFAIL, REFUSED, ... or ERROR", func(r Row) any { return r.Status }},
	{"name", "owner name of the record (or the queried name)", func(r Row) any { return r.Name }},
	{"name_unicode", "name with internationalized (xn--) labels shown in Unicode", func(r Row) any { return unicodeName(r.Name) }},
	{"type", "record type", func(r Row) any { return r.Type }},
	{"ttl", "record TTL, or negative-caching TTL (RFC 2308)", func(r Row) any {
		if !r.HasTTL {
			return nil
		}
		return r.TTL
	}},
	{"value", "record data", func(r Row) any { return r.Value }},
	{"zone", "zone apex from an SOA record, when known", func(r Row) any { return r.Zone }},
	{"ns", "nameserver host, with --check-nameservers", func(r Row) any { return r.NS }},
	{"serial", "SOA serial, from SOA answers and --check-nameservers", func(r Row) any {
		if !r.HasSerial {
			return nil
		}
		return r.Serial
	}},
	{"check", "problem found by --check-nameservers or --compare-servers; empty when fine", func(r Row) any { return r.Check }},
	{"server", "resolver that answered (all servers tried, on ERROR)", func(r Row) any { return r.Server }},
	{"protocol", "transport of the final response (udp, tcp, tls, https or quic)", func(r Row) any { return r.Protocol }},
	{"rtt_ms", "round-trip time in milliseconds; empty when no reply was received", func(r Row) any {
		if !r.Replied {
			return nil
		}
		return math.Round(float64(r.RTT.Microseconds())/10) / 100
	}},
	{"authoritative", "AA flag of the response; empty when no reply was received", func(r Row) any {
		if !r.Replied {
			return nil
		}
		return r.Authoritative
	}},
	{"error", "error message for failed queries", func(r Row) any { return r.Error }},
	{"cached", "answered from this run's cache", func(r Row) any { return r.Cached }},
	{"ede", "extended DNS error the server gave, such as 15 Blocked (RFC 8914)", func(r Row) any { return r.EDE }},
	{"nsid", "identifier of the server that answered, with --nsid (RFC 5001)", func(r Row) any { return r.NSID }},
	{"ecs", "client subnet the server says its answer is for, with --ecs (RFC 7871); empty if it ignored the subnet", func(r Row) any { return r.ECS }},
	{"dnssec", "DNSSEC status with --dnssec: secure, insecure or bogus", func(r Row) any { return r.DNSSEC }},
	{"dnssec_reason", "why the DNSSEC status is not secure", func(r Row) any { return r.DNSSECReason }},
	{"explanation", "plain-language explanation (with --explain)", func(r Row) any { return r.Explanation }},
}

var defaultFields = []string{"query", "status", "name", "type", "ttl", "value"}

func lookupField(name string) (Field, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, f := range Fields {
		if f.Name == n {
			return f, nil
		}
	}
	return Field{}, fmt.Errorf("unknown field %q (see --list-fields, or use %q)", name, AllFields)
}

// AllFields is the --select-fields name that expands to every field.
const AllFields = "all"

// FieldOptions shapes the field selection when --select-fields is not
// given.
type FieldOptions struct {
	Defaults []string // default selection; nil means the standard one
	DNSSEC   bool     // --dnssec: add the dnssec field to the defaults
	NSID     bool     // --nsid: add the nsid field to the defaults
	ECS      bool     // --ecs: add the ecs field to the defaults
	Explain  bool     // --explain: append explanation, even to explicit names
}

// SelectFields resolves the requested field names, falling back to the
// defaults adjusted by opts. "all" expands to every field in Fields order,
// and may be mixed with other names; duplicates keep their first position.
// Explicit names are used as given, except that opts.Explain still appends
// the explanation field.
func SelectFields(names []string, opts FieldOptions) ([]Field, error) {
	if len(names) == 0 {
		names = append([]string{}, defaultFields...)
		if opts.Defaults != nil {
			names = append([]string{}, opts.Defaults...)
		}
		if opts.DNSSEC {
			names = append(names, "dnssec")
		}
		if opts.NSID {
			names = append(names, "nsid")
		}
		if opts.ECS {
			names = append(names, "ecs")
		}
	}
	var out []Field
	seen := map[string]bool{}
	add := func(f Field) {
		if !seen[f.Name] {
			seen[f.Name] = true
			out = append(out, f)
		}
	}
	for _, n := range names {
		if strings.EqualFold(strings.TrimSpace(n), AllFields) {
			for _, f := range Fields {
				add(f)
			}
			continue
		}
		f, err := lookupField(n)
		if err != nil {
			return nil, err
		}
		add(f)
	}
	if opts.Explain && !seen["explanation"] {
		f, _ := lookupField("explanation")
		out = append(out, f)
	}
	return out, nil
}

func (f Field) String(r Row) string { return formatValue(f.get(r)) }

func formatValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return fmt.Sprint(x)
	}
}
