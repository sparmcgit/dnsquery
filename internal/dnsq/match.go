package dnsq

import (
	"fmt"
	"strings"
)

// Matcher filters rows by field match expressions. Each expression is one or
// more field=value clauses joined by &&; a value may list alternatives
// separated by |. Values match case-insensitively as substrings. A row must
// satisfy every expression.
type Matcher struct {
	exprs [][]clause
}

type clause struct {
	field Field
	alts  []string
}

// ParseMatch parses match expressions such as "status=NOERROR&&value=mx|mail".
func ParseMatch(exprs []string) (*Matcher, error) {
	m := &Matcher{}
	for _, e := range exprs {
		var clauses []clause
		for part := range strings.SplitSeq(e, "&&") {
			name, value, ok := strings.Cut(part, "=")
			if !ok {
				return nil, fmt.Errorf("invalid match expression %q: want field=value", part)
			}
			f, err := lookupField(name)
			if err != nil {
				return nil, err
			}
			var alts []string
			for a := range strings.SplitSeq(value, "|") {
				alts = append(alts, strings.ToLower(strings.TrimSpace(a)))
			}
			clauses = append(clauses, clause{field: f, alts: alts})
		}
		m.exprs = append(m.exprs, clauses)
	}
	return m, nil
}

// Match reports whether r satisfies all expressions.
func (m *Matcher) Match(r Row) bool {
	for _, clauses := range m.exprs {
		for _, c := range clauses {
			if !c.match(r) {
				return false
			}
		}
	}
	return true
}

func (c clause) match(r Row) bool {
	v := strings.ToLower(c.field.String(r))
	for _, a := range c.alts {
		if strings.Contains(v, a) {
			return true
		}
	}
	return false
}
