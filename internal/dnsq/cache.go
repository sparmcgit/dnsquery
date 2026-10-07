package dnsq

import (
	"container/list"
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// failureTTL is how long a failed lookup (timeout, SERVFAIL, REFUSED, ...)
// is cached. RFC 9520 requires resolution failures to be cached for at
// least 1 second and at most 5 minutes.
const failureTTL = 30 * time.Second

// lru is a size-bounded, expiring least-recently-used map. A nil *lru is a
// valid, always-empty cache.
type lru[V any] struct {
	mu    sync.Mutex
	max   int
	ll    *list.List
	items map[string]*list.Element
}

type lruEntry[V any] struct {
	key     string
	val     V
	expires time.Time
}

func newLRU[V any](max int) *lru[V] {
	if max <= 0 {
		return nil
	}
	return &lru[V]{max: max, ll: list.New(), items: map[string]*list.Element{}}
}

func (l *lru[V]) get(key string, now time.Time) (V, bool) {
	var zero V
	if l == nil {
		return zero, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.items[key]
	if !ok {
		return zero, false
	}
	e := el.Value.(*lruEntry[V])
	if !now.Before(e.expires) {
		l.ll.Remove(el)
		delete(l.items, key)
		return zero, false
	}
	l.ll.MoveToFront(el)
	return e.val, true
}

func (l *lru[V]) put(key string, val V, expires time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[key]; ok {
		e := el.Value.(*lruEntry[V])
		e.val, e.expires = val, expires
		l.ll.MoveToFront(el)
		return
	}
	l.items[key] = l.ll.PushFront(&lruEntry[V]{key: key, val: val, expires: expires})
	if l.ll.Len() > l.max {
		oldest := l.ll.Back()
		l.ll.Remove(oldest)
		delete(l.items, oldest.Value.(*lruEntry[V]).key)
	}
}

// Cache holds responses for the duration of one run, keyed by query name
// and type. Entries live for the response's TTL (RFC 1035), negative
// answers for their RFC 2308 TTL, and failures for failureTTL (RFC 9520).
// Its size is bounded, so memory stays flat on large inputs. A nil *Cache
// caches nothing.
type Cache struct {
	entries *lru[cacheEntry]
	now     func() time.Time
}

type cacheEntry struct {
	resp   *response
	err    error
	stored time.Time
}

// NewCache returns a cache holding up to size responses, or nil (no
// caching) when size is not positive.
func NewCache(size int) *Cache {
	if size <= 0 {
		return nil
	}
	return &Cache{entries: newLRU[cacheEntry](size), now: time.Now}
}

// get returns a cached response with TTLs reduced by the time it has spent
// in the cache, or the cached error.
func (c *Cache) get(key string) (*response, error, bool) {
	if c == nil {
		return nil, nil, false
	}
	now := c.now()
	e, ok := c.entries.get(key, now)
	if !ok {
		return nil, nil, false
	}
	if e.err != nil {
		return nil, e.err, true
	}
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	m := e.resp.msg.Copy()
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			if h := rr.Header(); h.Rrtype != dns.TypeOPT {
				h.Ttl -= min(h.Ttl, elapsed)
			}
		}
	}
	return &response{msg: m, server: e.resp.server, protocol: e.resp.protocol, cached: true}, nil, true
}

func (c *Cache) put(key string, resp *response, err error) {
	if c == nil {
		return
	}
	if ttl := cacheTTL(resp, err); ttl > 0 {
		now := c.now()
		c.entries.put(key, cacheEntry{resp: resp, err: err, stored: now}, now.Add(ttl))
	}
}

// cacheTTL is how long a response may be cached: the smallest TTL in its
// answer and authority sections, with SOA records limited to their MINIMUM
// field (RFC 2308 section 5). Negative answers without an SOA are not
// cached (RFC 2308 section 5), nor are cancelled queries.
func cacheTTL(resp *response, err error) time.Duration {
	switch {
	case errors.Is(err, context.Canceled):
		return 0
	case err != nil:
		return failureTTL
	case tryNextServer(resp.msg.Rcode) || resp.msg.Rcode == dns.RcodeFormatError:
		return failureTTL
	}
	ttl, found := uint32(math.MaxUint32), false
	for _, section := range [][]dns.RR{resp.msg.Answer, resp.msg.Ns} {
		for _, rr := range section {
			t := rr.Header().Ttl
			if soa, ok := rr.(*dns.SOA); ok {
				t = min(t, soa.Minttl)
			}
			ttl, found = min(ttl, t), true
		}
	}
	if !found {
		return 0
	}
	return time.Duration(ttl) * time.Second
}
