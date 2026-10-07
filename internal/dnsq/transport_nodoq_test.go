//go:build !doq

package dnsq

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDoQLeftOut(t *testing.T) {
	if _, err := newDoQTransport("192.0.2.1:853", &tls.Config{}); err == nil {
		t.Error("the DoQ transport must fail in this build")
	}
	// A server string that bypassed ParseServer still fails cleanly.
	r := &Resolver{Servers: []string{"quic://192.0.2.1:853"}, Timeout: 100 * time.Millisecond}
	if got := r.Lookup(context.Background(), "www.example", dns.TypeA, false)[0]; got.Status != StatusError || !strings.Contains(got.Error, "not included") {
		t.Errorf("status %s, error %q", got.Status, got.Error)
	}
}
