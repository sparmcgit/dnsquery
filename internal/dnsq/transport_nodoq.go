//go:build !doq

package dnsq

import (
	"crypto/tls"
	"errors"
)

// DoQAvailable reports whether this build includes DNS over QUIC. This
// build does not; build with -tags doq to add it (it pulls in quic-go,
// about 2 MB).
const DoQAvailable = false

func newDoQTransport(string, *tls.Config) (transport, error) {
	return nil, errors.New("DNS over QUIC is not included in this build")
}
