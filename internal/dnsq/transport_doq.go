//go:build doq

package dnsq

import (
	"context"
	"crypto/tls"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// DoQAvailable reports whether this build includes DNS over QUIC; it is
// built with -tags doq.
const DoQAvailable = true

func init() {
	// quic-go logs to stderr when the OS caps its UDP receive buffer
	// below what bulk transfers want; DNS queries do not need it.
	if os.Getenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING") == "" {
		_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	}
}

func newDoQTransport(addr string, conf *tls.Config) (transport, error) {
	return &doqTransport{addr: addr, conf: conf}, nil
}

// doqTransport is DNS over QUIC (RFC 9250): one shared connection per
// server, one stream per query.
type doqTransport struct {
	addr string
	conf *tls.Config

	mu   sync.Mutex
	conn *quic.Conn
}

// DoQ error codes, RFC 9250 section 4.3.
const (
	doqNoError          = 0x0
	doqRequestCancelled = 0x3
)

func (t *doqTransport) exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	for attempt := 0; ; attempt++ {
		conn, reused, err := t.connect(ctx)
		if err != nil {
			return nil, ctxErr(ctx, err)
		}
		resp, err := t.query(ctx, conn, m)
		// A connection the server closed while idle fails on its next
		// stream: drop it and try once more on a new one.
		if err != nil && reused && attempt == 0 && ctx.Err() == nil && conn.Context().Err() != nil {
			t.drop(conn)
			continue
		}
		return resp, err
	}
}

func (t *doqTransport) query(ctx context.Context, conn *quic.Conn, m *dns.Msg) (*dns.Msg, error) {
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, ctxErr(ctx, err)
	}
	resp, err := exchangeStream(ctx, streamWriteClose{s}, s.SetDeadline, m)
	if err != nil {
		s.CancelRead(doqRequestCancelled)
		s.CancelWrite(doqRequestCancelled)
	}
	return resp, err
}

// streamWriteClose closes the sending side after the query, which RFC 9250
// section 4.2 requires (STREAM FIN).
type streamWriteClose struct{ s *quic.Stream }

func (w streamWriteClose) Write(p []byte) (int, error) {
	n, err := w.s.Write(p)
	if err == nil {
		err = w.s.Close()
	}
	return n, err
}

func (w streamWriteClose) Read(p []byte) (int, error) { return w.s.Read(p) }

func (t *doqTransport) connect(ctx context.Context) (*quic.Conn, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil && t.conn.Context().Err() == nil {
		return t.conn, true, nil
	}
	conn, err := quic.DialAddr(ctx, t.addr, t.conf, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		return nil, false, err
	}
	t.conn = conn
	return conn, false, nil
}

func (t *doqTransport) drop(conn *quic.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn == conn {
		t.conn = nil
	}
	_ = conn.CloseWithError(doqNoError, "")
}

func (t *doqTransport) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		_ = t.conn.CloseWithError(doqNoError, "")
		t.conn = nil
	}
}
