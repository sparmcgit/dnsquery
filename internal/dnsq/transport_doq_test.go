//go:build doq

package dnsq

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"testing"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func init() { startDoQ = startDoQServer }

// startDoQServer serves DNS over QUIC on loopback.
func startDoQServer(t testing.TB, cert tls.Certificate, log *queryLog) string {
	t.Helper()
	conf := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"doq"}}
	l, err := quic.ListenAddr("127.0.0.1:0", conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept(context.Background())
			if err != nil {
				return
			}
			log.conns.Add(1)
			go func() {
				for {
					s, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go serveDoQStream(s, log)
				}
			}()
		}
	}()
	return l.Addr().String()
}

func serveDoQStream(s *quic.Stream, log *queryLog) {
	defer func() { _ = s.Close() }()
	// The client closes its side after the query (RFC 9250 section 4.2),
	// so the whole stream can be read.
	b, err := io.ReadAll(s)
	if err != nil || len(b) < 2 || int(binary.BigEndian.Uint16(b)) != len(b)-2 {
		s.CancelWrite(0x2) // DOQ_PROTOCOL_ERROR
		return
	}
	req := new(dns.Msg)
	if req.Unpack(b[2:]) != nil {
		s.CancelWrite(0x2)
		return
	}
	wire, _ := log.answer(req, len(b)-2).Pack()
	_, _ = s.Write(binary.BigEndian.AppendUint16(nil, uint16(len(wire))))
	_, _ = s.Write(wire)
}
