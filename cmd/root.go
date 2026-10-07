package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "dnsquery [domain ...]",
	Short: "Query DNS records for domains from args, files, or stdin",
	Long: `dnsquery queries DNS records for domains from args, files, or stdin.
Internationalized names such as räksmörgås.se are converted to their
xn-- form (IDNA 2008).

It is a stub client that talks to recursive resolvers and tracks
standards-aligned DNS response handling rather than implementing a full
iterative resolver itself.

The current behavior is aligned with core DNS semantics and related
extensions such as RFC 1034, RFC 1035, RFC 1123, RFC 2308, RFC 6891, and
RFC 7766.

Servers from --server (default: every nameserver in /etc/resolv.conf) are
tried in order. A server that times out or is unreachable, or answers
SERVFAIL, REFUSED or NOTIMP, is followed by the next one; only servers
that timed out are retried, up to --retries times.

A server written as tls://host[#tls-name], https://host/path[#tls-name]
or quic://host[#tls-name] is queried over DNS over TLS (RFC 7858), HTTPS
(RFC 8484) or QUIC (RFC 9250). Certificates are always checked against
host, or tls-name when given; with an IP address as host and #tls-name,
no name lookup is needed (https://8.8.8.8/dns-query#dns.google).
Connections are reused and queries padded (RFC 8467). For private
certificates, --tls-ca adds CA certificates to trust; --tls-insecure
skips the certificate check altogether. DNS over QUIC is
only included in builds made with -tags doq (TAGS=doq ./compile).

--dnssec validates answers locally from the IANA root trust anchor and
reports each RRset as secure, insecure or bogus.

Responses are cached in memory for the run only, so a domain listed twice
or a repeated DNSSEC lookup is not asked again. Answers expire with their
TTL, "does not exist" answers with their SOA-based TTL (RFC 2308), and
failures after 30 seconds (RFC 9520). --cache-size 0 turns the cache
off; the README explains what that departs from. Your resolver's own
cache is separate and unaffected.

--rate caps the queries per second sent (default 15), counting every
retry, failover and fallback, so a large run does not trip a resolver's
rate limiting. --concurrency only caps how many queries wait for a reply
at once; it does not limit speed.

Results are written as they complete, in input order, so memory use stays
flat however many domains are queried. Text output aligns columns in
blocks of 1000 rows. Excel output is limited to 1048575 rows and is only
included in builds made with -tags excel (TAGS=excel ./compile).

--check-nameservers asks each authoritative nameserver of the zone
directly and reports lame servers and differing serials or answers. It
uses the nameservers' IPv4 addresses; --ipv6 adds their IPv6 addresses.
--compare-servers asks every --server for each query, instead of
failing over, and flags servers whose answer differs from the others.
--ecs sends a client subnet (RFC 7871) to see what clients there get.
--dns-posture looks up each domain's MX, SPF, DMARC, DKIM, NS and CAA
records, falling back to the organizational domain (www.example.com ->
example.com), and flags missing ones in the check field.
Extended DNS Errors (RFC 8914) are shown in the ede field; --nsid asks
servers to identify themselves (RFC 5001).

--verbose prints the configuration; --trace prints every query, response
and DNSSEC step on stderr, for troubleshooting. A UDP answer that cannot
be read, typically one larger than requested without the TC flag, is
retried over TCP automatically.

Exit status is 0 on success, 1 on usage or configuration errors, and 2
when one or more queries failed with status ERROR (invalid name or no
usable response), were bogus with --dnssec, found nameserver problems
with --check-nameservers, or got differing or missing answers with
--compare-servers. DNS answers such as
NXDOMAIN or SERVFAIL are results, not failures.`,
	Example: `  dnsquery example.com
  dnsquery example.com --type MX
  dnsquery example.com --type A,AAAA,MX
  dnsquery --file domains.txt
  dnsquery example.com --server tls://1.1.1.1
  dnsquery example.com --server https://cloudflare-dns.com/dns-query
  printf "example.com\nexample.org\n" | dnsquery --type A`,
	Args:          cobra.ArbitraryArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runQuery,
}

func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCode(err))
	}
}

// exitCode maps an Execute error to the process exit status.
func exitCode(err error) int {
	var qf *queryFailuresError
	if errors.As(err, &qf) {
		return 2
	}
	return 1
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (optional)")
	_ = viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	addQueryFlags(rootCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName(".dnsquery")
		viper.AddConfigPath("$HOME")
	}
	// DNSQUERY_TYPE, DNSQUERY_TRY_TO_RESOLVE, ...
	viper.SetEnvPrefix("DNSQUERY")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
