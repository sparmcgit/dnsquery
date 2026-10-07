# dnsquery

A DNS stub client that queries record types for many domains at once —
from arguments, a file, or stdin — and writes the results as text, YAML,
JSON, CSV or (optionally) Excel.

It sends recursive queries to your resolvers (it is not an iterative
resolver) and follows standards-aligned response handling: EDNS(0), TCP
fallback on truncation, NXDOMAIN vs. NODATA with negative-caching TTLs,
failover across redundant nameservers, a per-run cache, optional local
DNSSEC validation from the root trust anchor, and encrypted transports
(DNS over TLS, HTTPS and QUIC).

```
$ dnsquery example.com
QUERY        STATUS   NAME          TYPE  TTL  VALUE
example.com  NOERROR  example.com.  A     300  172.66.147.243
example.com  NOERROR  example.com.  A     300  104.20.23.154
```

## Build

Requires Go 1.26+.

```bash
./compile
```

`./compile` runs `go mod tidy`, `govulncheck`, and builds a static
`dnsquery` binary for linux/amd64.

Excel output and DNS over QUIC are optional, because the libraries behind
them (excelize and quic-go) make the binary much larger:

| Build | Command | Size |
|-------|---------|------|
| Default | `./compile` | 8.8 MB |
| With Excel output | `TAGS=excel ./compile` (or `go build -tags excel`) | 16.7 MB |
| With DNS over QUIC | `TAGS=doq ./compile` | 10.1 MB |
| With both | `TAGS=excel,doq ./compile` | 18.5 MB |

Without them, `--output excel` or a `.xlsx` path, or a `quic://` server,
fails at once, before any query is sent, with a hint to rebuild. DNS over
TLS and HTTPS are always included.

## Usage

```bash
dnsquery example.com
dnsquery example.com --type MX
dnsquery example.com example.org --type A,AAAA,MX   # each domain, each type
dnsquery --file domains.txt
printf "example.com\nexample.org\n" | dnsquery --type A
dnsquery 192.0.2.1 --type PTR                   # IPs are reversed for PTR
dnsquery example.com --server 1.1.1.1,9.9.9.9   # tried in order
dnsquery example.com --server tls://1.1.1.1     # DNS over TLS
dnsquery example.com --server https://cloudflare-dns.com/dns-query   # DNS over HTTPS
dnsquery example.com --server quic://dns.adguard-dns.com             # DNS over QUIC
```

| Command      | Description                                    |
|--------------|------------------------------------------------|
| *(none)*     | Query the given domains                        |
| `version`    | Print the version                              |
| `author`     | Print the author                               |
| `completion` | Generate a shell completion script             |

### Input

- Domains given as arguments are used on their own, unless `--file` is
  also set explicitly, in which case both are queried.
- With no arguments, domains are read from `--file` (default `-`, stdin).
  If stdin is an interactive terminal, the help is shown instead.
- In files, blank lines and lines starting with `#` are skipped, and only
  the first word of each line is used.
- Internationalized names work as typed: `räksmörgås.se` is queried as
  `xn--rksmrgs-5wao1o.se` (IDNA 2008 lookup rules with UTS #46 mapping, as
  browsers use). Only labels with non-ASCII characters are converted, so
  names like `_dmarc.räksmörgås.se` keep their underscore labels. The
  `name_unicode` field shows the answer's owner name back in Unicode.

### Flags

| Flag                 | Default          | Description |
|----------------------|------------------|-------------|
| `--type`             | `A`              | Record types, comma-separated (A, AAAA, MX, NS, TXT, SOA, PTR, …, or `TYPEnnn`); each domain is queried for each type, and its rows come out grouped, types in the order given |
| `--server`           | `/etc/resolv.conf` | Server `ip[:port]`, `tls://…`, `https://…` or `quic://…` (see [Encrypted DNS](#encrypted-dns-dot-doh-doq)), repeatable or comma-separated, tried in order |
| `--timeout`          | `3s`             | Timeout per attempt |
| `--retries`          | `2`              | Extra rounds for servers that timed out |
| `--tcp`              | `false`          | Use TCP instead of UDP for plain DNS servers |
| `--tls-ca`           |                  | PEM file with extra CA certificates to trust for encrypted servers, in addition to the system's |
| `--tls-insecure`     | `false`          | Do not check certificates of `tls://`, `https://` and `quic://` servers (private or self-signed certificates) |
| `--rate`             | `15`             | Maximum queries per second sent, counting retries and failover (`0` = unlimited) |
| `--concurrency`      | `50`             | Maximum queries waiting for a reply at once |
| `--cache-size`       | `10000`          | Maximum responses cached during a run (`0` disables caching) |
| `--dnssec`           | `false`          | Validate answers with DNSSEC from the root trust anchor |
| `--trust-anchor`     | built-in         | File with root trust anchor DS or DNSKEY records |
| `--file`             | `-`              | Input file (`-` for stdin) |
| `--output`           | `text`           | `text`, `yaml`, `json`, `csv`, `excel`, or a file path ending in `.txt`, `.yaml`/`.yml`, `.json`, `.csv`, `.xlsx` (Excel needs a `-tags excel` build) |
| `--select-fields`    | see below        | Output fields, repeatable or comma-separated; `all` selects every field |
| `--match-fields`     |                  | Row filter expressions (see below) |
| `--list-fields`      |                  | List output fields and exit |
| `--explain`          | `false`          | Add a plain-language explanation column |
| `--try-to-resolve`   | `false`          | SOA only: on NODATA, walk up parent names until an SOA is found |
| `--is-authoritative` |                  | SOA only: keep rows whose SOA MNAME is one of these servers |
| `--progress`         | `false`          | Show a running count on stderr |
| `--verbose`          | `false`          | Print the running configuration on stderr |
| `--trace`            | `false`          | Print every query, response and DNSSEC step on stderr (see Troubleshooting) |
| `--nsid`             | `false`          | Ask each server to identify itself (NSID, RFC 5001) and add the `nsid` column |
| `--check-nameservers` | `false`         | Ask each authoritative nameserver of the zone directly and report problems (see below) |
| `--dns-posture`      | `false`          | Look up each domain's MX, SPF, DMARC, DKIM, NS and CAA records, with organizational-domain fallback, and flag missing ones (see below) |
| `--ipv6`             | `false`          | With `--check-nameservers`, also query the nameservers' IPv6 addresses (default: IPv4 only) |
| `--compare-servers`  | `false`          | Ask every `--server` for each query instead of failing over, and flag differing answers (see below) |
| `--ecs`              |                  | Send this client subnet with every query (EDNS Client Subnet, RFC 7871), e.g. `192.0.2.0/24` |
| `--config`           |                  | Config file (default `$HOME/.dnsquery.yaml` if present) |
| `--config-example`   |                  | Print an example config file with every setting and its default, and exit |

## Output

### Fields

`dnsquery --list-fields` lists them:

| Field           | Description |
|-----------------|-------------|
| `query`         | Input as given |
| `qtype`         | Queried record type |
| `status`        | `NOERROR`, `NODATA`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`, … or `ERROR` |
| `name`          | Owner name of the record (or the queried name) |
| `name_unicode`  | `name` with internationalized (`xn--`) labels shown in Unicode |
| `type`          | Record type |
| `ttl`           | Record TTL, or negative-caching TTL (RFC 2308) |
| `value`         | Record data |
| `zone`          | Zone apex from an SOA record, when known |
| `ns`            | Nameserver host, with `--check-nameservers` |
| `serial`        | SOA serial, from SOA answers and `--check-nameservers` |
| `check`         | Problem found by `--check-nameservers`, `--compare-servers` or `--dns-posture`; empty when fine |
| `server`        | Resolver that answered (all servers tried, on `ERROR`) |
| `protocol`      | Transport of the final response (`udp`, `tcp`, `tls`, `https` or `quic`) |
| `rtt_ms`        | Round-trip time in milliseconds; empty when no reply was received |
| `authoritative` | AA flag of the response; empty when no reply was received |
| `error`         | Error message for failed queries |
| `cached`        | Answered from this run's cache |
| `ede`           | Extended DNS Error the server gave, such as `15 Blocked` (RFC 8914) |
| `nsid`          | Identifier of the server that answered, with `--nsid` (RFC 5001) |
| `ecs`           | Client subnet the server says its answer is for, with `--ecs` (RFC 7871); empty if it ignored the subnet |
| `dnssec`        | DNSSEC status with `--dnssec`: `secure`, `insecure` or `bogus` |
| `dnssec_reason` | Why the DNSSEC status is not `secure` |
| `explanation`   | Plain-language explanation (with `--explain`) |

The default selection is `query,status,name,type,ttl,value`; `--dnssec`
adds `dnssec`, `--nsid` adds `nsid` and `--explain` appends `explanation`.
With `--select-fields` you get exactly the fields you list (plus
`explanation` when `--explain` is set). There is one row per answer record, or a single
row for a negative or failed response.

`--select-fields all` selects every field, in the order listed above. It
can be mixed with other names: `--select-fields query,status,all` puts
those two first and the rest after, without repeating them. The
`explanation` and `dnssec` columns stay empty unless `--explain` and
`--dnssec` are set.

`NODATA` means the name exists but has no records of the queried type;
`ERROR` means there was no usable response at all (or the name was
invalid). Both are distinguished from `NXDOMAIN`, which is a definite
"this name does not exist".

### Filtering

`--match-fields` takes `field=value` expressions. Values match as
case-insensitive substrings; `|` separates alternatives for one field and
`&&` joins conditions. A row must satisfy every expression.

```bash
dnsquery --file domains.txt --type MX --match-fields 'status=NOERROR&&value=google|outlook'
dnsquery --file domains.txt --match-fields status=NXDOMAIN,query=.se
```

### Explanations

```
$ dnsquery gmail.com --type MX --select-fields name,value --explain
NAME        VALUE                                EXPLANATION
gmail.com.  20 alt2.gmail-smtp-in.l.google.com.  Mail for gmail.com is delivered to alt2.gmail-smtp-in.l.google.com (preference 20; lower is tried first). Resolvers may cache it for up to 2460 seconds.
```

### SOA lookups

```
$ printf "www.google.com\nnope-zz9.com\n" | dnsquery --type SOA --try-to-resolve --select-fields query,status,name,zone,ttl
QUERY           STATUS    NAME           ZONE         TTL
www.google.com  NOERROR   google.com.    google.com.  60
nope-zz9.com    NXDOMAIN  nope-zz9.com.  com.         900
```

`--is-authoritative ns1.google.com` would then keep only rows whose SOA
names that server as primary.

### Large inputs

Results are written as they complete, in input order, and only a bounded
window of queries (about 3 × `--concurrency`) is held at a time, so
memory stays flat: 500,000 domains peak at 36–90 MB depending on format,
of which the default 10,000-entry cache is about 12 MB.

At the default `--rate 15`, 100,000 domains take about 1 hour 51 minutes.
Raise `--rate` for resolvers you know can take it.

- Text output aligns columns in blocks of 1,000 rows.
- Excel files hold at most 1,048,575 rows; use CSV beyond that. Excel
  output also needs a build with `-tags excel` (see Build).

## Servers, retries and failover

Servers from `--server` (default: every `nameserver` in
`/etc/resolv.conf`) are tried in order for each query:

- A server that **times out** is retried in up to `--retries` further
  rounds.
- A server that is **unreachable**, answers **SERVFAIL**, **REFUSED** or
  **NOTIMP**, or replies to the wrong question is skipped and the next one
  is asked.
- If no server gives a usable answer, the last answer (for example
  `SERVFAIL`) is reported, or `ERROR` when none replied.

The `server` field shows which server answered. Plain and encrypted
servers can be mixed in one list.

## Encrypted DNS (DoT, DoH, DoQ)

A `--server` with a scheme is queried over an encrypted transport:

| Server | Transport | Default port |
|--------|-----------|--------------|
| `tls://host[:port][#tls-name]` | DNS over TLS (RFC 7858) | 853 |
| `https://host[:port]/path[#tls-name]` | DNS over HTTPS (RFC 8484), POST over HTTP/2 | 443 |
| `quic://host[:port][#tls-name]` | DNS over QUIC (RFC 9250); needs a `-tags doq` build | 853 |

```bash
dnsquery example.com --server tls://1.1.1.1
dnsquery example.com --server tls://8.8.8.8#dns.google
dnsquery example.com --server https://dns.google/dns-query
dnsquery example.com --server https://8.8.8.8/dns-query#dns.google
dnsquery example.com --server quic://94.140.14.14#dns.adguard-dns.com
```

- **Certificates are always checked** against the system's trusted CAs
  and the server name: `host`, or `#tls-name` when given. Use `#tls-name`
  when you connect to an IP address that the certificate does not list
  (strict privacy profile, RFC 8310).
- **Private certificates**: `--tls-ca file.pem` adds the CA certificates
  in the file to the system's trusted CAs. The check stays on, so the
  server's certificate must still be signed by a trusted CA and match its
  name, and public servers in the same list keep working. For a
  self-signed server certificate, put that certificate itself in the
  file The file is only read when an encrypted server is used.
- **Skipping the check**: `--tls-insecure` turns the certificate check
  off for all encrypted servers in the run. Traffic is
  still encrypted, but the server is not authenticated, so anyone on the
  path could impersonate it and answer whatever they like. dnsquery prints
  a warning on stderr, and `--verbose` shows `certificates: NOT checked`.
  Use it only for servers you control, for example a lab resolver, and
  prefer `--tls-ca`. The two flags cannot be combined.
- **A host name** in the server is looked up with the system resolver
  (`/etc/resolv.conf`), unencrypted, for each new connection. Give an IP
  address with `#tls-name` to avoid that lookup: the connection goes to
  the IP address, and the certificate check, TLS server name (SNI) and,
  for DoH, the HTTP `Host` all use `tls-name`. So
  `https://8.8.8.8/dns-query#dns.google` sends the same request as
  `https://dns.google/dns-query`, without looking up `dns.google`. The
  provider is still visible from the IP address and SNI; what this saves
  is the plain-text lookup and the dependency on the system resolver.
- **Connections are reused**: DoT keeps idle connections (one query at a
  time on each, dropped after 20 seconds unused so a connection a firewall
  has silently forgotten is not tried), DoH shares one HTTP/2 connection, and DoQ opens one
  stream per query on a shared connection. The first query to a server
  includes the TLS or QUIC handshake, so its `rtt_ms` is higher.
  `--timeout` covers the handshake too.
- **Queries are padded** to a multiple of 128 bytes (EDNS Padding,
  RFC 7830 and RFC 8467), so their size reveals less about the name.
  DoH and DoQ queries use message ID 0, as their RFCs require.
- DoH connects directly; `HTTPS_PROXY` and similar variables are ignored.
- Failover, retries, `--rate`, the cache and `--dnssec` work the same as
  for plain DNS. `--tcp` only affects plain servers.
- `--check-nameservers` still queries authoritative nameservers with
  plain DNS on port 53; only its lookups of the zone, NS and addresses
  go through `--server`.

## Rate limiting

`--rate` (default `15`) caps how many queries per second dnsquery sends.
Every packet counts — retries, failover to another server and TCP/EDNS
fallbacks included — because that is what the server sees. Queries are
spaced evenly rather than sent in bursts.

`--concurrency` is a different limit: at most that many queries wait for
a reply at once. It does not limit speed — against a resolver answering
in 1 ms, 50 concurrent queries would be about 50,000 queries per second —
so `--rate` is what keeps a resolver from rate-limiting or blocking you.

Some limits to be aware of:

| Resolver | Default limit |
|----------|---------------|
| Pi-hole  | 1,000 queries per 60 s per client (≈ 16.7/s) — the default of 15 stays under it |

Change it in `~/.dnsquery.yaml` (`rate: 100`) or with
`DNSQUERY_RATE=100`. `--rate 0` disables the limit.

## Checking a zone's nameservers

`--check-nameservers` asks every authoritative nameserver of a zone
directly, instead of going through your resolver, and compares what they
say. For each input name it finds the zone (walking up with SOA queries),
looks up the zone's NS records and each nameserver's IPv4 addresses, then
asks every address, with recursion off, for the zone's SOA and for the
name and `--type` you gave. There is one row per nameserver address.

Only IPv4 addresses are used by default. `--ipv6` adds the nameservers'
IPv6 addresses, as in the example below; on a host without IPv6
connectivity they show up as skipped. Without `--ipv6`, a nameserver that
has only IPv6 addresses is listed as skipped rather than checked.
Servers you give with `--server`, and those in `/etc/resolv.conf`, are
always used as given, whatever their address family.

```
$ dnsquery --check-nameservers --ipv6 nic.se --select-fields ns,server,status,serial,nsid,check
NS                SERVER                       STATUS   SERIAL      NSID    CHECK
ns.iis.se.        91.226.36.45:53              NOERROR  1790773966
ns.iis.se.        [2001:67c:124c:100a::45]:53  SKIPPED                      skipped: this host has no route to 2001:67c:124c:100a::45
ns3.iis.se.       91.226.37.45:53              NOERROR  1790773966
nsa.dnsnode.net.  194.58.192.46:53             NOERROR  1790773966  s4.got
nsu.dnsnode.net.  185.42.137.98:53             NOERROR  1790773966  u4.stu
...
```

The `check` field is empty when a server is fine, and otherwise names the
problem:

| Check | Meaning |
|-------|---------|
| `lame: …` | Listed as a nameserver but does not answer authoritatively (no AA flag, or REFUSED/SERVFAIL for its own zone) |
| `serial N differs from M on X of Y servers` | Serves an older or newer version of the zone than most servers; zone transfers may be failing |
| `serials differ: …; no majority` | No version of the zone is on most servers (for example 2 against 2); every server is flagged, and the serials are listed, highest first. Often brief, while a change spreads |
| `answer differs from X of Y servers` | Gives a different answer for the name than most servers, so results depend on which server a resolver picks |
| `answers differ: …, no majority` | No answer is given by most servers; every server is flagged |
| `nameserver has no A or AAAA address` | The NS name does not resolve |
| `no usable reply: …` | Timed out or failed |
| `skipped: this host has no route to …` | This machine cannot reach the address (typically IPv6, with `--ipv6`) |
| `skipped: only IPv6 addresses (…); add --ipv6 to check them` | The nameserver has no IPv4 address, and IPv6 addresses are only checked with `--ipv6` |
| `skipped: this host's firewall does not let DNS out to …` | The operating system refused to send the query (`operation not permitted`), typically a VPN that only allows DNS to its own resolver |

Skipped rows mean the query never left this machine, so they say nothing
about the server and are not counted as problems. Any other problem makes
dnsquery exit with status 2, and so does a check where *every* address
was skipped: nothing was checked, which is not the same as nothing being
wrong.

Behind a VPN that blocks DNS to other servers, `--check-nameservers` cannot
work. Run it without the VPN, or exclude dnsquery from the tunnel if your
VPN supports split tunnelling.
Server identifiers (NSID) are requested automatically, which shows which
anycast instance answered. `--check-nameservers` cannot be combined with
`--dnssec`, `--try-to-resolve` or `--is-authoritative`. The queries count
against `--rate`: two per nameserver address (one when checking the SOA
of the zone itself).

## DNS posture: mail and zone records

`--dns-posture` looks up, for each domain, the records that show how its
mail and certificates are protected:

| Kind | Looked up as |
|------|--------------|
| `MX` | MX records of the name |
| `SPF` | TXT record starting `v=spf1` (RFC 7208) |
| `DMARC` | TXT record at `_dmarc.<name>` starting `v=DMARC1` (RFC 7489) |
| `DKIM` | TXT key record at `<selector>._domainkey.<name>` for the common selectors `default`, `google`, `k1`, `k2`, `selector1`, `selector2` (RFC 6376) |
| `NS` | NS records owned by the name itself |
| `CAA` | CAA records (RFC 8659) |

Each kind is looked up at the name first. If nothing is found and the name
is a subdomain, the **organizational domain** is tried instead: the
registrable domain from the public suffix list, so `www.gp.se` falls back
to `gp.se` and `www.example.co.uk` to `example.co.uk`. These records are
normally published at the apex. The `name` field shows where each record
was found. NS is never taken from an alias: an NS query for a CNAME'd
name returns the alias target's (for example a CDN's) nameservers.

There is one row per record found, with the kind in the `qtype` field, or
one row per kind found nowhere:

```
$ dnsquery www.gp.se --dns-posture
QUERY      QTYPE  STATUS   NAME                        VALUE                                        CHECK
www.gp.se  MX     NOERROR  gp.se.                      10 itgarden-in1a.mx-wecloud.net.
www.gp.se  MX     NOERROR  gp.se.                      10 itgarden-in2a.mx-wecloud.net.
www.gp.se  SPF    NOERROR  gp.se.                      v=spf1 mx ip4:81.201.209.101 … -all
www.gp.se  DMARC  NOERROR  _dmarc.gp.se.               v=DMARC1; p=none; rua=mailto:…
www.gp.se  DKIM   NOERROR  selector1._domainkey.gp.se. v=DKIM1; k=rsa; p=MIIBIjAN…
www.gp.se  NS     NOERROR  gp.se.                      ns1.p201.dns.oraclecloud.net.
…
www.gp.se  CAA    NODATA   gp.se.                                                                   low: no CAA record; any certificate authority may issue certificates for the domain
```

The `check` field flags, with a severity you can filter on
(`--match-fields check=medium`):

| Check | When |
|-------|------|
| `medium: no SPF record, …` | The domain receives mail (has MX records) but publishes no SPF |
| `medium: no DMARC record, …` | The domain receives mail but publishes no DMARC policy |
| `low: no DKIM record for the common selectors …` | The domain receives mail and none of the common selectors has a key; its real selector may simply be another one |
| `low: no CAA record; …` | No CAA record, so any certificate authority may issue certificates |
| `medium: 2 SPF records; …` | More than one SPF record, which receivers treat as an error (RFC 7208 §4.5) |
| `medium: 2 DMARC records; …` | More than one DMARC record, so receivers ignore DMARC (RFC 7489 §6.6.3) |

A null MX (`0 .`, RFC 7505) means the domain takes no mail, so the mail
checks are skipped. Findings do not change the exit status. A lookup that
fails (no reply, or SERVFAIL) gives an `ERROR` row instead of a finding,
since the record may exist, and makes the exit status 2. `--dns-posture`
chooses its own record types, so it cannot be combined with `--type`,
nor with `--check-nameservers`, `--compare-servers`, `--dnssec`,
`--try-to-resolve` or `--is-authoritative`. It sends about 12 queries
per domain (twice that with the fallback), all counting against `--rate`
and answered from the cache when repeated.

## Comparing resolvers

`--compare-servers` asks **every** `--server` for each query at the same
time, instead of using the first that answers, and shows one row per
server with its whole answer. Answers are compared by status and records
(sorted, TTLs ignored), and the `check` field flags:

- a server whose answer differs from most of the others
- every server, when no answer has a majority (for example, two servers
  that disagree)
- a server that gives no usable reply (after `--retries`)

```
$ dnsquery example.com --compare-servers --server 1.1.1.1,8.8.8.8,9.9.9.9,192.0.2.53
QUERY        QTYPE  SERVER         STATUS   VALUE                             CHECK
example.com  A      1.1.1.1:53     NOERROR  A 104.20.23.154 | A 172.66.147.243
example.com  A      8.8.8.8:53     NOERROR  A 104.20.23.154 | A 172.66.147.243
...
```

Use it to find resolvers that filter or rewrite answers, split-horizon
mistakes (an internal and an external resolver), and differences between
plain DNS and DoH/DoT/DoQ to the same provider. Plain and encrypted
servers can be mixed. Any flagged query makes the exit status 2.

Answers that legitimately vary, such as CDN or GeoDNS names and large
round-robin pools where each resolver returns a different subset, are
flagged too; that is what they are. The cache is bypassed (each server
is asked itself), and every server counts against `--rate`. It cannot be
combined with `--check-nameservers`, `--dnssec`, `--try-to-resolve` or
`--is-authoritative`.

### What clients elsewhere get: `--ecs`

`--ecs 192.0.2.0/24` sends that client subnet with every query (EDNS
Client Subnet, RFC 7871), so a CDN or GeoDNS service answers as it would
for clients in that network. An address alone is shortened to `/24`
(IPv4) or `/56` (IPv6), as the RFC recommends; `--ecs 0.0.0.0/0` asks
resolvers to send no client subnet at all. It works with any mode, not
only `--compare-servers`.

The `ecs` field shows the subnet and *scope* the server answered with:
which clients its answer is for. An empty `ecs` means the server ignored
the subnet. Many public resolvers do so deliberately, for privacy (for
example 1.1.1.1), so results depend on the resolver; an authoritative
server that supports ECS gives the clearest answer.

## DNSSEC validation

With `--dnssec`, dnsquery acts as a validating stub resolver (RFC 4035
§4.9): it does not trust the resolver's AD bit, which anything on the
path could forge, but checks the signatures itself.

```
$ printf "example.com\ngoogle.com\ndnssec-failed.org\nnonexistent-zz9q.se\n" | dnsquery --dnssec --select-fields query,status,dnssec,dnssec_reason
QUERY                STATUS    DNSSEC    DNSSEC_REASON
example.com          NOERROR   secure
example.com          NOERROR   secure
google.com           NOERROR   insecure  insecure delegation: google.com. has no DS in com.
dnssec-failed.org    NOERROR   bogus     no DNSKEY for dnssec-failed.org. matches its DS records or trust anchors
nonexistent-zz9q.se  NXDOMAIN  secure
1 of 4 queries failed (1 DNSSEC bogus)
```

| Status     | Meaning |
|------------|---------|
| `secure`   | Authenticated by a chain of signatures from the root trust anchor |
| `insecure` | Provably unsigned: an unsigned delegation, an NSEC3 opt-out span, or only unsupported algorithms. Not authenticated, but not an attack either |
| `bogus`    | Should be signed but does not validate: bad or expired signatures, missing RRSIGs, or no valid proof. A validating resolver would answer SERVFAIL |

How it works:

- Queries set the DO bit (return signatures) and the CD bit (return data
  even if the resolver considers it bogus, so dnsquery can judge it).
- The chain of trust is built top-down from the IANA root trust anchors
  (KSK-2017 and KSK-2024, built in; `--trust-anchor` overrides them)
  through DS and DNSKEY lookups, one label at a time.
- Answer RRsets are checked against their zone's keys, including CNAME
  chains, DNAME synthesis and wildcard expansion (with its proof of no
  closer match).
- NXDOMAIN and NODATA are checked against NSEC or NSEC3 proofs
  (RFC 4035 §5.4, RFC 5155 §8), including empty non-terminals and
  wildcard NODATA.
- The status is per RRset, so a secure CNAME into an unsigned CDN shows
  exactly where the chain ends:

```
$ dnsquery www.ripe.net --type AAAA --dnssec --select-fields name,type,dnssec
NAME                          TYPE   DNSSEC
www.ripe.net.                 CNAME  secure
www.ripe.net.edgekey.net.     CNAME  insecure
e337066.dscb.akamaiedge.net.  AAAA   insecure
e337066.dscb.akamaiedge.net.  AAAA   insecure
```

Things to know:

- Any `bogus` answer makes dnsquery exit with status 2.
- Validation needs DS and DNSKEY lookups for every zone on the way down.
  They are cached, so for many names under one TLD the cost is roughly
  two extra queries per new zone, all counted against `--rate`.
- If your resolver strips DNSSEC data (some home routers do), everything
  is `bogus` with the reason "no DNSKEY records for the root zone". Use a
  DNSSEC-aware resolver with `--server`.
- NXDOMAIN and DS answers proven with an NSEC3 opt-out span are
  `insecure`, as RFC 5155 §9.2 requires (the name may exist as an unsigned
  delegation). BIND's `delv` reports these as validated; Unbound, like
  dnsquery, does not.
- Supported algorithms: RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256
  and P-384, Ed25519. Zones signed only with others (such as Ed448) are
  `insecure` (RFC 4035 §5.2). NSEC3 with more than 150 iterations is
  `insecure` (RFC 9276).

## Caching

Responses are cached in memory for the duration of one run, so duplicate
domains, and the DS/DNSKEY lookups validation repeats constantly, are
answered without another query. The `cached` field marks rows served from
the cache.

- Positive answers live for their TTL, which counts down as with a
  resolver; negative answers for min(SOA TTL, SOA MINIMUM) (RFC 2308).
- Failures (timeouts, SERVFAIL, REFUSED) are cached for 30 seconds
  (RFC 9520), so a failing name is not hammered.
- Identical queries in flight at the same time are sent once.
- `--cache-size` (default 10,000 responses) bounds memory; the least
  recently used entries are dropped first.

There is no cache between runs: every run starts empty, so a cached
answer can only come from earlier in the same run — a domain listed
twice, or a DS/DNSKEY lookup that `--dnssec` already made.

This is dnsquery's own cache. Your resolver (`--server`, or the one in
`/etc/resolv.conf`) keeps a cache of its own, and that is usually why an
answer looks out of date after a DNS change. To see what a zone serves
right now, point `--server` at one of its authoritative nameservers.

### What the RFCs say

The RFCs don't talk about defaults; they say what a resolver must, should
or may do. For a stub resolver like dnsquery:

| Cached item | Requirement | Source |
|-------------|-------------|--------|
| Normal answers | **MAY** cache; if it does, entries **MUST** expire | RFC 1123 §6.1.3.1(B) |
| "Does not exist" answers (NXDOMAIN, NODATA) | **SHOULD** cache | RFC 1123 §6.1.3.3(4), RFC 2308 |
| Failures (timeouts, SERVFAIL, no usable answer) | **MUST** cache for 1 second to 5 minutes, and not ask again meanwhile | RFC 9520 §3.2 |

Caching normal answers is optional; caching "does not exist" answers and
failures is expected. With the cache on, the default, dnsquery does all
three. Normal answers expire with their TTL, "does not exist" answers with
min(SOA TTL, SOA MINIMUM), and failures after 30 seconds.

### Turning the cache off

`--cache-size 0` turns the cache off completely: every query goes to the
server, and with `--dnssec` the DS/DNSKEY chain is fetched again for
every name. What that costs:

- **It departs from RFC 9520 and RFC 1123 §6.1.3.3**, because failures
  and "does not exist" answers are no longer cached: a failing name that
  appears many times in the input is asked again every time.
- **More queries.** Duplicate names each cost a query, and DNSSEC
  validation costs several extra queries per name instead of per zone.
  `--rate` still caps the pace, so the run gets slower rather than harder
  on the server.

Identical queries in flight at the very same moment are still sent once;
that is not caching, just not asking twice at once.

## Troubleshooting

`--verbose` prints the configuration once. `--trace` shows what happens
under the hood, one line per event on stderr, so the results on stdout
stay clean:

- every packet: server, protocol, DO/CD flags, and a summary of the
  response (RCODE, record counts, RRSIGs, header flags, EDNS, size, time)
- retries, failover to the next server, TCP and no-EDNS fallbacks, time
  spent waiting for `--rate`, and cache hits
- with `--dnssec`, each step of the chain of trust and each check, down to
  the key tag that matched and the proof that made a zone insecure

Each line starts with the input it belongs to. Use `--concurrency 1` to
keep one lookup's lines together.

```
$ dnsquery www.ripe.net --dnssec --trace --server 1.1.1.1
trace www.ripe.net: 1.1.1.1:53 udp . DNSKEY +DO +CD -> NOERROR, answer 0, authority 0, additional 0, 0 RRSIGs, flags [tc ra cd], EDNS 1232 DO, ~28 bytes, 8.71ms
trace www.ripe.net: answer truncated (TC); retrying over TCP
trace www.ripe.net: 1.1.1.1:53 tcp . DNSKEY +DO +CD -> NOERROR, answer 5, authority 0, additional 0, 1 RRSIGs, flags [ra cd], EDNS 1232 DO, ~1420 bytes, 8.52ms
trace www.ripe.net: dnssec .: secure zone: 4 DNSKEYs; key 20326 matches the trust anchor and signs the DNSKEY set
...
trace www.ripe.net: dnssec www.ripe.net. CNAME: RRSIG by ripe.net. key 63758 verifies (valid until 20261012085147): secure
trace www.ripe.net: dnssec edgekey.net.: insecure: insecure delegation: edgekey.net. has no DS in net.
```

### Resolvers that send oversized UDP answers

dnsquery tells servers it accepts UDP answers of up to 1,232 bytes. A
correct server keeps within that or sets the TC (truncated) flag, and
dnsquery retries over TCP. Some VPN and middlebox resolvers do neither:
they send the whole, larger answer, which arrives cut off and cannot be
read. DNSSEC answers such as the root DNSKEY set are often large enough to
hit this.

dnsquery retries such an answer over TCP automatically. With `--trace` it
looks like this (the server address is an example):

```
trace www.ripe.net: 10.8.0.1:53 udp . DNSKEY +DO +CD -> dns: overflowing header size
trace www.ripe.net: UDP answer unreadable, probably larger than the 1232 bytes requested and not marked truncated; retrying over TCP
```

If TCP fails too, the error says so. `--tcp` (or `tcp: true` in the config
file) avoids UDP altogether.

### What the server tells you: Extended DNS Errors and NSID

Many resolvers explain a failure with an Extended DNS Error (RFC 8914),
shown in the `ede` field, by `--explain`, and in `--trace`. `--nsid` asks
the server which machine answered (RFC 5001), which helps with anycast
services such as 1.1.1.1 where one address hides many servers:

```
$ dnsquery dnssec-failed.org example.com --server 1.1.1.1 --nsid --select-fields query,status,ede,nsid
QUERY              STATUS    EDE                                                                    NSID
dnssec-failed.org  SERVFAIL  9 DNSKEY Missing: no SEP matching the DS found for dnssec-failed.org.  arn07
example.com        NOERROR                                                                          arn02
```

NSID is off by default: some middleboxes handle unfamiliar EDNS options
badly, so it is only sent when asked for.

### Resolvers you cannot bypass

Some VPNs intercept all DNS traffic, so `--server` still reaches the VPN's
resolver. `--trace` shows which server really answered and what it sent
back. A resolver that drops DNSSEC data shows `0 RRSIGs` and a note that
the DO bit was not echoed, and validation then reports `bogus` with the
reason "no DNSKEY records for the root zone".

## Configuration

Every flag can also be set in a YAML config file or an environment
variable. Precedence is flag > environment > config file > default.

`--config-example` prints a complete example with every setting, its help
text and its default, ready to save and edit:

```bash
dnsquery --config-example > ~/.dnsquery.yaml
```

Settings without a default (`server`, `output`, `select-fields`,
`match-fields`, `is-authoritative`, `trust-anchor`, `tls-ca`) appear
commented out with an example value. A short config might look like this:

```yaml
# ~/.dnsquery.yaml
server: [192.0.2.53, 192.0.2.54]
type: MX
timeout: 2s
output: csv
```

Environment variables use the `DNSQUERY_` prefix with `-` replaced by
`_`, for example `DNSQUERY_SERVER=1.1.1.1` or `DNSQUERY_TRY_TO_RESOLVE=true`.

## Exit status

| Code | Meaning |
|------|---------|
| 0    | Every query got a DNS answer (`NXDOMAIN` and `SERVFAIL` are answers) |
| 1    | Usage, configuration, input or output error, or interrupted |
| 2    | At least one query ended in `ERROR` (with `--dns-posture`: any of its lookups), was DNSSEC `bogus` with `--dnssec`, found a nameserver problem with `--check-nameservers`, or got differing or missing answers with `--compare-servers`; results are still written |

## Standards

| RFC      | What dnsquery does |
|----------|--------------------|
| 1034/1035 | Recursive queries with RD set; replies must echo the question; next server on error responses (§7.2) |
| 1123     | Stub resolver uses redundant recursive servers (§6.1.3.1) with bounded retransmission (§6.1.3.3); cached entries expire (§6.1.3.1(B)); negative answers and failures cached (§6.1.3.3) |
| 2308     | `NODATA` vs. `NXDOMAIN`; negative TTL = min(SOA TTL, SOA MINIMUM); negative answers cached for it |
| 4033/4034/4035 | Validating stub: DO and CD bits, chain of trust from the root, RRSIG, NSEC and wildcard validation, canonical ordering |
| 4509     | SHA-1 DS records ignored when a stronger digest is present |
| 5001     | NSID: server identification with `--nsid` and `--check-nameservers` |
| 5011     | Revoked keys are not trusted |
| 5155     | NSEC3 closest encloser, NXDOMAIN, NODATA, DS and wildcard proofs; opt-out is insecure (§9.2) |
| 6672     | DNAME: synthesized CNAMEs must match the signed DNAME |
| 6891     | EDNS(0) with a 1232-byte UDP buffer; retry without EDNS on FORMERR; an unreadable UDP answer (larger than requested, without TC) is retried over TCP |
| 7766     | Retry over TCP when a UDP answer is truncated |
| 7830/8467 | Encrypted queries padded to a multiple of 128 bytes |
| 7858/8310 | DNS over TLS (`tls://`), with the certificate checked against the server name |
| 8484     | DNS over HTTPS (`https://`), POST with message ID 0 |
| 8624     | DNSSEC algorithm support (see above) |
| 7871     | EDNS Client Subnet with `--ecs`: subnet sent truncated to its prefix, scope shown in the `ecs` field |
| 8914     | Extended DNS Errors shown in the `ede` field |
| 9250     | DNS over QUIC (`quic://`): one stream per query, message ID 0, ALPN `doq` |
| 9276     | NSEC3 with more than 150 iterations treated as insecure |
| 9520     | Resolution failures cached for 30 seconds |

Not implemented: exponential backoff between retries (RFC 1123
§6.1.3.3(5), a SHOULD), trust anchor rollover (RFC 5011; update the
built-in anchors or use `--trust-anchor`), and a cache that persists
between runs.

## Development

```bash
go test -race ./...                  # default build
go test -race -tags excel,doq ./...  # with Excel output and DNS over QUIC
golangci-lint run --build-tags excel,doq ./...
```

Tests run against in-process DNS servers, so they need no network. The
DNSSEC tests build a signed hierarchy (NSEC, NSEC3 and opt-out zones,
wildcards, DNAME, broken and expired zones) with real keys and tamper with
responses to check that forgeries are caught.

Every change is expected to pass `go build`, `go vet`, the tests in both
builds (without and with `-tags excel,doq`), `golangci-lint` with the
repository's `.golangci.yml`, and a minimum of 70% test coverage measured
on the full build:

```bash
go test -tags excel,doq -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -1
```

## License

BSD 2-Clause — see [LICENSE](LICENSE).
