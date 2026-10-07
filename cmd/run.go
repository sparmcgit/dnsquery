package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/time/rate"

	"github.com/sparmcgit/dnsquery/internal/dnsq"
)

// addQueryFlags registers the query flags on the root command.
func addQueryFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.Int("concurrency", 50, "number of concurrent workers")
	f.Bool("config-example", false, "print an example config file with all settings and defaults, and exit")
	f.Int("cache-size", 10000, "maximum responses cached during a run (0 disables caching)")
	f.Bool("dns-posture", false, "look up each domain's mail and zone records (MX, SPF, DMARC, DKIM on common selectors, NS, CAA), falling back to the organizational domain (www.example.com -> example.com), and flag missing ones")
	f.Bool("ipv6", false, "with --check-nameservers, query the nameservers' IPv6 addresses as well as IPv4 (default: IPv4 only); --server addresses are always used as given")
	f.Bool("compare-servers", false, "ask every --server (at least two) for each query instead of failing over, and flag servers whose answer differs from the others")
	f.String("ecs", "", "send this client subnet with every query (EDNS Client Subnet, RFC 7871), e.g. 192.0.2.0/24, to see the answer clients there get; an address alone is shortened to /24 (IPv4) or /56 (IPv6)")
	f.Bool("check-nameservers", false, "ask each authoritative nameserver of the zone directly and report lame servers and differing serials or answers")
	f.Bool("dnssec", false, "validate answers with DNSSEC from the root trust anchor (adds DS/DNSKEY queries)")
	f.String("trust-anchor", "", "file with root trust anchor DS or DNSKEY records (default: built-in IANA root anchors)")
	f.Bool("explain", false, "add a plain-language explanation of the DNS result")
	f.String("file", "-", "input file path ('-' for stdin)")
	f.StringSlice("is-authoritative", nil, "for SOA queries: only output if SOA MNAME matches one of these authoritative servers (repeatable)")
	f.Bool("list-fields", false, "list output fields and exit")
	f.Bool("nsid", false, "ask each server to identify itself (NSID, RFC 5001) and add the nsid column")
	f.StringSlice("match-fields", nil, "filter output rows by field match expressions: field=value (comma-separated or repeated); values use case-insensitive substring matching, | for OR, && for AND")
	output := "write results to stdout as text|yaml|json|csv|excel, or to a file path ending in .txt, .yaml/.yml, .json, .csv, or .xlsx"
	if !dnsq.ExcelAvailable {
		output += " (excel/.xlsx need a build with -tags excel)"
	}
	f.String("output", "", output)
	f.Bool("progress", false, "show query progress on stderr")
	f.StringSlice("select-fields", nil, "select output fields (repeatable or comma-separated; 'all' selects every field)")
	server := "DNS server, tried in order (repeatable or comma-separated): ip[:port] for plain DNS, tls://host[:port][#tls-name] for DNS over TLS, https://host[:port]/path[#tls-name] for DNS over HTTPS, quic://host[:port][#tls-name] for DNS over QUIC (default: nameservers in /etc/resolv.conf)"
	if !dnsq.DoQAvailable {
		server += " (quic:// needs a build with -tags doq)"
	}
	f.StringSlice("server", nil, server)
	f.Bool("tcp", false, "use TCP instead of UDP for plain DNS servers")
	f.String("tls-ca", "", "PEM file with extra CA certificates to trust for tls://, https:// and quic:// servers, in addition to the system's (for private certificates)")
	f.Bool("tls-insecure", false, "do not check the certificates of tls://, https:// and quic:// servers (for private or self-signed certificates; still encrypted, but anyone on the path could impersonate the server)")
	f.Duration("timeout", 3*time.Second, "DNS query timeout (e.g. 3s)")
	f.Int("retries", 2, "resend a query this many times when it times out")
	f.Float64("rate", 15, "maximum queries per second sent, counting retries and failover (0 for unlimited)")
	f.Bool("try-to-resolve", false, "for SOA queries: if the name returns NODATA, retry parent labels until an SOA is found")
	f.Bool("trace", false, "print every query, response and DNSSEC step on stderr, for troubleshooting")
	f.String("type", "A", "record types, comma-separated (A, AAAA, PTR, MX, NS, TXT, SOA, etc); each domain is queried for each type, in that order")
	f.Bool("verbose", false, "print running configuration")
}

func runQuery(cmd *cobra.Command, args []string) error {
	// Bind the running command's flags so precedence is flag > env > config > default.
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()

	if viper.GetBool("config-example") {
		return writeConfigExample(stdout, cmd.Flags())
	}
	if viper.GetBool("list-fields") {
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		for _, f := range dnsq.Fields {
			fmt.Fprintf(tw, "%s\t%s\n", f.Name, f.Description)
		}
		return tw.Flush()
	}

	types, err := parseTypes(viper.GetStringSlice("type"))
	if err != nil {
		return err
	}
	authServers := viper.GetStringSlice("is-authoritative")
	tryParents := viper.GetBool("try-to-resolve")
	if (len(types) != 1 || types[0] != dns.TypeSOA) && (len(authServers) > 0 || tryParents) {
		return errors.New("--is-authoritative and --try-to-resolve require --type SOA (alone)")
	}
	explain := viper.GetBool("explain")
	validate := viper.GetBool("dnssec")
	checkNS := viper.GetBool("check-nameservers")
	if checkNS && (validate || tryParents || len(authServers) > 0) {
		return errors.New("--check-nameservers cannot be combined with --dnssec, --try-to-resolve or --is-authoritative")
	}
	compare := viper.GetBool("compare-servers")
	if compare && (checkNS || validate || tryParents || len(authServers) > 0) {
		return errors.New("--compare-servers cannot be combined with --check-nameservers, --dnssec, --try-to-resolve or --is-authoritative")
	}
	posture := viper.GetBool("dns-posture")
	if posture && (checkNS || compare || validate || tryParents || len(authServers) > 0) {
		return errors.New("--dns-posture cannot be combined with --check-nameservers, --compare-servers, --dnssec, --try-to-resolve or --is-authoritative")
	}
	if posture && viper.IsSet("type") {
		return errors.New("--dns-posture chooses its own record types; leave out --type")
	}
	var ecs *dns.EDNS0_SUBNET
	if s := viper.GetString("ecs"); s != "" {
		if ecs, err = dnsq.ParseECS(s); err != nil {
			return err
		}
	}
	fieldOpts := dnsq.FieldOptions{DNSSEC: validate, NSID: viper.GetBool("nsid"), ECS: ecs != nil, Explain: explain}
	switch {
	case checkNS:
		fieldOpts.Defaults = dnsq.CheckFields
	case compare:
		fieldOpts.Defaults = dnsq.CompareFields
	case posture:
		fieldOpts.Defaults = dnsq.PostureFields
	}
	fields, err := dnsq.SelectFields(viper.GetStringSlice("select-fields"), fieldOpts)
	if err != nil {
		return err
	}
	matcher, err := dnsq.ParseMatch(viper.GetStringSlice("match-fields"))
	if err != nil {
		return err
	}
	format, outPath, err := dnsq.ResolveOutput(viper.GetString("output"))
	if err != nil {
		return err
	}
	concurrency := viper.GetInt("concurrency")
	if concurrency < 1 {
		return errors.New("--concurrency must be at least 1")
	}
	timeout := viper.GetDuration("timeout")
	if timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	retries := viper.GetInt("retries")
	if retries < 0 {
		return errors.New("--retries must not be negative")
	}
	qps := viper.GetFloat64("rate")
	if qps < 0 {
		return errors.New("--rate must not be negative")
	}
	servers, err := resolveServers(viper.GetStringSlice("server"))
	if err != nil {
		return err
	}
	if compare && len(servers) < 2 {
		return fmt.Errorf("--compare-servers needs at least two servers, got %s", strings.Join(servers, ", "))
	}
	caFile := viper.GetString("tls-ca")
	if caFile != "" && viper.GetBool("tls-insecure") {
		return errors.New("--tls-ca and --tls-insecure cannot be combined: --tls-ca checks certificates, --tls-insecure does not")
	}
	// Like --trust-anchor without --dnssec, the file is only read when used.
	encrypted := slices.ContainsFunc(servers, func(s string) bool { return strings.Contains(s, "://") })
	var caPool *x509.CertPool
	if caFile != "" && encrypted {
		if caPool, err = loadCAs(caFile); err != nil {
			return err
		}
	}
	cacheSize := viper.GetInt("cache-size")
	if cacheSize < 0 {
		return errors.New("--cache-size must not be negative")
	}
	var validator *dnsq.Validator
	anchorSource := "built-in IANA root anchors"
	if validate {
		anchors, source, err := loadTrustAnchors(viper.GetString("trust-anchor"))
		if err != nil {
			return err
		}
		validator, anchorSource = dnsq.NewValidator(anchors, cacheSize), source
	}

	src, err := openInputs(cmd, args)
	if err != nil {
		return err
	}
	if src == nil {
		// Nothing given and stdin is a terminal: show help instead of blocking.
		return cmd.Help()
	}
	defer src.close()
	next, stop := iter.Pull(src.all)
	defer stop()
	first, ok := next()
	if !ok {
		if src.err != nil {
			return src.err
		}
		return errors.New("no domains given")
	}

	res := &dnsq.Resolver{Servers: servers, TCP: viper.GetBool("tcp"), Timeout: timeout, Retries: retries,
		Cache: dnsq.NewCache(cacheSize), Validator: validator}
	defer res.Close()
	if viper.GetBool("tls-insecure") {
		res.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
		if encrypted {
			fmt.Fprintln(stderr, "warning: --tls-insecure: server certificates are not checked, so the answers are not authenticated")
		}
	} else if caPool != nil {
		res.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: caPool}
	}
	if viper.GetBool("trace") {
		res.Trace = dnsq.NewTracer(stderr)
	}
	res.NSID = viper.GetBool("nsid") || checkNS
	res.ECS = ecs
	res.IPv6 = viper.GetBool("ipv6")
	lookup := func(ctx context.Context, q query) []dnsq.Row {
		return res.Lookup(ctx, q.input, q.qtype, tryParents)
	}
	switch {
	case checkNS:
		lookup = func(ctx context.Context, q query) []dnsq.Row {
			return res.CheckNameservers(ctx, q.input, q.qtype)
		}
	case compare:
		lookup = func(ctx context.Context, q query) []dnsq.Row {
			return res.CompareServers(ctx, q.input, q.qtype)
		}
	case posture:
		lookup = func(ctx context.Context, q query) []dnsq.Row {
			return res.DNSPosture(ctx, q.input)
		}
	}
	if qps > 0 {
		// Burst 1 spaces queries evenly instead of sending them in clumps.
		res.Limiter = rate.NewLimiter(rate.Limit(qps), 1)
	}
	if viper.GetBool("verbose") {
		printConfig(stderr, res, types, src.desc, concurrency, cacheSize, anchorSource, format, outPath, fields)
	}

	dst := stdout
	var outFile *os.File
	if outPath != "" {
		if outFile, err = os.Create(outPath); err != nil {
			return err
		}
		defer func() { _ = outFile.Close() }()
		dst = outFile
	}
	buf := bufio.NewWriter(dst)
	rw, err := dnsq.NewWriter(buf, format, fields)
	if err != nil {
		return err
	}

	progress := viper.GetBool("progress")
	var total int
	var failures queryFailuresError
	emit := func(rs []dnsq.Row) error {
		total++
		switch {
		case checkNS && dnsq.Unchecked(rs):
			failures.unchecked++
		case checkNS:
			if slices.ContainsFunc(rs, func(r dnsq.Row) bool { return r.Check != "" && !r.Skipped }) {
				failures.nameservers++
			}
		case compare:
			if slices.ContainsFunc(rs, func(r dnsq.Row) bool { return r.Check != "" }) {
				failures.differ++
			}
		case posture:
			// Missing records are findings, not failures; a lookup that
			// failed is, since the posture is then unknown.
			if slices.ContainsFunc(rs, func(r dnsq.Row) bool { return r.Status == dnsq.StatusError }) {
				failures.errors++
			}
		case rs[0].Status == dnsq.StatusError:
			failures.errors++
		case slices.ContainsFunc(rs, func(r dnsq.Row) bool { return r.DNSSEC == dnsq.SecBogus }):
			failures.bogus++
		}
		if len(authServers) > 0 {
			rs = dnsq.FilterAuthoritative(rs, authServers)
		}
		for _, r := range rs {
			if explain {
				r.Explanation = dnsq.Explain(r)
			}
			if matcher.Match(r) {
				if err := rw.WriteRow(r); err != nil {
					return err
				}
			}
		}
		if progress {
			fmt.Fprintf(stderr, "\rqueried %d", total)
		}
		return nil
	}
	firstQuery, nextQuery := perType(first, next, types)
	err = lookupStream(cmd.Context(), lookup, firstQuery, nextQuery, concurrency, emit)
	if progress {
		fmt.Fprintln(stderr)
	}
	if err == nil {
		err = rw.Close()
	}
	if err == nil {
		err = buf.Flush()
	}
	if outFile != nil && err == nil {
		err = outFile.Close()
	}
	switch {
	case err != nil:
		return err
	case src.err != nil:
		return fmt.Errorf("reading input after %d domains: %w", total, src.err)
	case cmd.Context().Err() != nil:
		return fmt.Errorf("interrupted after %d domains: %w", total, cmd.Context().Err())
	case failures.count() > 0:
		failures.total = total
		return &failures
	}
	return nil
}

// queryFailuresError reports queries with status ERROR (invalid name or no
// usable response) or, with --dnssec, bogus answers. It is returned after
// the results have been written and maps to exit status 2.
type queryFailuresError struct {
	errors, bogus, nameservers, unchecked, differ, total int
}

func (e *queryFailuresError) count() int {
	return e.errors + e.bogus + e.nameservers + e.unchecked + e.differ
}

func (e *queryFailuresError) Error() string {
	var why []string
	if e.errors > 0 {
		why = append(why, fmt.Sprintf("%d with status ERROR", e.errors))
	}
	if e.bogus > 0 {
		why = append(why, fmt.Sprintf("%d DNSSEC bogus", e.bogus))
	}
	if e.nameservers > 0 {
		why = append(why, fmt.Sprintf("%d with nameserver problems", e.nameservers))
	}
	if e.unchecked > 0 {
		why = append(why, fmt.Sprintf("%d where no nameserver could be reached from this host", e.unchecked))
	}
	if e.differ > 0 {
		why = append(why, fmt.Sprintf("%d where servers disagreed or did not reply", e.differ))
	}
	return fmt.Sprintf("%d of %d queries failed (%s)", e.count(), e.total, strings.Join(why, ", "))
}

// loadCAs returns the system's trusted CAs plus the PEM certificates in
// path, so private and public encrypted servers can be mixed.
func loadCAs(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--tls-ca: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("--tls-ca: no PEM certificates in %s", path)
	}
	return pool, nil
}

// loadTrustAnchors reads the trust anchor file, or returns the built-in
// IANA root anchors when path is empty.
func loadTrustAnchors(path string) ([]*dns.DS, string, error) {
	if path == "" {
		anchors, err := dnsq.ParseTrustAnchors(strings.NewReader(dnsq.RootAnchors), "built-in")
		return anchors, "built-in IANA root anchors", err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = f.Close() }()
	anchors, err := dnsq.ParseTrustAnchors(f, path)
	return anchors, path, err
}

// query is one input asked for one record type.
type query struct {
	input string
	qtype uint16
}

// parseTypes reads --type: comma-separated record types, possibly given as
// a list (config file), with duplicates dropped and order kept.
func parseTypes(specs []string) ([]uint16, error) {
	var types []uint16
	for _, spec := range specs {
		for s := range strings.SplitSeq(spec, ",") {
			if s = strings.TrimSpace(s); s == "" {
				continue
			}
			t, err := dnsq.ParseType(s)
			if err != nil {
				return nil, err
			}
			if !slices.Contains(types, t) {
				types = append(types, t)
			}
		}
	}
	if len(types) == 0 {
		return nil, errors.New("--type: no record type given")
	}
	return types, nil
}

// perType turns the inputs first, next() into queries: each input once per
// type, in the order of types, so output stays grouped by input.
func perType(first string, next func() (string, bool), types []uint16) (query, func() (query, bool)) {
	input, i := first, 0
	return query{first, types[0]}, func() (query, bool) {
		if i++; i == len(types) {
			var ok bool
			if input, ok = next(); !ok {
				return query{}, false
			}
			i = 0
		}
		return query{input, types[i]}, true
	}
}

// lookupStream queries first and then every item from next with a pool of
// workers, and passes each item's rows to emit in input order. Only a
// bounded window of queries runs or waits ahead of emit, so memory use does
// not grow with the number of inputs. If emit fails, remaining queries are
// cancelled and its error is returned.
func lookupStream[T any](ctx context.Context, lookup func(context.Context, T) []dnsq.Row, first T,
	next func() (T, bool), workers int, emit func([]dnsq.Row) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type job struct {
		input T
		out   chan []dnsq.Row
	}
	jobs := make(chan job)
	// pending holds each dispatched job's result channel in input order.
	pending := make(chan chan []dnsq.Row, 2*workers)

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for j := range jobs {
				j.out <- lookup(ctx, j.input)
			}
		})
	}
	go func() {
		defer close(pending)
		defer close(jobs)
		for input, ok := first, true; ok; input, ok = next() {
			out := make(chan []dnsq.Row, 1)
			select {
			case jobs <- job{input, out}:
			case <-ctx.Done():
				return
			}
			select {
			case pending <- out:
			case <-ctx.Done():
				return
			}
		}
	}()

	var err error
	for out := range pending {
		rows := <-out
		if err == nil {
			if err = emit(rows); err != nil {
				cancel()
			}
		}
	}
	wg.Wait()
	return err
}

// inputSource yields domains from args, then from r (a file or stdin).
type inputSource struct {
	args  []string
	r     io.Reader
	desc  string
	close func()
	err   error // set once r fails to read
}

// openInputs picks the input sources. Args alone are used unless --file was
// set explicitly. It returns nil when input would come from an interactive
// terminal.
func openInputs(cmd *cobra.Command, args []string) (*inputSource, error) {
	src := &inputSource{args: args, desc: "args", close: func() {}}
	fileSet := cmd.Flags().Changed("file") || viper.IsSet("file") && viper.GetString("file") != "-"
	if len(args) > 0 && !fileSet {
		return src, nil
	}
	path := viper.GetString("file")
	if path == "-" || path == "" {
		r := cmd.InOrStdin()
		if isTerminal(r) {
			if len(args) > 0 {
				return src, nil
			}
			return nil, nil
		}
		src.r, src.desc = r, "stdin"
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		src.r, src.desc, src.close = f, path, func() { _ = f.Close() }
	}
	if len(args) > 0 {
		src.desc = "args + " + src.desc
	}
	return src, nil
}

func (s *inputSource) all(yield func(string) bool) {
	for _, a := range s.args {
		if !yield(a) {
			return
		}
	}
	if s.r == nil {
		return
	}
	sc := bufio.NewScanner(s.r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !yield(strings.Fields(line)[0]) {
			return
		}
	}
	s.err = sc.Err()
}

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// resolveServers normalizes each server in list (see dnsq.ParseServer),
// defaulting to every nameserver in /etc/resolv.conf in order.
func resolveServers(list []string) ([]string, error) {
	var out []string
	for _, s := range list {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		addr, err := dnsq.ParseServer(s)
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	if len(out) > 0 {
		return out, nil
	}
	cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("no --server given and /etc/resolv.conf unreadable: %w", err)
	}
	if len(cc.Servers) == 0 {
		return nil, errors.New("no --server given and no nameserver in /etc/resolv.conf")
	}
	for _, s := range cc.Servers {
		out = append(out, net.JoinHostPort(s, cc.Port))
	}
	return out, nil
}

func printConfig(w io.Writer, res *dnsq.Resolver, types []uint16, input string, concurrency, cacheSize int, anchors, format, outPath string, fields []dnsq.Field) {
	proto := "udp (tcp on truncation)"
	if res.TCP {
		proto = "tcp"
	}
	encrypted := slices.ContainsFunc(res.Servers, func(s string) bool { return strings.Contains(s, "://") })
	plain := slices.ContainsFunc(res.Servers, func(s string) bool { return !strings.Contains(s, "://") })
	switch {
	case encrypted && !plain:
		proto = "encrypted, per server (tls, https or quic)"
	case encrypted:
		proto += " for plain servers; tls://, https:// and quic:// servers use their own"
	}
	cfg := viper.ConfigFileUsed()
	if cfg == "" {
		cfg = "(none)"
	}
	dest := outPath
	if dest == "" {
		dest = "stdout"
	}
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = f.Name
	}
	tw := tabwriter.NewWriter(w, 0, 0, 1, ' ', 0)
	fmt.Fprintf(tw, "config:\t%s\n", cfg)
	fmt.Fprintf(tw, "servers:\t%s\n", strings.Join(res.Servers, ", "))
	fmt.Fprintf(tw, "protocol:\t%s\n", proto)
	fmt.Fprintf(tw, "timeout:\t%s\n", res.Timeout)
	fmt.Fprintf(tw, "retries:\t%d\n", res.Retries)
	if res.Limiter != nil {
		fmt.Fprintf(tw, "rate:\t%g queries/s\n", float64(res.Limiter.Limit()))
	} else {
		fmt.Fprintf(tw, "rate:\tunlimited\n")
	}
	if cacheSize > 0 {
		fmt.Fprintf(tw, "cache:\t%d responses\n", cacheSize)
	} else {
		fmt.Fprintf(tw, "cache:\toff\n")
	}
	if slices.ContainsFunc(res.Servers, func(s string) bool { return strings.Contains(s, "://") }) {
		if res.TLSConfig != nil && res.TLSConfig.InsecureSkipVerify {
			fmt.Fprintf(tw, "certificates:\tNOT checked (--tls-insecure)\n")
		} else if ca := viper.GetString("tls-ca"); ca != "" {
			fmt.Fprintf(tw, "certificates:\tchecked (system CAs and %s)\n", ca)
		} else {
			fmt.Fprintf(tw, "certificates:\tchecked (system CAs)\n")
		}
	}
	if viper.GetBool("check-nameservers") {
		if res.IPv6 {
			fmt.Fprintf(tw, "nameservers:\tIPv4 and IPv6 addresses\n")
		} else {
			fmt.Fprintf(tw, "nameservers:\tIPv4 addresses only (--ipv6 adds IPv6)\n")
		}
	}
	if viper.GetBool("dns-posture") {
		fmt.Fprintf(tw, "mode:\tdns posture (MX, SPF, DMARC, DKIM, NS, CAA; organizational-domain fallback)\n")
	}
	if viper.GetBool("compare-servers") {
		fmt.Fprintf(tw, "mode:\tcompare servers (every server asked, no failover, no cache)\n")
	}
	if res.ECS != nil {
		fmt.Fprintf(tw, "ecs:\t%s/%d\n", res.ECS.Address, res.ECS.SourceNetmask)
	}
	if res.Validator != nil {
		fmt.Fprintf(tw, "dnssec:\tvalidating (%s)\n", anchors)
	} else {
		fmt.Fprintf(tw, "dnssec:\toff\n")
	}
	typeNames := make([]string, len(types))
	for i, t := range types {
		typeNames[i] = dnsq.TypeString(t)
	}
	fmt.Fprintf(tw, "type:\t%s\n", strings.Join(typeNames, ","))
	fmt.Fprintf(tw, "input:\t%s\n", input)
	fmt.Fprintf(tw, "concurrency:\t%d\n", concurrency)
	fmt.Fprintf(tw, "output:\t%s -> %s\n", format, dest)
	fmt.Fprintf(tw, "fields:\t%s\n", strings.Join(names, ","))
	if m := viper.GetStringSlice("match-fields"); len(m) > 0 {
		fmt.Fprintf(tw, "match-fields:\t%s\n", strings.Join(m, " ; "))
	}
	if a := viper.GetStringSlice("is-authoritative"); len(a) > 0 {
		fmt.Fprintf(tw, "is-authoritative:\t%s\n", strings.Join(a, ","))
	}
	if viper.GetBool("try-to-resolve") {
		fmt.Fprintf(tw, "try-to-resolve:\ttrue\n")
	}
	tw.Flush()
}
