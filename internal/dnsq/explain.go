package dnsq

import (
	"fmt"
	"strings"
)

// Explain returns a plain-language description of a result row.
func Explain(r Row) string {
	if r.NS != "" {
		return explainCheck(r)
	}
	r.Name, r.Zone = host(r.Name), host(r.Zone)
	var s string
	switch r.Status {
	case StatusNoError:
		s = explainRecord(r)
		if r.HasTTL {
			s += fmt.Sprintf(" Resolvers may cache it for up to %d seconds.", r.TTL)
		}
	case StatusNoData:
		if r.Type == "CNAME" && r.QType != "CNAME" {
			s = explainRecord(r) + fmt.Sprintf(" The alias target has no %s records (NODATA, RFC 2308).", r.QType)
		} else {
			s = fmt.Sprintf("%s exists but has no %s records (NODATA, RFC 2308).", r.Name, r.QType)
		}
		s += negativeCache(r)
	case "NXDOMAIN":
		s = fmt.Sprintf("%s does not exist (NXDOMAIN, RFC 2308); no record of any type exists at this name.", r.Name)
		s += negativeCache(r)
	case "SERVFAIL":
		s = "The resolver could not produce an answer (SERVFAIL). Common causes are DNSSEC validation failures and unreachable or misconfigured authoritative servers."
	case "REFUSED":
		s = fmt.Sprintf("%s refused the query (REFUSED); it may not offer recursion to this client.", r.Server)
	case StatusError:
		s = fmt.Sprintf("No usable response for %s from %s: %s. Check the network and server address, or raise --timeout.", r.Name, r.Server, r.Error)
	default:
		s = fmt.Sprintf("The server answered with response code %s.", r.Status)
	}
	if r.EDE != "" {
		s += " The server added an extended error (RFC 8914): " + r.EDE + "."
	}
	switch r.DNSSEC {
	case SecSecure:
		s += " DNSSEC: authenticated by a chain of signatures from the root trust anchor (secure)."
	case SecInsecure:
		s += " DNSSEC: the zone is provably unsigned (insecure), so the answer cannot be authenticated: " + r.DNSSECReason + "."
	case SecBogus:
		s += " DNSSEC: validation failed (bogus): " + r.DNSSECReason + ". A validating resolver would refuse this answer."
	}
	return s
}

// explainCheck describes a --check-nameservers row.
func explainCheck(r Row) string {
	who := fmt.Sprintf("Nameserver %s (%s)", host(r.NS), r.Server)
	if r.Server == "" {
		who = "Nameserver " + host(r.NS)
	}
	switch {
	case r.Skipped:
		return who + " was skipped: the query never left this machine (" + strings.TrimPrefix(r.Check, "skipped: ") + "), so nothing is known about the server."
	case r.Check == "":
		return fmt.Sprintf("%s answers authoritatively for %s with serial %d and agrees with the other nameservers.", who, host(r.Zone), r.Serial)
	case strings.HasPrefix(r.Check, "lame"):
		return who + " is lame: it is listed as a nameserver for " + host(r.Zone) + " but does not answer authoritatively for it. Resolvers that pick it get errors or delays."
	case strings.Contains(r.Check, "serial"):
		return who + " serves a different version of the zone than most nameservers (" + r.Check + "). Zone transfers to it may be failing."
	case strings.Contains(r.Check, "answer differs"):
		return who + " gives a different answer than most nameservers, so what users get depends on which server their resolver asks."
	}
	return who + ": " + r.Check + "."
}

func negativeCache(r Row) string {
	if !r.HasTTL || r.Type != r.QType {
		return ""
	}
	return fmt.Sprintf(" Resolvers may cache this negative answer for %d seconds (zone %s).", r.TTL, r.Zone)
}

func explainRecord(r Row) string {
	f := strings.Fields(r.Value)
	arg := func(i int) string {
		if i < len(f) {
			return host(f[i])
		}
		return ""
	}
	switch r.Type {
	case "A":
		return fmt.Sprintf("%s has IPv4 address %s.", r.Name, r.Value)
	case "AAAA":
		return fmt.Sprintf("%s has IPv6 address %s.", r.Name, r.Value)
	case "CNAME":
		return fmt.Sprintf("%s is an alias for %s.", r.Name, host(r.Value))
	case "MX":
		return fmt.Sprintf("Mail for %s is delivered to %s (preference %s; lower is tried first).", r.Name, arg(1), arg(0))
	case "NS":
		return fmt.Sprintf("%s is served by name server %s.", r.Name, host(r.Value))
	case "PTR":
		return fmt.Sprintf("%s points back to host name %s (reverse DNS).", r.Name, host(r.Value))
	case "SOA":
		return fmt.Sprintf("%s is a zone apex; primary server (MNAME) %s, contact %s, serial %s.", r.Name, arg(0), arg(1), arg(2))
	case "TXT":
		kind := "a text record"
		switch v := strings.ToLower(strings.Trim(r.Value, `"`)); {
		case strings.HasPrefix(v, "v=spf1"):
			kind = "an SPF policy (allowed mail senders)"
		case strings.HasPrefix(v, "v=dmarc1"):
			kind = "a DMARC policy"
		case strings.HasPrefix(v, "v=dkim1"):
			kind = "a DKIM public key"
		}
		return fmt.Sprintf("%s publishes %s: %s.", r.Name, kind, r.Value)
	case "SRV":
		return fmt.Sprintf("Service %s is provided by %s port %s (priority %s, weight %s).", r.Name, arg(3), arg(2), arg(0), arg(1))
	case "CAA":
		return fmt.Sprintf("%s restricts certificate issuance: %s.", r.Name, r.Value)
	}
	return fmt.Sprintf("%s has a %s record: %s.", r.Name, r.Type, r.Value)
}

// host drops the trailing root dot so names read naturally in sentences.
func host(name string) string {
	if name == "." {
		return name
	}
	return strings.TrimSuffix(name, ".")
}
