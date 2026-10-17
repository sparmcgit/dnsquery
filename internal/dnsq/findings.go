package dnsq

import (
	"net/netip"
	"strings"
)

// takeoverProviders are hosting services where a name under the suffix
// is claimed by whoever registers it first, so a CNAME to such a name
// that no longer exists can be taken over. Suffixes are matched on label
// boundaries.
var takeoverProviders = []struct{ suffix, name string }{
	{"azurewebsites.net", "Azure App Service"},
	{"cloudapp.net", "Azure Cloud Services"},
	{"cloudapp.azure.com", "Azure virtual machines"},
	{"trafficmanager.net", "Azure Traffic Manager"},
	{"blob.core.windows.net", "Azure Blob Storage"},
	{"azureedge.net", "Azure CDN"},
	{"azure-api.net", "Azure API Management"},
	{"azurecontainer.io", "Azure Container Instances"},
	{"azurestaticapps.net", "Azure Static Web Apps"},
	{"elasticbeanstalk.com", "AWS Elastic Beanstalk"},
	{"s3.amazonaws.com", "Amazon S3"},
	{"github.io", "GitHub Pages"},
	{"herokuapp.com", "Heroku"},
	{"herokudns.com", "Heroku"},
	{"netlify.app", "Netlify"},
	{"pantheonsite.io", "Pantheon"},
	{"surge.sh", "Surge"},
	{"bitbucket.io", "Bitbucket"},
	{"readthedocs.io", "Read the Docs"},
	{"ngrok.io", "ngrok"},
}

// takeoverProvider returns the hosting service name belongs to, or "".
func takeoverProvider(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, p := range takeoverProviders {
		if name == p.suffix || strings.HasSuffix(name, "."+p.suffix) {
			return p.name
		}
	}
	// S3 website and regional endpoints: bucket.s3-website-eu-west-1.amazonaws.com,
	// bucket.s3.eu-west-1.amazonaws.com, ...
	if labels := strings.Split(name, "."); strings.HasSuffix(name, ".amazonaws.com") {
		for _, l := range labels[1:] {
			if l == "s3" || strings.HasPrefix(l, "s3-") {
				return "Amazon S3"
			}
		}
	}
	return ""
}

// AddFindings sets the check field of rows from one Lookup (--findings):
// a CNAME whose target does not exist (a dangling alias, which others may
// be able to claim), and A/AAAA answers with private or reserved
// addresses. Rows that already have a check are left alone. No queries
// are sent: everything comes from the answer.
func AddFindings(rows []Row) {
	for i := range rows {
		if rows[i].Check != "" {
			continue
		}
		switch {
		case rows[i].Type == "CNAME" && rows[i].Status == "NXDOMAIN" && rows[i].QType != "CNAME":
			rows[i].Check = danglingCNAME(rows, i)
		case (rows[i].Type == "A" || rows[i].Type == "AAAA") && rows[i].Status == StatusNoError:
			rows[i].Check = reservedAddress(rows[i])
		}
	}
}

// danglingCNAME describes rows[i] when it is the CNAME whose target does
// not exist: the end of the chain, not owner of any record in the answer.
// The response is NXDOMAIN for the target (RFC 6604 section 2.1).
func danglingCNAME(rows []Row, i int) string {
	target := strings.TrimSpace(rows[i].Value)
	for _, r := range rows {
		if strings.EqualFold(r.Name, target) {
			return "" // an earlier link of the chain
		}
	}
	alias := strings.TrimSuffix(rows[i].Name, ".")
	t := strings.TrimSuffix(target, ".")
	if p := takeoverProvider(target); p != "" {
		return "high: dangling CNAME: " + alias + " points to " + t + ", which does not exist (NXDOMAIN); whoever creates that name at " + p + " controls " + alias + " (subdomain takeover)"
	}
	return "medium: dangling CNAME: " + alias + " points to " + t + ", which does not exist (NXDOMAIN); if someone else can register that name or its domain, they control " + alias
}

// internalSuffixes are names that are not meant to be public, so private
// addresses under them are expected (RFC 6761, RFC 6762, RFC 8375, and
// ICANN's .internal).
var internalSuffixes = []string{"local", "localhost", "internal", "home.arpa", "lan", "corp", "home"}

var (
	sharedPrefix          = netip.MustParsePrefix("100.64.0.0/10")
	documentationPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	// Future use (240/4), benchmarking (RFC 2544) and IETF protocol
	// assignments (RFC 6890).
	reservedPrefixes = []netip.Prefix{netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("192.0.0.0/24")}
)

// reservedAddress describes an A/AAAA row whose address is not a public
// unicast address, or "" for a public one.
func reservedAddress(r Row) string {
	name := strings.ToLower(strings.TrimSuffix(r.Name, "."))
	for _, s := range internalSuffixes {
		if name == s || strings.HasSuffix(name, "."+s) {
			return ""
		}
	}
	a, err := netip.ParseAddr(strings.TrimSpace(r.Value))
	if err != nil {
		return ""
	}
	a = a.Unmap()
	in := func(prefixes ...netip.Prefix) bool {
		for _, p := range prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	switch {
	case a.IsUnspecified():
		return "low: unspecified address " + a.String() + ": usually a resolver or blocklist blocking the name"
	case a.IsLoopback():
		return "low: loopback address " + a.String() + ": often a resolver or blocklist blocking the name, or a placeholder; it can also be abused against local services"
	case a.IsPrivate():
		return "low: private address " + a.String() + " (RFC 1918/4193) in a public answer: an internal host name leaks, or a split-horizon mistake; it can also be used for DNS rebinding"
	case a.IsLinkLocalUnicast():
		return "low: link-local address " + a.String() + " in a public answer: unreachable from elsewhere, and 169.254.169.254 is the cloud metadata service"
	case in(sharedPrefix):
		return "low: shared address " + a.String() + " (carrier-grade NAT, RFC 6598) in a public answer: not reachable from the Internet"
	case in(documentationPrefixes...):
		return "low: documentation address " + a.String() + " (RFC 5737/3849): a placeholder that was never replaced"
	case a.IsMulticast(), in(reservedPrefixes...):
		return "low: reserved address " + a.String() + " in a public answer: not a normal Internet host"
	}
	return ""
}
