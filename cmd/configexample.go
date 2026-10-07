package cmd

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"go.yaml.in/yaml/v3"
)

const configExampleHeader = `# dnsquery example configuration.
#
# Save as ~/.dnsquery.yaml or pass with --config. Every key is a flag name;
# precedence is flag > environment (DNSQUERY_<NAME>, - as _) > this file >
# default. Values below are the defaults; commented keys have no default.
`

// configExampleSkip lists flags that trigger an action rather than set a
// value, so they do not belong in a config file.
var configExampleSkip = map[string]bool{
	"help":           true,
	"config":         true,
	"config-example": true,
	"list-fields":    true,
}

// configExampleValues gives example values, written commented out, for
// settings whose default is empty.
var configExampleValues = map[string]string{
	"server":           "[192.0.2.53, 192.0.2.54]",
	"output":           "results.csv",
	"select-fields":    "[query, status, name, type, ttl, value, server]",
	"match-fields":     `["status=NOERROR&&value=mx|mail"]`,
	"is-authoritative": "[ns1.example.com]",
	"trust-anchor":     "/etc/dnsquery/root-anchors.txt",
	"tls-ca":           "/etc/dnsquery/private-ca.pem",
	"ecs":              "192.0.2.0/24",
}

// writeConfigExample writes a YAML config listing every setting in fs with
// its help text and default value.
func writeConfigExample(w io.Writer, fs *pflag.FlagSet) error {
	var b strings.Builder
	b.WriteString(configExampleHeader)
	var err error
	fs.VisitAll(func(f *pflag.Flag) {
		if err != nil || f.Hidden || configExampleSkip[f.Name] {
			return
		}
		fmt.Fprintf(&b, "\n# %s\n", f.Usage)
		if f.DefValue == "" || f.DefValue == "[]" {
			ex, ok := configExampleValues[f.Name]
			if !ok {
				err = fmt.Errorf("config example: no example value for --%s", f.Name)
				return
			}
			fmt.Fprintf(&b, "# %s: %s\n", f.Name, ex)
			return
		}
		var v string
		if v, err = yamlDefault(f); err == nil {
			fmt.Fprintf(&b, "%s: %s\n", f.Name, v)
		}
	})
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, b.String())
	return err
}

// yamlDefault renders a flag's default as a YAML value of the right type.
func yamlDefault(f *pflag.Flag) (string, error) {
	var v any
	var err error
	switch f.Value.Type() {
	case "bool":
		v, err = strconv.ParseBool(f.DefValue)
	case "int":
		v, err = strconv.Atoi(f.DefValue)
	case "float64":
		v, err = strconv.ParseFloat(f.DefValue, 64)
	case "stringSlice":
		var items []string
		for s := range strings.SplitSeq(strings.Trim(f.DefValue, "[]"), ",") {
			q, e := scalar(s)
			if e != nil {
				return "", e
			}
			items = append(items, q)
		}
		return "[" + strings.Join(items, ", ") + "]", nil
	default: // string, duration
		v = f.DefValue
	}
	if err != nil {
		return "", fmt.Errorf("config example: default of --%s: %w", f.Name, err)
	}
	return scalar(v)
}

// scalar marshals v as a single YAML scalar, quoting it when needed
// (for example "-", which would otherwise start a sequence).
func scalar(v any) (string, error) {
	out, err := yaml.Marshal(v)
	return strings.TrimSpace(string(out)), err
}
