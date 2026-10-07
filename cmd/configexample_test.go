package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// withoutConfigLine drops the "config:" line from --verbose output, the
// only line expected to differ between runs with and without a config.
func withoutConfigLine(s string) string {
	var keep []string
	for line := range strings.SplitSeq(s, "\n") {
		if !strings.HasPrefix(line, "config:") {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}

func TestConfigExampleListsEverySetting(t *testing.T) {
	out, _, err := execute(t, "", "--config-example")
	if err != nil {
		t.Fatal(err)
	}
	rootCmd.Flags().VisitAll(func(f *pflag.Flag) {
		key := regexp.MustCompile(`(?m)^(# )?` + regexp.QuoteMeta(f.Name) + `: `)
		if listed := key.MatchString(out); listed == configExampleSkip[f.Name] {
			t.Errorf("--%s: listed=%v, skipped=%v", f.Name, listed, configExampleSkip[f.Name])
		}
	})
}

func TestConfigExampleRoundTrip(t *testing.T) {
	server := startServer(t)
	example, _, err := execute(t, "", "--config-example")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "example.yaml")
	if err := os.WriteFile(cfg, []byte(example), 0o644); err != nil {
		t.Fatal(err)
	}

	// The example as printed changes nothing: it holds only defaults.
	_, withDefaults, err1 := execute(t, "", "a.test", "--server", server, "--verbose")
	_, withExample, err2 := execute(t, "", "a.test", "--server", server, "--verbose", "--config", cfg)
	if err1 != nil || err2 != nil || withoutConfigLine(withExample) != withoutConfigLine(withDefaults) {
		t.Errorf("example config changed settings (%v, %v):\n%s\nvs\n%s", err1, err2, withExample, withDefaults)
	}

	// Uncommented, the example values load with the right types. Flags
	// override the server and output so the run stays local.
	uncommented := regexp.MustCompile(`(?m)^# ([a-z-]+: )`).ReplaceAllString(example, "$1")
	if err := os.WriteFile(cfg, []byte(uncommented), 0o644); err != nil {
		t.Fatal(err)
	}
	_, verbose, err := execute(t, "", "test", "--server", server, "--output", "csv", "--type", "SOA", "--verbose", "--config", cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"fields:           query,status,name,type,ttl,value,server",
		"match-fields:     status=NOERROR&&value=mx|mail",
		"is-authoritative: ns1.example.com",
	} {
		if !strings.Contains(verbose, want) {
			t.Errorf("uncommented example: missing %q in:\n%s", want, verbose)
		}
	}
}

func TestConfigExampleNeedsExampleForEmptyDefaults(t *testing.T) {
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	fs.String("undocumented", "", "a setting with no default and no example")
	if err := writeConfigExample(&strings.Builder{}, fs); err == nil || !strings.Contains(err.Error(), "--undocumented") {
		t.Errorf("got %v, want missing-example error", err)
	}
}
