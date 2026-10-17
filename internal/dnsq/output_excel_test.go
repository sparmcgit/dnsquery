//go:build excel

package dnsq

import (
	"bytes"
	"testing"
)

func TestExcelOutput(t *testing.T) {
	fields, _ := SelectFields([]string{"name", "ttl"}, FieldOptions{})
	var b bytes.Buffer
	if err := Write(&b, "excel", fields, []Row{{Name: "a.", TTL: 1, HasTTL: true}}); err != nil || !bytes.HasPrefix(b.Bytes(), []byte("PK")) {
		t.Errorf("excel: not a zip, %v", err)
	}
	if f, path, err := ResolveOutput("out.XLSX"); err != nil || f != "excel" || path != "out.XLSX" {
		t.Errorf("ResolveOutput(out.XLSX) = %q, %q, %v", f, path, err)
	}
}
