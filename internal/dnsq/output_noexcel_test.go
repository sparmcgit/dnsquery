//go:build !excel

package dnsq

import (
	"strings"
	"testing"
)

func TestExcelLeftOut(t *testing.T) {
	for _, spec := range []string{"excel", "EXCEL", "out.xlsx"} {
		if _, _, err := ResolveOutput(spec); err == nil || !strings.Contains(err.Error(), "-tags excel") {
			t.Errorf("%s: want a rebuild hint, got %v", spec, err)
		}
	}
	if _, err := NewWriter(nil, "excel", nil); err == nil {
		t.Error("the excel writer must fail in this build")
	}
}
