//go:build !excel

package dnsq

import (
	"errors"
	"io"
)

// ExcelAvailable reports whether this build includes Excel output. This
// build does not; build with -tags excel to add it (it pulls in excelize,
// several MB).
const ExcelAvailable = false

func newExcelWriter(io.Writer, []Field) (RowWriter, error) {
	return nil, errors.New("excel output is not included in this build")
}
