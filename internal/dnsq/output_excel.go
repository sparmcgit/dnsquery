//go:build excel

package dnsq

import (
	"io"

	"github.com/xuri/excelize/v2"
)

// ExcelAvailable reports whether this build includes Excel output; it is
// built with -tags excel, which pulls in excelize (several MB).
const ExcelAvailable = true

// excelWriter uses excelize's stream writer, which spills rows to a
// temporary file instead of keeping the sheet in memory.
type excelWriter struct {
	w      io.Writer
	x      *excelize.File
	sw     *excelize.StreamWriter
	fields []Field
	n      int
}

func newExcelWriter(w io.Writer, fields []Field) (*excelWriter, error) {
	const sheet = "dnsquery"
	x := excelize.NewFile()
	e := &excelWriter{w: w, x: x, fields: fields}
	err := x.SetSheetName("Sheet1", sheet)
	if err == nil {
		e.sw, err = x.NewStreamWriter(sheet)
	}
	if err == nil {
		err = e.sw.SetPanes(&excelize.Panes{Freeze: true, YSplit: 1, TopLeftCell: "A2", ActivePane: "bottomLeft"})
	}
	if err == nil {
		header := make([]any, len(fields))
		for i, f := range fields {
			header[i] = f.Name
		}
		err = e.sw.SetRow("A1", header)
	}
	if err != nil {
		_ = x.Close()
		return nil, err
	}
	return e, nil
}

func (e *excelWriter) WriteRow(r Row) error {
	vals := make([]any, len(e.fields))
	for i, f := range e.fields {
		vals[i] = f.get(r)
	}
	e.n++
	cell, err := excelize.CoordinatesToCellName(1, e.n+1)
	if err != nil {
		return err
	}
	return e.sw.SetRow(cell, vals)
}

func (e *excelWriter) Close() error {
	defer func() { _ = e.x.Close() }()
	if err := e.sw.Flush(); err != nil {
		return err
	}
	return e.x.Write(e.w)
}
