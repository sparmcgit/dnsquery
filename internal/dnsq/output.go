package dnsq

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"go.yaml.in/yaml/v3"
)

var formats = []string{"text", "yaml", "json", "csv", "excel"}

var extFormats = map[string]string{
	".txt":  "text",
	".yaml": "yaml",
	".yml":  "yaml",
	".json": "json",
	".csv":  "csv",
	".xlsx": "excel",
}

// ResolveOutput interprets --output: a format name writes to stdout (path is
// empty), anything else must be a file path with a known extension.
func ResolveOutput(spec string) (format, path string, err error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return "text", "", nil
	}
	for _, f := range formats {
		if strings.EqualFold(s, f) {
			return checkAvailable(f, "")
		}
	}
	if f, ok := extFormats[strings.ToLower(filepath.Ext(s))]; ok {
		return checkAvailable(f, s)
	}
	return "", "", fmt.Errorf("invalid --output %q: use text|yaml|json|csv|excel or a path ending in .txt, .yaml, .yml, .json, .csv or .xlsx", spec)
}

// checkAvailable rejects formats left out of this build, before any query
// is sent.
func checkAvailable(format, path string) (string, string, error) {
	if format == "excel" && !ExcelAvailable {
		return "", "", errors.New("excel output is not included in this build; rebuild with: go build -tags excel (or TAGS=excel ./compile)")
	}
	return format, path, nil
}

// RowWriter writes result rows one at a time, so output never needs the
// whole result set in memory.
type RowWriter interface {
	WriteRow(Row) error
	// Close completes the output. It does not close the underlying writer.
	Close() error
}

// NewWriter returns a RowWriter rendering fields in format to w.
func NewWriter(w io.Writer, format string, fields []Field) (RowWriter, error) {
	switch format {
	case "text":
		return newTextWriter(w, fields), nil
	case "json":
		return &jsonWriter{w: w, fields: fields}, nil
	case "yaml":
		return &yamlWriter{w: w, fields: fields}, nil
	case "csv":
		return newCSVWriter(w, fields)
	case "excel":
		return newExcelWriter(w, fields)
	}
	return nil, fmt.Errorf("unknown output format %q", format)
}

// Write renders rows in format to w.
func Write(w io.Writer, format string, fields []Field, rows []Row) error {
	rw, err := NewWriter(w, format, fields)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := rw.WriteRow(r); err != nil {
			return err
		}
	}
	return rw.Close()
}

// textBlockRows bounds how many rows the text writer buffers to align
// columns. Column widths may change between blocks of a long output.
const textBlockRows = 1000

type textWriter struct {
	tw     *tabwriter.Writer
	fields []Field
	cols   []string
	n      int
}

func newTextWriter(w io.Writer, fields []Field) *textWriter {
	t := &textWriter{tw: tabwriter.NewWriter(w, 0, 0, 2, ' ', 0), fields: fields, cols: make([]string, len(fields))}
	for i, f := range fields {
		t.cols[i] = strings.ToUpper(f.Name)
	}
	fmt.Fprintln(t.tw, strings.Join(t.cols, "\t"))
	return t
}

func (t *textWriter) WriteRow(r Row) error {
	for i, f := range t.fields {
		// Tabs inside values (e.g. TXT data) would break the columns.
		t.cols[i] = strings.ReplaceAll(f.String(r), "\t", " ")
	}
	if _, err := fmt.Fprintln(t.tw, strings.Join(t.cols, "\t")); err != nil {
		return err
	}
	if t.n++; t.n%textBlockRows == 0 {
		return t.tw.Flush()
	}
	return nil
}

func (t *textWriter) Close() error { return t.tw.Flush() }

// orderedRow marshals to a JSON object that keeps the selected field order.
type orderedRow struct {
	fields []Field
	row    Row
}

func (o orderedRow) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range o.fields {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(f.Name)
		v, err := json.Marshal(f.get(o.row))
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// jsonWriter streams a JSON array, one indented object per row.
type jsonWriter struct {
	w      io.Writer
	fields []Field
	n      int
}

func (j *jsonWriter) WriteRow(r Row) error {
	obj, err := json.MarshalIndent(orderedRow{j.fields, r}, "  ", "  ")
	if err != nil {
		return err
	}
	sep := ",\n  "
	if j.n == 0 {
		sep = "[\n  "
	}
	j.n++
	if _, err := io.WriteString(j.w, sep); err != nil {
		return err
	}
	_, err = j.w.Write(obj)
	return err
}

func (j *jsonWriter) Close() error {
	end := "\n]\n"
	if j.n == 0 {
		end = "[]\n"
	}
	_, err := io.WriteString(j.w, end)
	return err
}

// yamlWriter streams a YAML sequence by encoding each row as a one-item
// sequence; concatenated, they form a single sequence document.
type yamlWriter struct {
	w      io.Writer
	fields []Field
	n      int
}

func (y *yamlWriter) WriteRow(r Row) error {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, f := range y.fields {
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: f.Name}
		val := &yaml.Node{}
		if err := val.Encode(f.get(r)); err != nil {
			return err
		}
		m.Content = append(m.Content, key, val)
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{m}}
	enc := yaml.NewEncoder(y.w)
	enc.SetIndent(2)
	if err := enc.Encode(seq); err != nil {
		return err
	}
	y.n++
	return enc.Close()
}

func (y *yamlWriter) Close() error {
	if y.n == 0 {
		_, err := io.WriteString(y.w, "[]\n")
		return err
	}
	return nil
}

type csvWriter struct {
	cw     *csv.Writer
	fields []Field
	rec    []string
}

func newCSVWriter(w io.Writer, fields []Field) (*csvWriter, error) {
	c := &csvWriter{cw: csv.NewWriter(w), fields: fields, rec: make([]string, len(fields))}
	for i, f := range fields {
		c.rec[i] = f.Name
	}
	return c, c.cw.Write(c.rec)
}

func (c *csvWriter) WriteRow(r Row) error {
	for i, f := range c.fields {
		c.rec[i] = f.String(r)
	}
	return c.cw.Write(c.rec)
}

func (c *csvWriter) Close() error {
	c.cw.Flush()
	return c.cw.Error()
}
