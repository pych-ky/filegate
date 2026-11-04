// Package inspect validates formats inside the isolated inspection VM.
package inspect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
	"unicode/utf8"
)

const (
	InputLimit = int64(250 << 20)
	FileLimit  = int64(100 << 20)
	TotalLimit = int64(1 << 30)
	EntryLimit = 10000
)

type Metadata struct {
	DisplayName       string `json:"display_name,omitempty"`
	DeclaredMediaType string `json:"declared_media_type,omitempty"`
	ExpectedType      string `json:"expected_type,omitempty"`
}

type Object struct {
	ID                string `json:"object_id"`
	ParentID          string `json:"parent_id,omitempty"`
	Kind              string `json:"kind"`
	Format            string `json:"format,omitempty"`
	SHA256            string `json:"sha256,omitempty"`
	ByteSize          int64  `json:"byte_size"`
	AVRequired        bool   `json:"av_required"`
	AVExclusionReason string `json:"av_exclusion_reason,omitempty"`
	Path              string `json:"path,omitempty"`
}

type Rejection struct {
	ObjectID   string `json:"object_id"`
	ReasonCode string `json:"reason_code"`
}

type Result struct {
	SchemaVersion           int         `json:"schema_version"`
	StructureStatus         string      `json:"structure_status"`
	StructureChecksComplete bool        `json:"structure_checks_complete"`
	FormatChecksComplete    bool        `json:"format_checks_complete"`
	RequiredChecksComplete  bool        `json:"required_checks_complete"`
	Reasons                 []string    `json:"reason_codes"`
	Checks                  []string    `json:"completed_checks"`
	ArchiveEntryCount       int         `json:"archive_entry_count"`
	ExtractedFileCount      int         `json:"extracted_file_count"`
	RequiredAVInputCount    int         `json:"required_av_input_count"`
	ExtractedBytes          int64       `json:"extracted_bytes"`
	Manifest                []Object    `json:"manifest"`
	ConfirmedRejections     []Rejection `json:"confirmed_rejections"`
}

type failure struct{ reason string }

func (f failure) Error() string { return f.reason }
func fail(reason string) error  { return failure{reason} }

type inspector struct {
	ctx      context.Context
	result   Result
	work     *os.Root
	sequence int
	formats  bool
}

func newInspector(ctx context.Context) *inspector {
	return &inspector{ctx: ctx, result: Result{SchemaVersion: 1, StructureStatus: "HOLD", Reasons: []string{}, Checks: []string{}, Manifest: []Object{}, ConfirmedRejections: []Rejection{}}}
}

func (v *inspector) finish(err error, status string) Result {
	if err == nil && v.work != nil {
		var dir *os.File
		dir, err = v.work.Open(".")
		if err == nil {
			err = dir.Sync()
			closeErr := dir.Close()
			if err == nil {
				err = closeErr
			}
		}
	}
	if err != nil {
		var f failure
		reason := "WORKSPACE_IO_ERROR"
		if errors.As(err, &f) {
			reason = f.reason
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			reason = "SCAN_TIMEOUT"
		}
		v.result.Reasons = []string{reason}
		if reason == "UNSAFE_ARCHIVE_PATH" || reason == "ARCHIVE_NAME_COLLISION" || reason == "ARCHIVE_PATH_TYPE_CONFLICT" {
			v.result.StructureStatus = "BLOCK"
		}
		return v.result
	}
	v.result.StructureStatus = status
	v.result.StructureChecksComplete = true
	v.result.FormatChecksComplete = v.formats
	return v.result
}

func (v *inspector) id() string {
	v.sequence++
	return fmt.Sprintf("object_%06d", v.sequence)
}

// Inspect checks supported formats, but never runs AV or produces a PASS verdict.
func Inspect(ctx context.Context, inputPath string, metadata Metadata, workdir string) Result {
	v := newInspector(ctx)
	v.formats = true
	f, err := os.Open(inputPath)
	if err != nil {
		return v.finish(err, "")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return v.finish(err, "")
	}
	if !st.Mode().IsRegular() {
		return v.finish(fail("UNSUPPORTED_FORMAT"), "")
	}
	v.work, err = os.OpenRoot(workdir)
	if err != nil {
		return v.finish(err, "")
	}
	defer v.work.Close()
	err = v.object(f, st.Size(), metadata, "", "", 0)
	return v.finish(err, "ACCEPT_FORMAT_STRUCTURE")
}

// ValidateZIP isolates ZIP responsibilities from the contained format adapters.
func ValidateZIP(ctx context.Context, r io.ReaderAt, size int64, workdir string) Result {
	v := newInspector(ctx)
	var err error
	v.work, err = os.OpenRoot(workdir)
	if err != nil {
		return v.finish(err, "")
	}
	defer v.work.Close()
	err = v.object(r, size, Metadata{ExpectedType: "zip"}, "", "", 0)
	return v.finish(err, "ACCEPT_ZIP_STRUCTURE")
}

func ValidateTXT(ctx context.Context, r io.Reader, size int64, metadata Metadata) Result {
	v := newInspector(ctx)
	v.formats = true
	if size < 0 || size > InputLimit {
		return v.finish(fail("LIMIT_EXCEEDED"), "")
	}
	if err := matchingMetadata(metadata, "txt"); err != nil {
		return v.finish(err, "")
	}
	h := sha256.New()
	err := text(ctx, io.TeeReader(r, h), size)
	if err == nil {
		v.result.Manifest = append(v.result.Manifest, Object{ID: v.id(), Kind: "regular_file", Format: "txt", SHA256: hex.EncodeToString(h.Sum(nil)), ByteSize: size, AVRequired: true})
		v.result.RequiredAVInputCount = 1
		v.result.Checks = append(v.result.Checks, "txt-encoding", "txt-controls", "txt-identification", "declared-type")
	}
	return v.finish(err, "ACCEPT_TXT_STRUCTURE")
}

func (v *inspector) object(r io.ReaderAt, size int64, metadata Metadata, parent, stored string, depth int) error {
	if size < 0 || size > InputLimit {
		return fail("LIMIT_EXCEEDED")
	}
	prefix := make([]byte, min(size, 8))
	if _, err := r.ReadAt(prefix, 0); err != nil && err != io.EOF {
		return err
	}
	zip := bytes.HasPrefix(prefix, []byte("PK\x03\x04")) || bytes.HasPrefix(prefix, []byte("PK\x05\x06"))
	if !zip && v.formats && size >= 22 {
		end := make([]byte, 4)
		if _, err := r.ReadAt(end, size-22); err != nil {
			return err
		}
		zip = bytes.Equal(end, []byte("PK\x05\x06"))
	}
	if !v.formats && parent != "" {
		// Structure fixtures name nested containers; member magic belongs to the format adapter.
		zip = strings.EqualFold(path.Ext(metadata.DisplayName), ".zip")
	}
	if metadata.ExpectedType == "zip" && !zip && !v.formats {
		// The ZIP-only contract also validates inputs with damaged identifying bytes.
		zip = true
	}
	kind := "regular_file"
	format := "txt"
	if zip {
		kind, format = "container", "zip"
	} else if v.formats && bytes.Equal(prefix, []byte("\x89PNG\r\n\x1a\n")) {
		format = "png"
	} else if v.formats && bytes.HasPrefix(prefix, []byte{0xff, 0xd8}) {
		format = "jpeg"
	}
	if !zip && v.formats || parent == "" && !v.formats {
		if err := matchingMetadata(metadata, format); err != nil {
			return err
		}
	}
	h := sha256.New()
	n, err := copyContext(v.ctx, h, io.NewSectionReader(r, 0, size))
	if err != nil {
		return err
	}
	if n != size {
		return fail("WORKSPACE_IO_ERROR")
	}
	id := v.id()
	object := Object{ID: id, ParentID: parent, Kind: kind, SHA256: hex.EncodeToString(h.Sum(nil)), ByteSize: size, AVRequired: true, Path: stored}
	if zip || v.formats {
		object.Format = format
	}
	v.result.Manifest = append(v.result.Manifest, object)
	v.result.RequiredAVInputCount++
	if zip {
		if depth > 3 {
			return fail("LIMIT_EXCEEDED")
		}
		return v.zip(r, size, id, depth, metadata)
	}
	if v.formats {
		checks := []string{"txt-encoding", "txt-controls", "txt-identification", "declared-type"}
		if format == "png" || format == "jpeg" {
			if err := validateImage(v.ctx, r, size, format); err != nil {
				return err
			}
			checks = []string{"image-structure", "image-decode", "declared-type"}
		} else {
			if err := text(v.ctx, io.NewSectionReader(r, 0, size), size); err != nil {
				return err
			}
		}
		v.addChecks(checks...)
	}
	return nil
}

func (v *inspector) addChecks(checks ...string) {
	for _, check := range checks {
		found := false
		for _, completed := range v.result.Checks {
			found = found || completed == check
		}
		if !found {
			v.result.Checks = append(v.result.Checks, check)
		}
	}
}

func matchingMetadata(m Metadata, format string) error {
	if m.ExpectedType != "" && m.ExpectedType != format {
		return fail("UNEXPECTED_ARTIFACT_TYPE")
	}
	ext := strings.ToLower(path.Ext(m.DisplayName))
	if ext != "" && ext != "."+format && !(format == "jpeg" && ext == ".jpg") {
		return fail("UNSUPPORTED_FORMAT")
	}
	if m.DeclaredMediaType == "" {
		return nil
	}
	media, params, err := mime.ParseMediaType(m.DeclaredMediaType)
	if err != nil {
		return fail("UNSUPPORTED_FORMAT")
	}
	if media != "application/octet-stream" && media != map[string]string{"txt": "text/plain", "zip": "application/zip", "png": "image/png", "jpeg": "image/jpeg",
		"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}[format] {
		return fail("UNSUPPORTED_FORMAT")
	}
	for name, value := range params {
		if format != "txt" || name != "charset" || !strings.EqualFold(value, "utf-8") {
			return fail("UNSUPPORTED_FORMAT")
		}
	}
	return nil
}

func text(ctx context.Context, input io.Reader, size int64) error {
	r := bufio.NewReader(io.LimitReader(input, size+1))
	prefix, err := r.Peek(512)
	if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
		return err
	}
	probe := bytes.TrimPrefix(prefix, []byte{0xef, 0xbb, 0xbf})
	if bytes.HasPrefix(probe, []byte("#!")) {
		return fail("UNSUPPORTED_FORMAT")
	}
	if len(probe) != 0 && !strings.HasPrefix(http.DetectContentType(probe), "text/plain") {
		return fail("UNSUPPORTED_FORMAT")
	}
	var n int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c, width, err := r.ReadRune()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		n += int64(width)
		if n > size || (c == utf8.RuneError && width == 1) || (c < 32 && c != '\t' && c != '\n' && c != '\r') || c == 127 {
			return fail("UNSUPPORTED_FORMAT")
		}
	}
	if n != size {
		return fail("WORKSPACE_IO_ERROR")
	}
	return nil
}

func copyContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := src.Read(buf)
		if n > 0 {
			written, writeErr := dst.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}
