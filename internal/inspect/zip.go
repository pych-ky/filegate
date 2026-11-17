package inspect

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

type entry struct {
	name                                 string
	creator, needed, flags, method       uint16
	crc, compressed, uncompressed, attrs uint32
	local, data, end                     int64
	directory                            bool
	block                                string
	stored                               string
}

func u16(p []byte) uint16 { return binary.LittleEndian.Uint16(p) }
func u32(p []byte) uint32 { return binary.LittleEndian.Uint32(p) }

func readAt(r io.ReaderAt, offset, length, bound int64) ([]byte, error) {
	if offset < 0 || length < 0 || offset > bound || length > bound-offset {
		return nil, fail("ARCHIVE_CORRUPT")
	}
	p := make([]byte, length)
	if _, err := r.ReadAt(p, offset); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, fail("ARCHIVE_CORRUPT")
		}
		return nil, err
	}
	return p, nil
}

func (v *inspector) zip(r io.ReaderAt, size int64, parent string, depth int, metadata Metadata) error {
	entries, err := v.layout(r, size)
	if err != nil {
		return err
	}
	block := tree(entries)
	for _, e := range entries {
		if e.block != "" {
			block = e.block
		}
	}
	// Compare the standard reader's view before any decoding, independently of its CRC policy.
	standard, err := zip.NewReader(r, size)
	if err != nil && err != zip.ErrInsecurePath {
		return fail("ARCHIVE_CORRUPT")
	}
	if standard == nil || len(standard.File) != len(entries) {
		return fail("ARCHIVE_CORRUPT")
	}
	for i, e := range entries {
		f := standard.File[i]
		offset, err := f.DataOffset()
		if err != nil || offset != e.data || f.Name != e.name || f.Method != e.method || f.Flags != e.flags || f.ReaderVersion != e.needed || f.CreatorVersion != e.creator || f.ExternalAttrs != e.attrs || f.CRC32 != e.crc || f.CompressedSize64 != uint64(e.compressed) || f.UncompressedSize64 != uint64(e.uncompressed) {
			return fail("ARCHIVE_CORRUPT")
		}
	}
	for i := range entries {
		e := &entries[i]
		if e.directory {
			continue
		}
		if err := v.extract(r, e); err != nil {
			return err
		}
	}
	if block != "" {
		v.result.ConfirmedRejections = append(v.result.ConfirmedRejections, Rejection{ObjectID: parent, ReasonCode: block})
		return fail(block)
	}
	if v.formats {
		for _, e := range entries {
			if e.name == "[Content_Types].xml" && !e.directory {
				if err := v.ooxml(entries, parent, metadata); err != nil {
					return err
				}
				v.zipChecks()
				return nil
			}
		}
		if err := matchingMetadata(metadata, "zip"); err != nil {
			return err
		}
	}
	for _, e := range entries {
		if e.directory {
			v.result.Manifest = append(v.result.Manifest, Object{ID: v.id(), ParentID: parent, Kind: "verified_empty_directory", AVExclusionReason: "VERIFIED_EMPTY_DIRECTORY"})
			continue
		}
		f, err := v.work.Open(e.stored)
		if err != nil {
			return err
		}
		err = v.object(f, int64(e.uncompressed), Metadata{DisplayName: e.name}, parent, e.stored, depth+1)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if depth == 0 {
		v.zipChecks()
	}
	return nil
}

func (v *inspector) zipChecks() {
	v.addChecks("header-match", "intervals", "coverage", "crc-stream", "deflate-end", "entry-kind", "tree", "path-rules", "zip-profile", "limits", "manifest", "decoder-boundary")
}

func (v *inspector) layout(r io.ReaderAt, size int64) ([]entry, error) {
	end, err := readAt(r, size-22, 22, size)
	if err != nil {
		return nil, err
	}
	if u32(end) != 0x06054b50 {
		tail, err := readAt(r, max(0, size-65557), min(size, 65557), size)
		if err != nil {
			return nil, err
		}
		if bytes.Contains(tail, []byte("PK\x05\x06")) {
			return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
		}
		return nil, fail("ARCHIVE_CORRUPT")
	}
	count, cdSize, cdStart := int(u16(end[10:])), int64(u32(end[12:])), int64(u32(end[16:]))
	if u16(end[4:]) != 0 || u16(end[6:]) != 0 || u16(end[8:]) != uint16(count) || count == 65535 || cdSize == 0xffffffff || cdStart == 0xffffffff || u16(end[20:]) != 0 {
		return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
	}
	if count > EntryLimit-v.result.ArchiveEntryCount {
		return nil, fail("LIMIT_EXCEEDED")
	}
	v.result.ArchiveEntryCount += count
	if cdStart > size-22 || cdSize > size-22-cdStart {
		return nil, fail("ARCHIVE_CORRUPT")
	}
	if cdStart+cdSize != size-22 {
		return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
	}
	entries := make([]entry, 0, count)
	cursor := cdStart
	for i := 0; i < count; i++ {
		if err := v.ctx.Err(); err != nil {
			return nil, err
		}
		header, err := readAt(r, cursor, 46, cdStart+cdSize)
		if err != nil {
			return nil, err
		}
		if u32(header) != 0x02014b50 {
			return nil, fail("ARCHIVE_CORRUPT")
		}
		e := entry{creator: u16(header[4:]), needed: u16(header[6:]), flags: u16(header[8:]), method: u16(header[10:]), crc: u32(header[16:]), compressed: u32(header[20:]), uncompressed: u32(header[24:]), attrs: u32(header[38:]), local: int64(u32(header[42:]))}
		nameSize, extraSize, commentSize := int64(u16(header[28:])), int64(u16(header[30:])), int64(u16(header[32:]))
		if nameSize > 1024 {
			return nil, fail("LIMIT_EXCEEDED")
		}
		if commentSize != 0 || u16(header[34:]) != 0 || e.compressed == 0xffffffff || e.uncompressed == 0xffffffff || e.local == 0xffffffff {
			return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
		}
		name, err := readAt(r, cursor+46, nameSize, cdStart+cdSize)
		if err != nil {
			return nil, err
		}
		centralExtra, err := readAt(r, cursor+46+nameSize, extraSize, cdStart+cdSize)
		if err != nil {
			return nil, err
		}
		e.name = string(name)
		cursor += 46 + nameSize + extraSize
		if e.flags&0x2041 != 0 {
			return nil, fail("ENCRYPTED_ARCHIVE")
		}
		mask := uint16(0x0808)
		if e.method == 8 {
			mask = 0x080e
		} else if e.method != 0 {
			return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
		}
		if e.flags & ^mask != 0 {
			return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
		}
		if e.needed != 20 && (e.method != 0 || e.flags&8 != 0 || e.needed != 10) {
			return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
		}
		if e.flags&0x800 == 0 {
			for _, c := range name {
				if c >= 128 {
					return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
				}
			}
		} else if !utf8.Valid(name) {
			return nil, fail("ARCHIVE_CORRUPT")
		}
		local, err := readAt(r, e.local, 30, cdStart)
		if err != nil {
			return nil, err
		}
		if u32(local) != 0x04034b50 || u16(local[4:]) != e.needed || u16(local[6:]) != e.flags || u16(local[8:]) != e.method || int64(u16(local[26:])) != nameSize {
			return nil, fail("ARCHIVE_CORRUPT")
		}
		localExtraSize := int64(u16(local[28:]))
		localName, err := readAt(r, e.local+30, nameSize, cdStart)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(name, localName) {
			return nil, fail("ARCHIVE_CORRUPT")
		}
		localExtra, err := readAt(r, e.local+30+nameSize, localExtraSize, cdStart)
		if err != nil {
			return nil, err
		}
		if err := unixMetadata(localExtra, centralExtra); err != nil {
			return nil, err
		}
		e.data = e.local + 30 + nameSize + localExtraSize
		if e.data > cdStart || int64(e.compressed) > cdStart-e.data {
			return nil, fail("ARCHIVE_CORRUPT")
		}
		e.end = e.data + int64(e.compressed)
		if e.flags&8 != 0 {
			if u32(local[14:]) != 0 || u32(local[18:]) != 0 || u32(local[22:]) != 0 {
				return nil, fail("ARCHIVE_CORRUPT")
			}
			// An unsigned descriptor is outside this profile, including when only 12 bytes remain.
			sig, err := readAt(r, e.end, 4, cdStart)
			if err != nil {
				return nil, err
			}
			if u32(sig) != 0x08074b50 {
				return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
			}
			dd, err := readAt(r, e.end, 16, cdStart)
			if err != nil {
				return nil, err
			}
			if u32(dd[4:]) != e.crc || u32(dd[8:]) != e.compressed || u32(dd[12:]) != e.uncompressed {
				return nil, fail("ARCHIVE_CORRUPT")
			}
			e.end += 16
		} else if u32(local[14:]) != e.crc || u32(local[18:]) != e.compressed || u32(local[22:]) != e.uncompressed {
			return nil, fail("ARCHIVE_CORRUPT")
		}
		if err := e.kind(); err != nil {
			return nil, err
		}
		if err := e.path(); err != nil {
			if err.Error() == "UNSAFE_ARCHIVE_PATH" {
				e.block = err.Error()
			} else {
				return nil, err
			}
		}
		entries = append(entries, e)
	}
	if cursor != cdStart+cdSize {
		return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
	}
	physical := append([]entry(nil), entries...)
	sort.Slice(physical, func(i, j int) bool { return physical[i].local < physical[j].local })
	cursor = 0
	for _, e := range physical {
		if e.local < cursor {
			return nil, fail("ARCHIVE_CORRUPT")
		}
		if e.local != cursor {
			return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
		}
		cursor = e.end
	}
	if cursor != cdStart {
		return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
	}
	return entries, nil
}

func (e *entry) kind() error {
	slash := strings.HasSuffix(e.name, "/")
	creator := e.creator >> 8
	if e.attrs&0xffff&^uint32(0x37) != 0 {
		return fail("ARCHIVE_ENTRY_TYPE_CONFLICT")
	}
	switch creator {
	case 3, 19:
		switch e.attrs >> 16 & 0xf000 {
		case 0x4000:
			e.directory = true
		case 0x8000:
		case 0x1000, 0x2000, 0x6000, 0xa000, 0xc000:
			e.block = "UNSAFE_ARCHIVE_PATH"
		default:
			return fail("ARCHIVE_ENTRY_TYPE_CONFLICT")
		}
		if e.attrs&0x10 != 0 && !e.directory {
			return fail("ARCHIVE_ENTRY_TYPE_CONFLICT")
		}
	case 0, 10, 14:
		if e.attrs>>16 != 0 {
			return fail("ARCHIVE_ENTRY_TYPE_CONFLICT")
		}
		e.directory = e.attrs&0x10 != 0
	default:
		return fail("ARCHIVE_ENTRY_TYPE_CONFLICT")
	}
	if e.directory != slash {
		return fail("ARCHIVE_ENTRY_TYPE_CONFLICT")
	}
	if e.directory {
		if e.method == 0 && e.uncompressed == 0 && e.compressed != 0 {
			return fail("ARCHIVE_CORRUPT")
		}
		// APPNOTE asks for 2.0, but Info-ZIP and macOS write 1.0 for empty stored directories; nothing else differs here.
		if e.needed != 20 && e.needed != 10 || e.method != 0 || e.flags&8 != 0 || e.crc != 0 || e.compressed != 0 || e.uncompressed != 0 {
			return fail("ARCHIVE_ENTRY_TYPE_CONFLICT")
		}
	}
	return nil
}

func (e *entry) path() error {
	name := strings.TrimSuffix(e.name, "/")
	parts := strings.Split(name, "/")
	depth := len(parts) - 1
	if e.directory {
		depth++
	}
	if depth > 32 {
		return fail("LIMIT_EXCEEDED")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return fail("UNSAFE_ARCHIVE_PATH")
		}
		for _, c := range part {
			if c < 32 || c == 127 || strings.ContainsRune("\\:\"<>|?*", c) {
				return fail("UNSAFE_ARCHIVE_PATH")
			}
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" {
			return fail("UNSAFE_ARCHIVE_PATH")
		}
		if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
			suffix := strings.TrimPrefix(strings.TrimPrefix(base, "COM"), "LPT")
			if len([]rune(suffix)) == 1 && strings.ContainsAny(suffix, "123456789¹²³") {
				return fail("UNSAFE_ARCHIVE_PATH")
			}
		}
	}
	return nil
}

func tree(entries []entry) string {
	type node struct{ file, explicit bool }
	nodes := map[string]node{}
	fold := cases.Fold()
	for _, e := range entries {
		if e.block != "" {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(e.name, "/"), "/")
		key := ""
		for i, part := range parts {
			key += "/" + norm.NFC.String(fold.String(norm.NFC.String(part)))
			last := i == len(parts)-1
			old, exists := nodes[key]
			if !last {
				if old.file {
					return "ARCHIVE_PATH_TYPE_CONFLICT"
				}
				if !exists {
					nodes[key] = node{}
				}
				continue
			}
			if exists {
				if old.file != !e.directory {
					return "ARCHIVE_PATH_TYPE_CONFLICT"
				}
				if old.explicit {
					return "ARCHIVE_NAME_COLLISION"
				}
			}
			nodes[key] = node{file: !e.directory, explicit: true}
		}
	}
	return ""
}

type boundedReader struct {
	r        *io.SectionReader
	consumed int64
}

func (r *boundedReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.consumed += int64(n)
	return n, err
}
func (r *boundedReader) ReadByte() (byte, error) {
	var p [1]byte
	n, err := r.Read(p[:])
	if n == 1 {
		return p[0], nil
	}
	return 0, err
}

type budgetWriter struct {
	v                 *inspector
	output            io.Writer
	count, compressed int64
}

func (w *budgetWriter) Write(p []byte) (int, error) {
	n := int64(len(p))
	if n > FileLimit-w.count || n > TotalLimit-w.v.result.ExtractedBytes || w.count+n > w.compressed*100 {
		return 0, fail("LIMIT_EXCEEDED")
	}
	written, err := w.output.Write(p)
	w.count += int64(written)
	w.v.result.ExtractedBytes += int64(written)
	return written, err
}

func (v *inspector) extract(r io.ReaderAt, e *entry) error {
	if int64(e.uncompressed) > FileLimit {
		return fail("LIMIT_EXCEEDED")
	}
	stored := v.id() + ".data"
	f, err := v.work.OpenFile(stored, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	bounded := &boundedReader{r: io.NewSectionReader(r, e.data, int64(e.compressed))}
	var input io.Reader = bounded
	var decoder io.ReadCloser
	if e.method == 8 {
		decoder = flate.NewReader(bounded)
		defer decoder.Close()
		input = decoder
	}
	checksum := crc32.NewIEEE()
	writer := &budgetWriter{v: v, output: io.MultiWriter(f, checksum), compressed: int64(e.compressed)}
	if _, err = copyContext(v.ctx, writer, input); err != nil {
		if _, ok := err.(flate.CorruptInputError); ok || err == io.ErrUnexpectedEOF {
			return fail("ARCHIVE_CORRUPT")
		}
		return err
	}
	if bounded.consumed != int64(e.compressed) || writer.count != int64(e.uncompressed) || checksum.Sum32() != e.crc {
		return fail("ARCHIVE_CORRUPT")
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	e.stored = stored
	v.result.ExtractedFileCount++
	return nil
}
