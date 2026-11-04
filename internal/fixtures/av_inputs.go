package fixtures

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"time"
	"unicode/utf16"
)

func avPut16(body []byte, offset int, value uint16) {
	binary.LittleEndian.PutUint16(body[offset:], value)
}
func avPut32(body []byte, offset int, value uint32) {
	binary.LittleEndian.PutUint32(body[offset:], value)
}
func avBE16(body []byte, offset int, value uint16) { binary.BigEndian.PutUint16(body[offset:], value) }
func avBE32(body []byte, offset int, value uint32) { binary.BigEndian.PutUint32(body[offset:], value) }
func avZip(entries []struct {
	name string
	body []byte
}, compressed bool) ([]byte, error) {
	var stream bytes.Buffer
	archive := zip.NewWriter(&stream)
	method := uint16(zip.Store)
	if compressed {
		method = zip.Deflate
	}
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: method, Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		header.SetMode(0600)
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err = writer.Write(entry.body); err != nil {
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return stream.Bytes(), nil
}
func avBasicInputs() map[string][]byte {
	inputs := map[string][]byte{"clean.txt": []byte("FileGate synthetic clean fixture.\n"), "marker.txt": []byte("FileGate harmless AV observation marker.\n"), "limit.txt": bytes.Repeat([]byte{'A'}, 4096), "pcre.txt": append(bytes.Repeat([]byte{'A'}, 1024), 'X'), "marker.ndb": []byte("FileGate.Harmless.Marker:0:*:46696c6547617465206861726d6c657373\n"), "pcre-match.ldb": []byte("FileGate.Harmless.PCRE.Match;Engine:81-255,Target:0;0&1;414141;0/(*NO_START_OPT)(*NO_AUTO_POSSESS)^(A+)+B$/\n"), "pcre-depth.ldb": []byte("FileGate.Harmless.PCRE.Depth;Engine:81-255,Target:0;0&1;414141;0/(*NO_START_OPT)(*NO_AUTO_POSSESS)^(A|B)+$/\n")}
	for _, spec := range []struct {
		name    string
		count   int
		payload []byte
	}{{"max-files.zip", 3, []byte("harmless\n")}, {"max-size.zip", 1, bytes.Repeat([]byte{'A'}, 4096)}} {
		entries := []struct {
			name string
			body []byte
		}{}
		for i := 0; i < spec.count; i++ {
			entries = append(entries, struct {
				name string
				body []byte
			}{fmt.Sprintf("item-%d.txt", i), spec.payload})
		}
		body, err := avZip(entries, true)
		if err != nil {
			panic(err)
		}
		inputs[spec.name] = body
	}
	return inputs
}

const avBytecodeTemplate = "ClamBCafhhjllfole|aa```````|ancflfafmfbfcfmb`cnbicicnbbc``anaap`clamcoincidencejb:4096\n\nTeddaaahdabahdacahdadahdaeahdafahdagahaae`badbadb`bb`baae`badahb`bb`b\nE``\nG`aa`@`\nA`b`bL`Fabab\nBTbaaa\nBTbaaaE\nSifnfdg`befnfdgbgig`gofifnfdghbibSkgSgghfiflfefhbacibkgmgSbgefdgegbgnf`b`ckcSmgS\n"

func avBytecodeLoop() ([]byte, error) {
	lines := bytes.Split(bytes.TrimSuffix([]byte(avBytecodeTemplate), []byte{'\n'}), []byte{'\n'})
	header := lines[0]
	number := func(offset int) (uint64, int, error) {
		if offset >= len(header) {
			return 0, 0, invalid
		}
		width := int(header[offset]) - 0x60
		if width < 0 || width > 16 || offset+width >= len(header) {
			return 0, 0, invalid
		}
		var value uint64
		for i := 0; i < width; i++ {
			value |= uint64(header[offset+i+1]&15) << uint(4*i)
		}
		return value, offset + width + 1, nil
	}
	level, offset, err := number(len("ClamBC"))
	if err != nil || level != 6 {
		return nil, invalid
	}
	_, offset, err = number(offset)
	if err != nil || header[offset] != '|' {
		return nil, invalid
	}
	length, offset, err := number(offset + 1)
	if err != nil {
		return nil, err
	}
	offset += int(2 * length)
	_, offset, err = number(offset)
	if err != nil {
		return nil, err
	}
	kindOffset := offset
	kind, offset, err := number(offset)
	if err != nil || kind != 0 {
		return nil, invalid
	}
	changed := append(append(append([]byte{}, header[:kindOffset]...), []byte("c``a")...), header[offset:]...)
	lines[0] = append([]byte("ClamBCag"), changed[8:]...)
	lines[1] = []byte("FileGate.Harmless.BytecodeLoop;Engine:81-255,Target:0;0;414141")
	return append(bytes.Join(lines, []byte{'\n'}), '\n'), nil
}
func avPEData() []byte {
	result := make([]byte, 1024)
	copy(result, []byte("MZ"))
	avPut32(result, 0x3c, 128)
	copy(result[128:], []byte{'P', 'E', 0, 0})
	avPut16(result, 132, 0x14c)
	avPut16(result, 134, 1)
	avPut16(result, 148, 224)
	avPut16(result, 150, 0x2102)
	optional := 152
	avPut16(result, optional, 0x10b)
	avPut32(result, optional+8, 512)
	avPut32(result, optional+24, 4096)
	avPut32(result, optional+28, 0x400000)
	avPut32(result, optional+32, 4096)
	avPut32(result, optional+36, 512)
	avPut16(result, optional+40, 6)
	avPut32(result, optional+56, 8192)
	avPut32(result, optional+60, 512)
	avPut16(result, optional+68, 3)
	avPut32(result, optional+92, 16)
	section := optional + 224
	copy(result[section:], []byte(".data\x00\x00\x00"))
	avPut32(result, section+8, 512)
	avPut32(result, section+12, 4096)
	avPut32(result, section+16, 512)
	avPut32(result, section+20, 512)
	avPut32(result, section+36, 0x40000040)
	copy(result[512:], bytes.Repeat([]byte{'A'}, 512))
	return result
}
func avPNGAllocation() []byte {
	chunk := func(kind string, body []byte) []byte {
		out := make([]byte, 8+len(body)+4)
		binary.BigEndian.PutUint32(out, uint32(len(body)))
		copy(out[4:], kind)
		copy(out[8:], body)
		binary.BigEndian.PutUint32(out[8+len(body):], crc32.ChecksumIEEE(out[4:8+len(body)]))
		return out
	}
	header := make([]byte, 13)
	avBE32(header, 0, 15000)
	avBE32(header, 4, 15000)
	header[8] = 8
	header[9] = 6
	var data bytes.Buffer
	writer := zlib.NewWriter(&data)
	_, _ = writer.Write([]byte{0})
	_ = writer.Close()
	result := []byte("\x89PNG\r\n\x1a\n")
	result = append(result, chunk("IHDR", header)...)
	result = append(result, chunk("IDAT", data.Bytes())...)
	return append(result, chunk("IEND", nil)...)
}
func avALZStored() []byte {
	out := make([]byte, 8)
	avPut32(out, 0, 0x015a4c41)
	for i := 0; i < 3; i++ {
		name := []byte(fmt.Sprintf("benign-%d.txt", i))
		body := bytes.Repeat([]byte{'A'}, 64)
		record := make([]byte, 23)
		avPut32(record, 0, 0x015a4c42)
		avPut16(record, 4, uint16(len(name)))
		record[6] = 0x20
		record[11] = 0x20
		avPut32(record, 15, crc32.ChecksumIEEE(body))
		avPut16(record, 19, uint16(len(body)))
		avPut16(record, 21, uint16(len(body)))
		out = append(out, record...)
		out = append(out, name...)
		out = append(out, body...)
	}
	footer := make([]byte, 4)
	avPut32(footer, 0, 0x025a4c43)
	return append(out, footer...)
}
func avLimitInputs() (map[string][]byte, error) {
	inputs := avBasicInputs()
	nested := []byte("benign\n")
	var err error
	for depth := 0; depth < 5; depth++ {
		name := "leaf.txt"
		if depth != 0 {
			name = fmt.Sprintf("nested-%d.zip", depth)
		}
		nested, err = avZip([]struct {
			name string
			body []byte
		}{{name, nested}}, false)
		if err != nil {
			return nil, err
		}
	}
	mbr := make([]byte, 1536)
	for i := 0; i < 2; i++ {
		entry := 446 + i*16
		mbr[entry+4] = 0x83
		avPut32(mbr, entry+8, uint32(i+1))
		avPut32(mbr, entry+12, 1)
	}
	copy(mbr[510:], []byte{0x55, 0xaa})
	inputs["empty.txt"] = nil
	inputs["nested.zip"] = nested
	inputs["html.html"] = bytes.Join([][]byte{[]byte("<!doctype html><html><body>"), bytes.Repeat([]byte{'A'}, 4096), []byte("</body></html>")}, nil)
	inputs["script.txt"] = bytes.Join([][]byte{[]byte("var harmless = '"), bytes.Repeat([]byte{'A'}, 4096), []byte("';\n")}, nil)
	inputs["mbr.bin"] = mbr
	inputs["embedded-pe.bin"] = append(avPEData(), avPEData()...)
	inputs["scan-time.txt"] = bytes.Repeat([]byte{'A'}, 8<<20)
	prefix := []byte("From: synthetic@example.invalid\nTo: synthetic@example.invalid\n")
	inputs["mail-headers.eml"] = bytes.Join([][]byte{prefix, bytes.Repeat([]byte("Content-Transfer-Encoding: 7bit\n"), 1025), []byte("\nbody\n")}, nil)
	inputs["mail-header-bytes.eml"] = bytes.Join([][]byte{prefix, []byte("Content-Disposition: inline; name=\""), bytes.Repeat(append(bytes.Repeat([]byte{'A'}, 1000), []byte("\n ")...), 263), []byte("end\"\n\nbody\n")}, nil)
	inputs["mail-folds.eml"] = bytes.Join([][]byte{prefix, []byte("X-Fold: start\n"), bytes.Repeat([]byte(" A\n"), 256*1024+1), []byte("\nbody\n")}, nil)
	inputs["mail-arguments.eml"] = bytes.Join([][]byte{prefix, []byte("MIME-Version: 1.0\nContent-Type: text/plain;\n "), bytes.Repeat([]byte("a=b;\n "), 256), []byte("last=value\n\nbody\n")}, nil)
	inputs["mail-parts.eml"] = bytes.Join([][]byte{prefix, []byte("MIME-Version: 1.0\nContent-Type: multipart/related; boundary=part\n\n"), bytes.Repeat([]byte("--part\nContent-Type: text/plain\n\nA\n"), 1025), []byte("--part--\n")}, nil)
	inputs["html-token.html"] = bytes.Join([][]byte{[]byte("<html><body><a href='"), bytes.Repeat([]byte{'A'}, 2048), []byte("'>text</a></body></html>")}, nil)
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	for i := 1; i < 65538; i++ {
		fmt.Fprintf(&pdf, "%d 0 obj\nnull\nendobj\n", i)
	}
	pdf.WriteString("trailer << /Size 65538 >>\n%%EOF\n")
	inputs["pdf-objects.pdf"] = pdf.Bytes()
	inputs["bytecode-loop.cbc"], err = avBytecodeLoop()
	if err != nil {
		return nil, err
	}
	inputs["image-allocation.png"] = avPNGAllocation()
	inputs["stored.alz"] = avALZStored()
	return inputs, nil
}
func avCompound(name string, stream []byte) []byte {
	sectors := (len(stream) + 511) / 512
	free, end, fat := uint32(0xffffffff), uint32(0xfffffffe), uint32(0xfffffffd)
	header := make([]byte, 512)
	copy(header, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	for i, n := range []uint16{0x3e, 3, 0xfffe, 9, 6} {
		avPut16(header, 24+i*2, n)
	}
	for i, n := range []uint32{0, 1, 1, 0, 4096, end, 0, end, 0} {
		avPut32(header, 40+i*4, n)
	}
	avPut32(header, 76, 0)
	for i := 1; i < 109; i++ {
		avPut32(header, 76+i*4, free)
	}
	table := make([]byte, 512)
	for i := 0; i < 128; i++ {
		avPut32(table, i*4, free)
	}
	avPut32(table, 0, fat)
	avPut32(table, 4, end)
	for i := 0; i < sectors; i++ {
		next := uint32(i + 3)
		if i == sectors-1 {
			next = end
		}
		avPut32(table, (i+2)*4, next)
	}
	entry := func(name string, kind byte, child, start uint32, size uint64) []byte {
		body := make([]byte, 128)
		encoded := utf16.Encode([]rune(name + "\x00"))
		for i, value := range encoded {
			avPut16(body, i*2, value)
		}
		avPut16(body, 64, uint16(len(encoded)*2))
		body[66] = kind
		body[67] = 1
		avPut32(body, 68, free)
		avPut32(body, 72, free)
		avPut32(body, 76, child)
		avPut32(body, 116, start)
		binary.LittleEndian.PutUint64(body[120:], size)
		return body
	}
	result := append(header, table...)
	result = append(result, entry("Root Entry", 5, 1, end, 0)...)
	result = append(result, entry(name, 2, free, 2, uint64(len(stream)))...)
	result = append(result, make([]byte, 256)...)
	result = append(result, stream...)
	return append(result, make([]byte, sectors*512-len(stream))...)
}
func avHWP3(levels int) []byte {
	empty := make([]byte, 43)
	header := make([]byte, 43)
	header[0] = 1
	avPut16(header, 1, 2)
	hidden := make([]byte, 16)
	avPut16(hidden, 0, 15)
	avPut16(hidden, 6, 15)
	paragraphs := append([]byte{}, empty...)
	for i := 0; i < levels; i++ {
		paragraphs = bytes.Join([][]byte{header, hidden, paragraphs, []byte{13, 0}, empty}, nil)
	}
	identity := make([]byte, 30)
	copy(identity, []byte("HWP Document File V3.00 \x1a\x01\x02\x03\x04\x05"))
	return bytes.Join([][]byte{identity, make([]byte, 128+1008+16), paragraphs, make([]byte, 8)}, nil)
}
func avRemainingInputs() map[string][]byte {
	marker := []byte("FileGate benign boundary marker.")
	tail := []byte("ZZBOUNDARYZZ")
	inputs := map[string][]byte{"xml-marker.ndb": []byte(fmt.Sprintf("FileGate.Harmless.Remaining.XML:0:*:%x\n", marker)), "html-marker.ndb": []byte(fmt.Sprintf("FileGate.Harmless.Remaining.HTML:0:*:%x\n", append(append([]byte{}, tail...), []byte(" x")...))), "clean-marker.ndb": []byte("FileGate.Harmless.Remaining.Unused:0:*:66696c65676174655f756e757365645f6d61726b6572\n")}
	for _, count := range []int{20, 21} {
		attributes := []byte{}
		for i := 0; i < count-1; i++ {
			if i > 0 {
				attributes = append(attributes, ' ')
			}
			attributes = append(attributes, []byte(fmt.Sprintf("A%02d=\"x\"", i))...)
		}
		inputs[fmt.Sprintf("xml-attributes-%d.xml", count)] = bytes.Join([][]byte{[]byte("\xef\xbb\xbf<?xml version=\"1.0\"?><HWPML><BINDATASTORAGE><BINDATA "), attributes, []byte(" Encoding=\"Base64\">"), []byte(base64.StdEncoding.EncodeToString(marker)), []byte("\n</BINDATA></BINDATASTORAGE></HWPML>")}, nil)
	}
	for _, length := range []int{1024, 1025} {
		inputs[fmt.Sprintf("html-token-%d.html", length)] = bytes.Join([][]byte{[]byte("<html><body><a href="), bytes.Repeat([]byte{'A'}, length-len(tail)), tail, []byte(">x</a></body></html>\n")}, nil)
	}
	for _, level := range []int{15, 16} {
		inputs[fmt.Sprintf("hwp-recursion-%d.hwp", level)] = avHWP3(level)
	}
	for _, length := range []int{8228, 8229} {
		stream := make([]byte, 4+length+4)
		avPut16(stream, 0, 0xeb)
		avPut16(stream, 2, uint16(length))
		avPut16(stream, 4+length, 0xa)
		inputs[fmt.Sprintf("xlm-record-%d.ole", length)] = avCompound("Workbook", stream)
	}
	return inputs
}
