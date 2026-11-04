package inspect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	wordNS     = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
	sheetNS    = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
	officeNS   = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
	packageNS  = "http://schemas.openxmlformats.org/package/2006/relationships"
	typesNS    = "http://schemas.openxmlformats.org/package/2006/content-types"
	xmlNS      = "http://www.w3.org/XML/1998/namespace"
	docxType   = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
	xlsxType   = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
	relsType   = "application/vnd.openxmlformats-package.relationships+xml"
	sheetType  = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
	stringType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"
)

type officeNode struct {
	name     xml.Name
	attrs    []xml.Attr
	text     strings.Builder
	children []*officeNode
}

func (n *officeNode) attr(name string) string {
	for _, a := range n.attrs {
		if officeName(a.Name) == name {
			return a.Value
		}
	}
	return ""
}

func officeName(n xml.Name) string {
	switch n.Space {
	case "":
		return n.Local
	case wordNS:
		return "w:" + n.Local
	case officeNS:
		return "r:" + n.Local
	case xmlNS:
		return "xml:" + n.Local
	default:
		return "{" + n.Space + "}" + n.Local
	}
}

func trimOfficeSpace(value string) string { return strings.Trim(value, " \t\r\n") }

func officeShape(n *officeNode, ns, local, attrs, children string, text bool) bool {
	if n == nil || n.name != (xml.Name{Space: ns, Local: local}) || !text && trimOfficeSpace(n.text.String()) != "" {
		return false
	}
	for _, a := range n.attrs {
		if a.Name.Space == "xmlns" || a.Name.Space == "" && a.Name.Local == "xmlns" {
			switch a.Value {
			case wordNS, sheetNS, officeNS, packageNS, typesNS, xmlNS:
				continue
			default:
				return false
			}
		}
		if a.Value == "" || !strings.Contains(" "+attrs+" ", " "+officeName(a.Name)+" ") {
			return false
		}
	}
	for _, c := range n.children {
		if c.name.Space != ns || !strings.Contains(" "+children+" ", " "+c.name.Local+" ") {
			return false
		}
	}
	return true
}

var declarationAttr = regexp.MustCompile("^(version|encoding|standalone)[ \t\r\n]*=[ \t\r\n]*(?:\"([^\"]*)\"|'([^']*)')")

func officeDeclaration(body string) bool {
	values := map[string]string{}
	var order []string
	for body = trimOfficeSpace(body); body != ""; body = trimOfficeSpace(body) {
		m := declarationAttr.FindStringSubmatch(body)
		if m == nil || values[m[1]] != "" || m[2]+m[3] == "" {
			return false
		}
		values[m[1]] = m[2] + m[3]
		order = append(order, m[1])
		body = body[len(m[0]):]
		if body != "" && !strings.ContainsRune(" \t\r\n", rune(body[0])) {
			return false
		}
	}
	return len(order) > 0 && order[0] == "version" && values["version"] == "1.0" &&
		(values["encoding"] == "" || strings.EqualFold(values["encoding"], "utf-8")) &&
		(values["standalone"] == "" || values["standalone"] == "yes" || values["standalone"] == "no") &&
		!(len(order) == 3 && order[1] != "encoding")
}

func officeStartSyntax(body []byte) bool {
	space := func(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }
	if len(body) < 3 || body[0] != '<' || body[len(body)-1] != '>' {
		return false
	}
	i := 1
	for i < len(body) && !space(body[i]) && body[i] != '/' && body[i] != '>' {
		i++
	}
	for i < len(body) {
		start := i
		for i < len(body) && space(body[i]) {
			i++
		}
		if i == len(body)-1 && body[i] == '>' || i == len(body)-2 && body[i] == '/' && body[i+1] == '>' {
			return true
		}
		if i == start || i >= len(body) {
			return false
		}
		start = i
		for i < len(body) && !space(body[i]) && body[i] != '=' && body[i] != '/' && body[i] != '>' {
			i++
		}
		if i == start {
			return false
		}
		for i < len(body) && space(body[i]) {
			i++
		}
		if i >= len(body) || body[i] != '=' {
			return false
		}
		i++
		for i < len(body) && space(body[i]) {
			i++
		}
		if i >= len(body) || body[i] != '\'' && body[i] != '"' {
			return false
		}
		quote := body[i]
		i++
		for i < len(body) && body[i] != quote {
			i++
		}
		if i == len(body) {
			return false
		}
		i++
	}
	return false
}

func (v *inspector) officeXML(body []byte, nodes *int) (*officeNode, error) {
	if !utf8.Valid(body) {
		return nil, fail("UNSUPPORTED_FORMAT")
	}
	for _, c := range string(body) {
		if !(c == 9 || c == 10 || c == 13 || c >= 0x20 && c <= 0xd7ff || c >= 0xe000 && c <= 0xfffd || c >= 0x10000 && c <= 0x10ffff) {
			return nil, fail("UNSUPPORTED_FORMAT")
		}
	}
	body = bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var root *officeNode
	var stack []*officeNode
	declaration := false
	prologSeen := false
	for {
		if err := v.ctx.Err(); err != nil {
			return nil, err
		}
		offset := decoder.InputOffset()
		token, err := decoder.Token()
		if err == io.EOF {
			if root == nil || len(stack) != 0 {
				return nil, fail("UNSUPPORTED_FORMAT")
			}
			return root, nil
		}
		if err != nil {
			return nil, fail("UNSUPPORTED_FORMAT")
		}
		switch t := token.(type) {
		case xml.StartElement:
			if !officeStartSyntax(body[offset:decoder.InputOffset()]) {
				return nil, fail("UNSUPPORTED_FORMAT")
			}
			*nodes = *nodes + 1
			if *nodes > 100000 || len(stack) >= 64 || len(t.Attr) > 32 {
				return nil, fail("LIMIT_EXCEEDED")
			}
			seen := map[xml.Name]bool{}
			for _, a := range t.Attr {
				if seen[a.Name] {
					return nil, fail("UNSUPPORTED_FORMAT")
				}
				if a.Name.Space == "xmlns" && (!officeNCName.MatchString(a.Name.Local) || a.Name.Local == "xmlns" || a.Value == "" ||
					(a.Name.Local == "xml") != (a.Value == xmlNS) || a.Value == "http://www.w3.org/2000/xmlns/") ||
					a.Name.Space == "" && a.Name.Local == "xmlns" && (a.Value == xmlNS || a.Value == "http://www.w3.org/2000/xmlns/") {
					return nil, fail("UNSUPPORTED_FORMAT")
				}
				if len(a.Value) > 4096 {
					return nil, fail("LIMIT_EXCEEDED")
				}
				seen[a.Name] = true
			}
			n := &officeNode{name: t.Name, attrs: t.Attr}
			if len(stack) == 0 {
				if root != nil {
					return nil, fail("UNSUPPORTED_FORMAT")
				}
				root = n
			} else {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if trimOfficeSpace(string(body[offset:decoder.InputOffset()])) != "" {
					return nil, fail("UNSUPPORTED_FORMAT")
				}
			} else {
				stack[len(stack)-1].text.Write(t)
			}
		case xml.ProcInst:
			if t.Target != "xml" || declaration || prologSeen || root != nil || !officeDeclaration(string(t.Inst)) {
				return nil, fail("UNSUPPORTED_FORMAT")
			}
			declaration = true
		case xml.Directive:
			return nil, fail("UNSUPPORTED_FORMAT")
		}
		prologSeen = true
	}
}

func officeFeatures(n *officeNode, format string) string {
	if format == "docx" && (n.name.Space == wordNS || n.name.Space == "http://purl.oclc.org/ooxml/wordprocessingml/main") {
		switch n.name.Local {
		case "fldSimple", "fldChar", "instrText", "delInstrText":
			return "DOCX_FIELD_REQUIRES_REVIEW"
		}
	}
	if format == "xlsx" && (n.name.Space == sheetNS || n.name.Space == "http://purl.oclc.org/ooxml/spreadsheetml/main") {
		switch n.name.Local {
		case "f", "definedNames", "definedName", "connections", "connection", "queryTable", "pivotTableDefinition", "pivotCacheDefinition", "externalLink", "conditionalFormatting", "dataValidations", "table":
			return "XLSX_FORMULA_OR_CONNECTION"
		}
	}
	if n.name == (xml.Name{Space: packageNS, Local: "Relationship"}) && n.attr("TargetMode") == "External" {
		return "ACTIVE_CONTENT_REQUIRES_REVIEW"
	}
	for _, c := range n.children {
		if reason := officeFeatures(c, format); reason != "" {
			return reason
		}
	}
	return ""
}

type officePart struct {
	entry entry
	xml   *officeNode
}

var worksheetPart = regexp.MustCompile("^xl/worksheets/sheet[1-9][0-9]*[.]xml$")

func (v *inspector) ooxml(entries []entry, parent string, metadata Metadata) error {
	manifestStart, avStart := len(v.result.Manifest), v.result.RequiredAVInputCount
	boundContainer := false
	defer func() {
		if !boundContainer {
			v.result.Manifest = v.result.Manifest[:manifestStart]
			v.result.RequiredAVInputCount = avStart
		}
	}()
	parts := map[string]officePart{}
	nodes, xmlBytes := 0, int64(0)
	var parseErr error
	for _, e := range entries {
		if e.directory {
			v.result.Manifest = append(v.result.Manifest, Object{ID: v.id(), ParentID: parent, Kind: "verified_empty_directory", AVExclusionReason: "VERIFIED_EMPTY_DIRECTORY"})
			continue
		}
		f, err := v.work.Open(e.stored)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = copyContext(v.ctx, h, f)
		if err == nil {
			v.result.Manifest = append(v.result.Manifest, Object{ID: v.id(), ParentID: parent, Kind: "regular_file", Format: "ooxml-part", SHA256: hex.EncodeToString(h.Sum(nil)), ByteSize: int64(e.uncompressed), AVRequired: true, Path: e.stored})
			v.result.RequiredAVInputCount++
		}
		var n *officeNode
		if err == nil {
			xmlBytes += int64(e.uncompressed)
			if e.uncompressed > 8<<20 || xmlBytes > 16<<20 {
				f.Close()
				return fail("LIMIT_EXCEEDED")
			}
			body := make([]byte, e.uncompressed)
			if _, err = f.ReadAt(body, 0); err == nil {
				n, err = v.officeXML(body, &nodes)
			}
			if err != nil {
				parseErr = err
				err = nil
			}
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		parts[e.name] = officePart{e, n}
	}
	types := parts["[Content_Types].xml"].xml
	format := ""
	if types != nil {
		for _, child := range types.children {
			switch child.attr("ContentType") {
			case docxType:
				if format != "" && format != "docx" {
					return fail("UNSUPPORTED_FORMAT")
				}
				format = "docx"
			case xlsxType:
				if format != "" && format != "xlsx" {
					return fail("UNSUPPORTED_FORMAT")
				}
				format = "xlsx"
			}
		}
	}
	if format == "" {
		return fail("UNSUPPORTED_FORMAT")
	}
	for i := range v.result.Manifest {
		if v.result.Manifest[i].ID == parent {
			v.result.Manifest[i].Format = format
		}
	}
	boundContainer = true
	for _, e := range entries {
		if n := parts[e.name].xml; n != nil {
			if reason := officeFeatures(n, format); reason != "" {
				return fail(reason)
			}
		}
	}
	if parseErr != nil {
		return parseErr
	}
	if err := matchingMetadata(metadata, format); err != nil {
		return err
	}
	if !officeTypes(types, parts, format) {
		return fail("UNSUPPORTED_FORMAT")
	}
	for _, e := range entries {
		if e.directory {
			used := false
			for name := range parts {
				used = used || strings.HasPrefix(name, e.name)
			}
			if !used {
				return fail("UNSUPPORTED_FORMAT")
			}
		}
	}
	root, ok := officeRelationships(parts["_rels/.rels"].xml, "")
	main := "word/document.xml"
	if format == "xlsx" {
		main = "xl/workbook.xml"
	}
	if !ok || len(root) != 1 {
		return fail("UNSUPPORTED_FORMAT")
	}
	for _, relationship := range root {
		if relationship.kind != "officeDocument" || relationship.target != main {
			return fail("UNSUPPORTED_FORMAT")
		}
	}
	if format == "docx" {
		if rel, exists := parts["word/_rels/document.xml.rels"]; exists {
			rs, ok := officeRelationships(rel.xml, main)
			if !ok || len(rs) != 0 {
				return fail("UNSUPPORTED_FORMAT")
			}
		}
		if !officeDocument(parts[main].xml) {
			return fail("UNSUPPORTED_FORMAT")
		}
	} else if !officeWorkbook(parts) {
		return fail("UNSUPPORTED_FORMAT")
	}
	v.addChecks("ooxml-package", "ooxml-xml", "ooxml-profile", "declared-type")
	return nil
}

func officeTypes(n *officeNode, parts map[string]officePart, format string) bool {
	if !officeShape(n, typesNS, "Types", "", "Default Override", false) {
		return false
	}
	defaults, overrides := map[string]string{}, map[string]string{}
	for _, c := range n.children {
		switch c.name.Local {
		case "Default":
			ext, typ := c.attr("Extension"), c.attr("ContentType")
			if !officeShape(c, typesNS, "Default", "Extension ContentType", "", false) || defaults[ext] != "" ||
				!(ext == "rels" && typ == relsType || ext == "xml" && typ == "application/xml") {
				return false
			}
			defaults[ext] = typ
		case "Override":
			name, typ := c.attr("PartName"), c.attr("ContentType")
			if !officeShape(c, typesNS, "Override", "PartName ContentType", "", false) || !strings.HasPrefix(name, "/") || overrides[name[1:]] != "" || typ == "" {
				return false
			}
			if _, ok := parts[name[1:]]; !ok || name == "/[Content_Types].xml" {
				return false
			}
			overrides[name[1:]] = typ
		}
	}
	for name, part := range parts {
		if part.xml == nil {
			return false
		}
		if name == "[Content_Types].xml" {
			continue
		}
		expected := ""
		switch {
		case name == "_rels/.rels", format == "docx" && name == "word/_rels/document.xml.rels", format == "xlsx" && name == "xl/_rels/workbook.xml.rels":
			expected = relsType
		case format == "docx" && name == "word/document.xml":
			expected = docxType
		case format == "xlsx" && name == "xl/workbook.xml":
			expected = xlsxType
		case format == "xlsx" && worksheetPart.MatchString(name):
			expected = sheetType
		case format == "xlsx" && name == "xl/sharedStrings.xml":
			expected = stringType
		default:
			return false
		}
		actual := overrides[name]
		if actual == "" {
			actual = defaults[strings.TrimPrefix(path.Ext(name), ".")]
		}
		if actual != expected {
			return false
		}
	}
	return true
}

type officeRelationship struct{ kind, target string }

var officeNCName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

func officeRelationships(n *officeNode, source string) (map[string]officeRelationship, bool) {
	if !officeShape(n, packageNS, "Relationships", "", "Relationship", false) {
		return nil, false
	}
	result := map[string]officeRelationship{}
	for _, c := range n.children {
		id, target, kind := c.attr("Id"), c.attr("Target"), c.attr("Type")
		_, duplicate := result[id]
		if !officeShape(c, packageNS, "Relationship", "Id Type Target TargetMode", "", false) || !officeNCName.MatchString(id) || duplicate ||
			!strings.HasPrefix(kind, officeNS+"/") || target == "" || strings.ContainsAny(target, "\\%?#:") ||
			c.attr("TargetMode") != "" && c.attr("TargetMode") != "Internal" {
			return nil, false
		}
		for _, component := range strings.Split(strings.TrimPrefix(target, "/"), "/") {
			if component == "" || component == "." || component == ".." {
				return nil, false
			}
		}
		if strings.HasPrefix(target, "/") {
			target = target[1:]
		} else {
			target = path.Join(path.Dir(source), target)
		}
		result[id] = officeRelationship{strings.TrimPrefix(kind, officeNS+"/"), target}
	}
	return result, true
}

func officeText(n *officeNode, ns string) bool {
	return officeShape(n, ns, "t", "xml:space", "", true) && (n.attr("xml:space") == "" || n.attr("xml:space") == "default" || n.attr("xml:space") == "preserve")
}

func officeDocument(n *officeNode) bool {
	if !officeShape(n, wordNS, "document", "", "body", false) || len(n.children) != 1 ||
		!officeShape(n.children[0], wordNS, "body", "", "p", false) {
		return false
	}
	for _, p := range n.children[0].children {
		if !officeShape(p, wordNS, "p", "", "r", false) {
			return false
		}
		for _, r := range p.children {
			if !officeShape(r, wordNS, "r", "", "t tab br", false) {
				return false
			}
			for _, c := range r.children {
				if c.name.Local == "t" {
					if !officeText(c, wordNS) {
						return false
					}
				} else if !officeShape(c, wordNS, c.name.Local, "", "", false) {
					return false
				}
			}
		}
	}
	return true
}

func officeUint(value string, maximum uint64) (uint64, bool) {
	if value == "" || strings.Trim(value, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseUint(value, 10, 64)
	return n, err == nil && n <= maximum
}
