package fixtures

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"path/filepath"
	"strings"
)

const avSignedCVDSHA = "fb1ae86172fe4a7d4c1952395b8f568112ca7862f013dbdfd211b29aeca1dcfc"
const avXMLObserverSHA = "acd72d535b8a9b8ac22388e326edd20803b3153705cfe24c97cf33e236b35485"
const avXMLDictionarySHA = "64cd2b2b653406bb5eea376400c01de906a07c254e303abc20a9897ce0f7dc72"

func avOverlappingZIP() []byte {
	type entry struct {
		name              []byte
		crc, size, header uint32
	}
	entries := []entry{}
	body := bytes.Repeat([]byte{'A'}, 256)
	for i := 7; i >= 0; i-- {
		name := []byte(fmt.Sprintf("item-%d.bin", i))
		crc := crc32.ChecksumIEEE(body)
		header := make([]byte, 30+len(name))
		avPut32(header, 0, 0x04034b50)
		avPut16(header, 4, 10)
		avPut16(header, 12, 0x5c21)
		avPut32(header, 14, crc)
		avPut32(header, 18, uint32(len(body)))
		avPut32(header, 22, uint32(len(body)))
		avPut16(header, 26, uint16(len(name)))
		copy(header[30:], name)
		entries = append([]entry{{name, crc, uint32(len(body)), uint32(len(header))}}, entries...)
		body = append(header, body...)
	}
	central := []byte{}
	offset := uint32(0)
	for _, item := range entries {
		header := make([]byte, 46+len(item.name))
		avPut32(header, 0, 0x02014b50)
		avPut16(header, 4, 3<<8|20)
		avPut16(header, 6, 10)
		avPut16(header, 14, 0x5c21)
		avPut32(header, 16, item.crc)
		avPut32(header, 20, item.size)
		avPut32(header, 24, item.size)
		avPut16(header, 28, uint16(len(item.name)))
		avPut32(header, 38, 0100600<<16)
		avPut32(header, 42, offset)
		copy(header[46:], item.name)
		central = append(central, header...)
		offset += item.header
	}
	end := make([]byte, 22)
	avPut32(end, 0, 0x06054b50)
	avPut16(end, 8, 8)
	avPut16(end, 10, 8)
	avPut32(end, 12, uint32(len(central)))
	avPut32(end, 16, uint32(len(body)))
	return bytes.Join([][]byte{body, central, end}, nil)
}
func avHardInputs() (map[string][]byte, error) {
	signed, _, err := readOwned("/av/signed-bytecode.cvd", 32<<20, true)
	if err != nil || digest(signed) != avSignedCVDSHA {
		return nil, invalid
	}
	inputs := avBasicInputs()
	start, end := []byte("<?xml version=\"1.0\"?><wordDocument>"), []byte("</wordDocument>")
	xml := func(parts ...[]byte) []byte { return bytes.Join(append(append([][]byte{start}, parts...), end), nil) }
	inputs["signed-bytecode.cvd"] = signed
	inputs["xml-local-recursion.xml"] = xml(bytes.Repeat([]byte("<a>"), 22), []byte{'A'}, bytes.Repeat([]byte("</a>"), 22))
	inputs["xml-text-size.xml"] = xml([]byte("<a>"), bytes.Repeat([]byte{'A'}, 10000001), []byte("</a>"))
	inputs["xml-name-size.xml"] = xml([]byte{'<'}, bytes.Repeat([]byte{'a'}, 50001), []byte("/>"))
	inputs["xml-element-depth.xml"] = xml([]byte("<!--"), bytes.Repeat([]byte{'A'}, 8192), []byte("-->"), bytes.Repeat([]byte("<a>"), 258), []byte{'A'}, bytes.Repeat([]byte("</a>"), 258))
	inputs["xml-lookup-start-tag.xml"] = xml([]byte("<a"), bytes.Repeat([]byte{' '}, 10000001), []byte("/>"))
	prefix := []byte("<?xml version=\"1.0\"?><?mso-application progid=\"Word.Document\"?>")
	var definitions bytes.Buffer
	definitions.WriteString("<!ENTITY e0 \"A\">")
	for i := 1; i < 23; i++ {
		fmt.Fprintf(&definitions, "<!ENTITY e%d \"&e%d;\">", i, i-1)
	}
	inputs["xml-entity-depth.xml"] = bytes.Join([][]byte{prefix, []byte("<!DOCTYPE wordDocument ["), definitions.Bytes(), []byte("]><wordDocument value=\"&e22;\" />")}, nil)
	inputs["xml-entity-amplification.xml"] = bytes.Join([][]byte{prefix, []byte("<!DOCTYPE wordDocument [<!ENTITY a \""), bytes.Repeat([]byte{'A'}, 1000), []byte("\">]><wordDocument value=\""), bytes.Repeat([]byte("&a;"), 3000), []byte("\" />")}, nil)
	var dictionary bytes.Buffer
	dictionary.Write(start)
	for i := 0; i < 1000000; i++ {
		fmt.Fprintf(&dictionary, "<a%025d/>", i)
	}
	dictionary.Write(end)
	inputs["xml-dictionary.xml"] = dictionary.Bytes()
	inputs["pdf-filter-count.pdf"] = bytes.Join([][]byte{[]byte("%PDF-1.5\n1 0 obj\n<< /Length 3 /Filter ["), bytes.Repeat([]byte("/ASCIIHexDecode "), 65), []byte("] >>\nstream\n30>\nendstream\nendobj\ntrailer << /Size 2 >>\n%%EOF\n")}, nil)
	inputs["pdf-bytecode-timeout.pdf"] = bytes.Join([][]byte{[]byte("%PDF-1.5\n1 0 obj\n<< /S /JavaScript /JS (//"), bytes.Repeat([]byte{'A'}, 2<<20), []byte("\n0;) >>\nendobj\ntrailer << /Size 2 /Root 1 0 R >>\n%%EOF\n")}, nil)
	inputs["zip-overlap.zip"] = avOverlappingZIP()
	inputs["mail-similarity.eml"] = bytes.Join([][]byte{[]byte("From: synthetic@example.invalid\nTo: synthetic@example.invalid\nContent-Type: "), bytes.Repeat([]byte{'x'}, 60), []byte("/plain\n\nA\n")}, nil)
	return inputs, nil
}
func avHardDiagnostics() map[string]string {
	diagnostics := map[string]string{"xml-local-recursion": "reached msxml json recursion limit", "xml-text-size": "Text node too long", "xml-name-size": "Name too long", "xml-element-depth": "Excessive depth", "xml-entity-depth": "Maximum entity nesting depth exceeded", "xml-entity-amplification": "Maximum entity amplification factor exceeded", "xml-lookup-size": "Buffer size limit exceeded", "pdf-filter-count": "detected 64 applied filters", "signed-bytecode-timeout": "Bytecode run timed out in interpreter after", "trusted-bytecode": "Loading trusted bytecode", "ordinary-error": "LibClamAV Error:", "zip-overlap-count": "Heuristics.Zip.OverlappingFiles", "mail-similarity-pattern": "Unknown MIME type: `", "xml-dictionary": "Memory allocation failed", "xml-observer-loaded": "FILEGATE_XML_OBSERVER loaded=21309", "xml-observer-unclassified": "FILEGATE_XML_OBSERVER failure=unclassified "}
	for _, id := range []string{"xml-text-size", "xml-name-size", "xml-element-depth", "xml-entity-depth", "xml-entity-amplification", "xml-lookup-size", "xml-parser-memory", "xml-name-size-followup", "xml-dictionary"} {
		diagnostics["observer-"+id] = "FILEGATE_XML_OBSERVER failure=" + id + " "
	}
	return diagnostics
}
func avDictionaryProbe(root string) (map[string]any, error) {
	source := "/av/xml_dict_probe.c"
	body, _, err := readOwned(source, 1<<20, true)
	if err != nil || digest(body) != avXMLDictionarySHA {
		return nil, invalid
	}
	binary := filepath.Join(root, "xml-dict-probe")
	args := []string{"/usr/bin/gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-I/usr/include/libxml2", source, "-lxml2", "-o", binary}
	compiled := observeAV(args, root, nil, "", 64<<20)
	var report map[string]any
	status := -1
	var binarySHA any
	if compiled.Valid && compiled.ExitCode == 0 {
		binarySHA, err = fileDigest(binary)
		if err != nil {
			return nil, err
		}
		stdout, _, code, err := command([]string{binary}, nil, 1<<20, []string{"PATH=/bin:/usr/bin", "LC_ALL=C", "HOME=" + root, "TMPDIR=" + filepath.Join(root, "avtmp")})
		status = code
		if err == nil {
			_ = decode(stdout, &report)
		}
	}
	number := func(name string) int64 { v, _ := report[name].(json.Number); value, _ := v.Int64(); return value }
	met := status == 0 && report != nil && number("fixed_limit") == 10000000 && number("limit_readback") == 10000000 && number("comparison_only_limit") == 40000000 && report["same_name_retry_with_larger_comparison_limit_succeeded"] == true && report["fixture_1000000_names_reaches_limit"] == true && report["runtime_version"] == "21309" && number("usage_before") > 10000000 && number("usage_after") > number("usage_before")
	library, err := filepath.EvalSymlinks("/usr/lib/libxml2.so.2")
	if err != nil {
		return nil, err
	}
	librarySHA, err := fileDigest(library)
	if err != nil {
		return nil, err
	}
	return map[string]any{"compile_arguments": args, "compile_observation": compiled, "exit_code": status, "report": report, "expectation_met": met, "not_ClamAV_private_context": true, "source_sha256": avXMLDictionarySHA, "binary_sha256": binarySHA, "libxml2_sha256": librarySHA}, nil
}
func runAVHard(root, binary string) ([]map[string]any, error) {
	dictionary, err := avDictionaryProbe(root)
	if err != nil {
		return nil, err
	}
	source := "/av/xml_error_observer.c"
	body, _, err := readOwned(source, 1<<20, true)
	if err != nil || digest(body) != avXMLObserverSHA {
		return nil, invalid
	}
	observer := filepath.Join(root, "xml-error-observer.so")
	compile := []string{"/usr/bin/gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", "-I/usr/include/libxml2", source, "-lxml2", "-ldl", "-o", observer}
	compiled := observeAV(compile, root, nil, "", 64<<20)
	observerReady := compiled.Valid && compiled.ExitCode == 0
	var observerSHA any
	if observerReady {
		observerSHA, err = fileDigest(observer)
		if err != nil {
			return nil, err
		}
	}
	diagnostics := avHardDiagnostics()
	cases := []avCase{{"xml-local-recursion", "marker.ndb", "xml-local-recursion.xml", "hidden", "", nil}, {"xml-text-size", "marker.ndb", "xml-text-size.xml", "ordinary_warning_or_error", "", nil}, {"xml-name-size", "marker.ndb", "xml-name-size.xml", "ordinary_warning_or_error", "", nil}, {"xml-element-depth", "marker.ndb", "xml-element-depth.xml", "ordinary_warning_or_error", "", nil}, {"xml-entity-depth", "marker.ndb", "xml-entity-depth.xml", "hidden", "", nil}, {"xml-entity-amplification", "marker.ndb", "xml-entity-amplification.xml", "hidden", "", nil}, {"xml-lookup-size", "marker.ndb", "xml-lookup-start-tag.xml", "ordinary_warning_or_error", "", nil}, {"xml-dictionary", "marker.ndb", "xml-dictionary.xml", "ordinary_warning_or_error", "", nil}, {"pdf-filter-count", "marker.ndb", "pdf-filter-count.pdf", "hidden", "", nil}, {"zip-overlap-count", "marker.ndb", "zip-overlap.zip", "zip_overlap_notification", "", nil}, {"mail-similarity-pattern", "marker.ndb", "mail-similarity.eml", "hidden", "", nil}, {"signed-bytecode-timeout", "signed-bytecode.cvd", "pdf-bytecode-timeout.pdf", "ordinary_warning_or_error", "", map[string]string{"bytecode-timeout": "1", "bytecode-mode": "ForceInterpreter"}}}
	rows := []map[string]any{}
	for _, test := range cases {
		args, err := avArguments(binary, root, filepath.Join(root, "avtmp"), test)
		if err != nil {
			return nil, err
		}
		normal := observeAV(args, root, diagnostics, "", 64<<20)
		debug := observeAV(avDebug(args), root, diagnostics, "", 64<<20)
		var instrumented *avObservation
		if strings.HasPrefix(test.id, "xml-") && observerReady {
			v := observeAV(args, root, diagnostics, observer, 64<<20)
			instrumented = &v
		}
		instrumentedReached := instrumented != nil && instrumented.Valid && instrumented.Diagnostics["xml-observer-loaded"] == 1 && instrumented.Diagnostics["observer-"+test.id] > 0 && instrumented.Diagnostics["xml-observer-unclassified"] == 0 && avSameOrdinary(normal, *instrumented)
		reached := debug.Valid && debug.Diagnostics[test.id] > 0 || instrumentedReached
		matched := reached && normal.Valid
		switch test.expected {
		case "hidden":
			matched = matched && avClean(normal)
		case "zip_overlap_notification":
			matched = matched && normal.ExitCode == 1 && normal.Diagnostics[test.id] > 0
		default:
			matched = matched && normal.Warnings+normal.Errors > 0 && normal.ExitCode == 0 && normal.Normal == 1
		}
		if test.id == "signed-bytecode-timeout" {
			matched = matched && debug.Diagnostics["trusted-bytecode"] > 0 && normal.Diagnostics[test.id] > 0
		}
		if test.id == "xml-dictionary" {
			matched = matched && dictionary["expectation_met"] == true && instrumentedReached
		}
		rows = append(rows, map[string]any{"id": test.id, "expected": test.expected, "limit_reached_witness": reached, "normal": normal, "debug": debug, "expectation_met": matched, "diagnostic_instrumented": instrumented, "instrumented_limit_witness": instrumentedReached, "arguments": args[1:], "fixture_overrides": test.overrides, "dictionary_dependency_API_comparison": dictionary, "xml_diagnostic_observer": map[string]any{"compile_arguments": compile, "compile_observation": compiled, "source_sha256": avXMLObserverSHA, "binary_sha256": observerSHA, "scope": "diagnostic_interposition_only_not_production_normal_output"}})
	}
	return rows, nil
}
