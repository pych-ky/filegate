package inspect

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

var sheetName = regexp.MustCompile("^[A-Za-z0-9_ -]{1,31}$")
var cellReference = regexp.MustCompile("^([A-Z]{1,3})([1-9][0-9]{0,6})$")
var cellNumber = regexp.MustCompile("^[+-]?(?:[0-9]+(?:[.][0-9]*)?|[.][0-9]+)(?:[eE][+-]?[0-9]+)?$")

func officeWorkbook(parts map[string]officePart) bool {
	n := parts["xl/workbook.xml"].xml
	if !officeShape(n, sheetNS, "workbook", "", "sheets", false) || len(n.children) != 1 ||
		!officeShape(n.children[0], sheetNS, "sheets", "", "sheet", false) || len(n.children[0].children) == 0 {
		return false
	}
	relationships, ok := officeRelationships(parts["xl/_rels/workbook.xml.rels"].xml, "xl/workbook.xml")
	if !ok {
		return false
	}
	shared, hasShared := parts["xl/sharedStrings.xml"]
	stringsCount := 0
	if hasShared {
		var ok bool
		stringsCount, ok = officeSharedStrings(shared.xml)
		if !ok {
			return false
		}
	}
	used, ids, names := map[string]bool{}, map[uint64]bool{}, map[string]bool{}
	sharedReferences := 0
	for _, s := range n.children[0].children {
		id, valid := officeUint(s.attr("sheetId"), math.MaxUint32)
		name := s.attr("name")
		relationship, exists := relationships[s.attr("r:id")]
		if !officeShape(s, sheetNS, "sheet", "name sheetId r:id", "", false) || !valid || id == 0 || ids[id] ||
			!sheetName.MatchString(name) || names[strings.ToLower(name)] || !exists || relationship.kind != "worksheet" ||
			!worksheetPart.MatchString(relationship.target) || used[relationship.target] {
			return false
		}
		part, exists := parts[relationship.target]
		if !exists || !officeWorksheet(part.xml, stringsCount, &sharedReferences) {
			return false
		}
		used[relationship.target], ids[id], names[strings.ToLower(name)] = true, true, true
	}
	sharedRelationship := false
	for _, r := range relationships {
		switch r.kind {
		case "worksheet":
			if !used[r.target] {
				return false
			}
		case "sharedStrings":
			if !hasShared || sharedRelationship || r.target != "xl/sharedStrings.xml" {
				return false
			}
			sharedRelationship = true
		default:
			return false
		}
	}
	for name := range parts {
		if worksheetPart.MatchString(name) && !used[name] {
			return false
		}
	}
	if sharedRelationship != hasShared || len(relationships) != len(used)+boolCount(hasShared) {
		return false
	}
	if hasShared && shared.xml.attr("count") != "" {
		count, ok := officeUint(shared.xml.attr("count"), 100000)
		if !ok || count != uint64(sharedReferences) {
			return false
		}
	}
	return true
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

func officeSharedStrings(n *officeNode) (int, bool) {
	if !officeShape(n, sheetNS, "sst", "count uniqueCount", "si", false) {
		return 0, false
	}
	texts := map[string]bool{}
	for _, item := range n.children {
		if !officeShape(item, sheetNS, "si", "", "t", false) || len(item.children) != 1 || !officeText(item.children[0], sheetNS) {
			return 0, false
		}
		text := item.children[0].text.String()
		if texts[text] {
			return 0, false
		}
		texts[text] = true
	}
	if n.attr("uniqueCount") != "" {
		count, ok := officeUint(n.attr("uniqueCount"), 100000)
		if !ok || count != uint64(len(texts)) {
			return 0, false
		}
	}
	return len(n.children), true
}

func officeWorksheet(n *officeNode, stringsCount int, sharedReferences *int) bool {
	if !officeShape(n, sheetNS, "worksheet", "", "sheetData", false) || len(n.children) != 1 ||
		!officeShape(n.children[0], sheetNS, "sheetData", "", "row", false) {
		return false
	}
	var previousRow uint64
	for _, row := range n.children[0].children {
		number, ok := officeUint(row.attr("r"), 1048576)
		if !officeShape(row, sheetNS, "row", "r", "c", false) || !ok || number <= previousRow {
			return false
		}
		previousRow = number
		column := 0
		for _, cell := range row.children {
			ref := cellReference.FindStringSubmatch(cell.attr("r"))
			if !officeShape(cell, sheetNS, "c", "r t", "v is", false) || ref == nil {
				return false
			}
			cellRow, ok := officeUint(ref[2], 1048576)
			next := 0
			for _, c := range ref[1] {
				next = next*26 + int(c-'A'+1)
			}
			if !ok || cellRow != number || next <= column || next > 16384 {
				return false
			}
			column = next
			kind := cell.attr("t")
			if len(cell.children) == 0 {
				if kind != "" && kind != "n" {
					return false
				}
				continue
			}
			if len(cell.children) != 1 {
				return false
			}
			value := cell.children[0]
			if kind == "inlineStr" {
				if !officeShape(value, sheetNS, "is", "", "t", false) || len(value.children) != 1 || !officeText(value.children[0], sheetNS) {
					return false
				}
				continue
			}
			if !officeShape(value, sheetNS, "v", "", "", true) {
				return false
			}
			text := trimOfficeSpace(value.text.String())
			switch kind {
			case "", "n":
				n, err := strconv.ParseFloat(text, 64)
				if !cellNumber.MatchString(text) || err != nil || math.IsInf(n, 0) || math.IsNaN(n) {
					return false
				}
			case "b":
				if text != "0" && text != "1" {
					return false
				}
			case "s":
				index, ok := officeUint(text, 100000)
				if !ok || index >= uint64(stringsCount) {
					return false
				}
				*sharedReferences = *sharedReferences + 1
			default:
				return false
			}
		}
	}
	return true
}
