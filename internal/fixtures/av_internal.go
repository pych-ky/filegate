package fixtures

import (
	"encoding/binary"
	"fmt"
)

func avHFSFork(start, blocks int) []byte {
	body := make([]byte, 80)
	binary.BigEndian.PutUint64(body, uint64(blocks*4096))
	avBE32(body, 12, uint32(blocks))
	avBE32(body, 16, uint32(start))
	avBE32(body, 20, uint32(blocks))
	return body
}
func avHFSTree(nodes, first, last, key int) []byte {
	body := make([]byte, 4096)
	body[8] = 1
	avBE16(body, 10, 3)
	if first != 0 {
		avBE16(body, 14, 1)
	}
	avBE32(body, 16, uint32(first))
	avBE32(body, 24, uint32(first))
	avBE32(body, 28, uint32(last))
	avBE16(body, 32, 4096)
	avBE16(body, 34, uint16(key))
	avBE32(body, 36, uint32(nodes))
	for i, value := range []uint16{248, 248, 120, 14} {
		avBE16(body, 4088+i*2, value)
	}
	return body
}
func avHFSLeaf(next, previous int, file bool) []byte {
	body := make([]byte, 4096)
	avBE32(body, 0, uint32(next))
	avBE32(body, 4, uint32(previous))
	body[8] = 255
	body[9] = 1
	end := 14
	count := 0
	if file {
		count = 1
		avBE16(body, 10, 1)
		key := make([]byte, 10)
		avBE16(key, 0, 8)
		avBE32(key, 2, 2)
		avBE16(key, 6, 1)
		key[9] = 'a'
		record := make([]byte, 248)
		avBE16(record, 0, 2)
		avBE32(record, 8, 16)
		avBE16(record, 42, 0x8000)
		copy(body[14:], append(key, record...))
		end += len(key) + len(record)
		avBE16(body, 4094, 14)
	}
	avBE16(body, 4096-2*(count+1), uint16(end))
	return body
}
func avHFSImage(leaves int, attribute *bool) []byte {
	catalogBlocks := leaves + 1
	attributeBlocks := 1
	if attribute != nil {
		attributeBlocks = 1002
	}
	attributeStart := 2 + catalogBlocks
	volume := make([]byte, (attributeStart+attributeBlocks+1)*4096)
	avBE16(volume, 1024, 0x482b)
	avBE16(volume, 1026, 4)
	if attribute != nil {
		avBE32(volume, 1056, 1)
	}
	avBE32(volume, 1064, 4096)
	avBE32(volume, 1068, uint32(len(volume)/4096))
	copy(volume[1216:], avHFSFork(1, 1))
	copy(volume[1296:], avHFSFork(2, catalogBlocks))
	copy(volume[1376:], avHFSFork(attributeStart, attributeBlocks))
	copy(volume[4096:], avHFSTree(1, 0, 0, 10))
	copy(volume[8192:], avHFSTree(catalogBlocks, 1, leaves, 516))
	for index := 1; index <= leaves; index++ {
		next := index + 1
		if index == leaves {
			next = 0
		}
		copy(volume[(2+index)*4096:], avHFSLeaf(next, index-1, attribute != nil))
	}
	first := 0
	if attribute != nil && *attribute {
		first = 1
	}
	start := attributeStart * 4096
	copy(volume[start:], avHFSTree(attributeBlocks, first, first, 266))
	if first != 0 {
		copy(volume[start+4096:], avHFSLeaf(0, 0, false))
	}
	mbr := make([]byte, 512)
	mbr[450] = 0xaf
	avPut32(mbr, 454, 1)
	avPut32(mbr, 458, uint32(len(volume)/512))
	copy(mbr[510:], []byte{0x55, 0xaa})
	return append(mbr, volume...)
}
func avVBAStream(count int) []byte {
	body := make([]byte, 4096)
	copy(body, []byte{0xcc, 0x61})
	avPut16(body, 34, 6)
	copy(body[36:], []byte{'*', 0, '\\', 0, 'g', 0})
	avPut16(body, 42, 2)
	avPut16(body, 44, 0xffff)
	avPut16(body, 46, 0xffff)
	avPut16(body, 150, uint16(count))
	return body
}
func avInternalInputs() map[string][]byte {
	yes, no := true, false
	inputs := map[string][]byte{"hfs-catalog-1001.img": avHFSImage(1001, nil), "hfs-catalog-1002.img": avHFSImage(1002, nil), "hfs-attribute-empty.img": avHFSImage(1, &no), "hfs-attribute-one-leaf.img": avHFSImage(1, &yes), "unused.ndb": []byte("FileGate.Harmless.Internal.Unused:0:*:66696c65676174655f756e757365645f6d61726b6572\n")}
	for _, count := range []int{0, 1000, 1001} {
		inputs[fmt.Sprintf("vba-records-%d.ole", count)] = avCompound("_VBA_PROJECT", avVBAStream(count))
	}
	return inputs
}

var avInternalDiagnostics = map[string]string{
	"internal-marker": "FileGate.Harmless.Internal.", "internal-macro": "Heuristics.OLE2.ContainsMacros", "hfs-entry": "cli_scanhfsplus: scanning partition content", "hfs-validated": "cli_scanhfsplus: validation successful",
	"hfs-catalog-leaf": "leaf node Desc:", "hfs-catalog-end": "hfsplus_walk_catalog: reached end of leaf nodes.", "hfs-catalog-limit": "hfsplus_walk_catalog: node scan limit reached.",
	"hfs-attribute-leaf": "leaf attribute node Desc: fLink 0 bLink 0 kind -1 height 1 numRecords 0", "hfs-attribute-end": "hfsplus_check_attribute: reached end of leaf nodes.", "hfs-attribute-limit": "hfsplus_check_attribute: node scan limit reached.",
	"vba-entry": "in cli_vba_readdir()", "vba-little-endian": "vba_readdir: Guessing little-endian", "vba-records-0": "vba_readdir: VBA Record count 0", "vba-records-1000": "vba_readdir: VBA Record count 1000", "vba-records-1001": "vba_readdir: VBA Record count 1001", "vba-record-limit": "vba_readdir: VBA Record count too big", "vba-empty-name": "vba_readdir: zero name length",
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
func avInternalWitness(id, route string, limited bool, value avObservation) bool {
	if !value.Valid {
		return false
	}
	c := value.Diagnostics
	if route == "catalog" || route == "attribute" {
		if c["hfs-entry"] != 1 || c["hfs-validated"] != 1 {
			return false
		}
		if route == "catalog" {
			return c["hfs-catalog-leaf"] == 1001 && c["hfs-catalog-limit"] == boolInt(limited) && c["hfs-catalog-end"] == boolInt(!limited)
		}
		leaves := 0
		if limited {
			leaves = 1001
		}
		return c["hfs-catalog-leaf"] == 1 && c["hfs-catalog-end"] == 1 && c["hfs-attribute-leaf"] == leaves && c["hfs-attribute-limit"] == boolInt(limited) && c["hfs-attribute-end"] == boolInt(!limited)
	}
	count := 1000
	if id == "vba-empty-control" {
		count = 0
	} else if limited {
		count = 1001
	}
	return c["vba-entry"] == 1 && c["vba-little-endian"] == 1 && c[fmt.Sprintf("vba-records-%d", count)] == 1 && c["vba-record-limit"] == boolInt(limited) && c["vba-empty-name"] == boolInt(count == 1000)
}
func runAVInternal(root, binary string) ([]map[string]any, error) {
	cases := []struct {
		id, input, catalog, route string
		limited                   bool
	}{{"hfs-catalog-control", "hfs-catalog-1001.img", "hfs-node-count", "catalog", false}, {"hfs-catalog-limit", "hfs-catalog-1002.img", "hfs-node-count", "catalog", true}, {"hfs-attribute-control", "hfs-attribute-empty.img", "hfs-node-count", "attribute", false}, {"hfs-attribute-limit", "hfs-attribute-one-leaf.img", "hfs-node-count", "attribute", true}, {"vba-empty-control", "vba-records-0.ole", "vba-record-count", "vba", false}, {"vba-boundary-control", "vba-records-1000.ole", "vba-record-count", "vba", false}, {"vba-record-limit", "vba-records-1001.ole", "vba-record-count", "vba", true}}
	rows := []map[string]any{}
	for _, test := range cases {
		args, err := avArguments(binary, root, root+"/avtmp", avCase{database: "unused.ndb", input: test.input})
		if err != nil {
			return nil, err
		}
		normal := observeAV(args, root, avInternalDiagnostics, "", 64<<20)
		debug := observeAV(avDebug(args), root, avInternalDiagnostics, "", 64<<20)
		witness := avInternalWitness(test.id, test.route, test.limited, debug)
		clean := avClean(normal) && normal.Diagnostics["internal-marker"] == 0 && normal.Diagnostics["internal-macro"] == 0
		rows = append(rows, map[string]any{"id": test.id, "catalog_id": test.catalog, "route": test.route, "limit_case": test.limited, "arguments": args[1:], "fixture_overrides": map[string]string{}, "normal": normal, "debug": debug, "limit_or_control_witness": witness, "expectation_met": witness && clean, "expected_normal": "ordinary_clean_without_internal_completion_assertion", "filegate_result_if_warning_error_or_limit_notification": "HOLD"})
	}
	return rows, nil
}
