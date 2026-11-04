package verification

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filegate.local/filegate/internal/hostvm"
)

func init() { Register("load", runVMLoad); Register("capacity-boundaries", runVMCapacity) }
func vmRepack(body []byte, part, start, end, replacement string) []byte {
	source, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	Must(err)
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	found := false
	for _, entry := range source.File {
		reader, err := entry.Open()
		Must(err)
		data, err := io.ReadAll(reader)
		Must(err)
		Must(reader.Close())
		if entry.Name == part {
			content := string(data)
			left, right := strings.Index(content, start), strings.Index(content, end)
			if left < 0 || right <= left {
				panic(Failure{"ooxml_load_part_marker"})
			}
			content = content[:left+len(start)] + replacement + content[right:]
			data = []byte(content)
			found = true
		}
		header := entry.FileHeader
		header.Extra = nil
		target, err := writer.CreateHeader(&header)
		Must(err)
		_, err = target.Write(data)
		Must(err)
	}
	Must(writer.Close())
	if !found {
		panic(Failure{"ooxml_load_part_missing"})
	}
	return out.Bytes()
}
func vmLoadInputs(h *Harness) []Object {
	root := vmCorpus(h)
	office := vmCorpusCases(h, root, "ooxml", []string{"docx_plain", "xlsx_values"})
	block := []byte("Synthetic FileGate measurement text.\n")
	chunk := bytes.Repeat(block, (1<<20)/len(block)+1)[:1<<20]
	path := filepath.Join(h.InputDirectory, "large.txt")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	Must(err)
	for i := 0; i < 64; i++ {
		_, err = file.Write(chunk)
		Must(err)
	}
	Must(file.Sync())
	Must(file.Close())
	text := Object{"name": "large.txt", "kind": "txt", "sha256": FileDigest(path), "bytes": 64 << 20, "required_av_inputs": 1}
	var archive bytes.Buffer
	zipWriter := zip.NewWriter(&archive)
	for i := 0; i < 9500; i++ {
		header := &zip.FileHeader{Name: fmt.Sprintf("synthetic_%05d.txt", i), Method: zip.Store}
		header.SetMode(0644)
		target, err := zipWriter.CreateHeader(header)
		Must(err)
		_, err = target.Write(bytes.Repeat([]byte("Synthetic ordinary text.\n"), 10))
		Must(err)
	}
	Must(zipWriter.Close())
	zipInput := archive.Bytes()
	Write(filepath.Join(h.InputDirectory, "many.zip"), zipInput)
	many := vmEntryInput("many.zip", "zip", zipInput)
	many["required_av_inputs"] = 9501
	var paragraphs strings.Builder
	for i := 0; i < 10000; i++ {
		fmt.Fprintf(&paragraphs, "<w:p><w:r><w:t>Synthetic paragraph %d.</w:t></w:r></w:p>", i)
	}
	docx := vmRepack(Read(filepath.Join(h.InputDirectory, Str(office[0], "name"))), "word/document.xml", "<w:body>", "</w:body>", paragraphs.String())
	Write(filepath.Join(h.InputDirectory, "paragraphs.docx"), docx)
	document := vmEntryInput("paragraphs.docx", "docx", docx)
	document["required_av_inputs"] = 4
	var rows strings.Builder
	for i := 1; i < 10001; i++ {
		fmt.Fprintf(&rows, "<row r=\"%d\"><c r=\"A%d\"><v>%d</v></c><c r=\"B%d\" t=\"b\"><v>1</v></c></row>", i, i, i, i)
	}
	xlsx := vmRepack(Read(filepath.Join(h.InputDirectory, Str(office[1], "name"))), "xl/worksheets/sheet1.xml", "<sheetData>", "</sheetData>", rows.String())
	Write(filepath.Join(h.InputDirectory, "values.xlsx"), xlsx)
	workbook := vmEntryInput("values.xlsx", "xlsx", xlsx)
	workbook["required_av_inputs"] = 6
	inputs := []Object{text, many, document, workbook}
	for _, test := range inputs {
		source := filepath.Join(h.InputDirectory, Str(test, "name"))
		destination := filepath.Join(h.Out, "inputs", Str(test, "name"))
		if !Exists(destination) {
			vmCopyLarge(source, destination)
		}
	}
	WriteJSON(filepath.Join(h.Out, "input-manifest.json"), inputs)
	return inputs
}
func runVMLoad(h *Harness) {
	VerifyBinaryProof(h)
	s := newVMSuite(h)
	defer s.finish()
	inputs := vmLoadInputs(h)
	h.Check("gates_closed", GatesClosed(s.start()))
	measurements := []Object{}
	for _, test := range inputs {
		started := time.Now()
		receipt, directory := s.submit(test, Str(test, "kind"))
		samples := []Object{}
		var job Object
		for {
			status, current := h.Request("GET", "/v1/jobs/"+Str(receipt, "job_id"), nil, nil, nil)
			h.Check("load_job_poll", status == 200)
			identity, err := hostvm.NativeIdentity(h.Process.Process.Pid)
			Must(err)
			h.Check("broker_memory_available", identity != nil)
			samples = append(samples, Object{"elapsed_seconds": time.Since(started).Seconds(), "broker_resident_bytes": identity["resident_bytes"]})
			phase := Str(current, "phase")
			if phase == "FINISHED" || phase == "FAILED" || phase == "CANCELLED" {
				job = current
				break
			}
			h.Check("load_job_deadline", time.Since(started) < 315*time.Second)
			time.Sleep(time.Second)
		}
		name := Str(test, "kind")
		h.Check(name+"_format_only_hold", Str(job, "phase") == "FINISHED" && Str(job, "verdict") == "HOLD" && Bool(job, "runtime_cleanup_complete"))
		s.persist(name, receipt, job, directory, true)
		report := ReadJSON(filepath.Join(directory, "output/report.json"))
		h.Check(name+"_all_objects_checked", Int(report, "result", "required_av_input_count") == Int(test, "required_av_inputs") && Bool(report, "result", "format_checks_complete"))
		native := ReadJSON(filepath.Join(directory, "output/watchdog/results.json"))
		peak, count := int64(0), 0
		for _, event := range List(native, "events") {
			if Str(event, "event") == "SAMPLE" && Int(event, "observed_memory_bytes") >= 0 {
				count++
				if n := Int(event, "observed_memory_bytes"); n > peak {
					peak = n
				}
			}
		}
		h.Check(name+"_bounded_native_memory", count > 0 && peak < 2<<30)
		h.Check(name+"_within_job_deadline", time.Since(started) < 300*time.Second)
		brokerPeak := int64(0)
		for _, sample := range samples {
			if n := Int(sample, "broker_resident_bytes"); n > brokerPeak {
				brokerPeak = n
			}
		}
		measurements = append(measurements, Object{"case": test, "intake_to_finished_seconds": time.Since(started).Seconds(), "broker_resident_observed_after_intake_max_bytes": brokerPeak, "broker_sample_interval_seconds": 1, "native_observed_memory_peak_bytes": peak, "native_memory_samples": count, "native_auxiliary_resources": native["auxiliary_resources"], "broker_samples": samples})
		WriteJSON(filepath.Join(h.Out, "measurements.json"), measurements)
	}
	h.Record["measurements"] = measurements
	h.Record["not_demonstrated"] = []string{"AV scan performance", "customer material", "RSS peak during intake", "concurrent update/release", "GUI performance"}
}
func vmCopyLarge(source, destination string) {
	Must(os.MkdirAll(filepath.Dir(destination), 0700))
	input, err := os.Open(source)
	Must(err)
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	Must(err)
	_, err = io.Copy(output, input)
	Must(err)
	Must(output.Sync())
	Must(output.Close())
}
func vmLedger(h *Harness) Object {
	value := Object{}
	for _, table := range []string{"objects", "reservations", "runtime_runs", "resource_pins", "scan_queue"} {
		value[table] = vmScalar(h, "SELECT count(*) FROM "+table)
	}
	value["raw_reserved"] = vmScalar(h, "SELECT coalesce(sum(raw_reserved),0) FROM runtime_runs")
	for _, name := range []string{"partial", "objects"} {
		entries, err := os.ReadDir(filepath.Join(h.Data, name))
		Must(err)
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		value[name+"_files"] = names
	}
	return value
}
func vmCapacityInputs(h *Harness) []Object {
	proofPath := h.Paths["fixture-proof"]
	h.Check("capacity_fixture_proof_required", proofPath != "")
	h.Check("capacity_fixture_provenance", FileDigest(proofPath) == "4dd239b27050de1244a85bad830f9e983cd8387e3b3a39f0826a61c5fd673b81")
	proof := ReadJSON(proofPath)
	h.Check("capacity_generator_identity", Str(proof, "source_sha256") == "6ca4d3c7512ed11e1d0111cf018ede029c167b22bfbd406ea030392c23e986f7")
	wanted := []string{"input-262144001", "input-262144000", "file-at", "file-over", "cumulative-at", "cumulative-over"}
	rows := List(proof, "cases")
	h.Check("capacity_exact_fixture_set", len(rows) == len(wanted))
	result := []Object{}
	for _, name := range wanted {
		var test Object
		for _, row := range rows {
			if Str(row, "id") == name {
				test = Decode(Encoded(row))
				break
			}
		}
		h.Check("capacity_fixture_"+name, test != nil)
		source := Str(test, "path")
		if h.Inputs != "" {
			source = filepath.Join(h.Inputs, filepath.Base(source))
		}
		h.Check("existing_capacity_fixture_required_"+name, Exists(source))
		info, err := os.Stat(source)
		Must(err)
		h.Check("capacity_fixture_hash_"+name, info.Size() == Int(test, "byte_size") && FileDigest(source) == Str(test, "sha256"))
		test["name"] = filepath.Base(source)
		test["bytes"] = test["byte_size"]
		kind := "zip"
		if filepath.Ext(source) == ".txt" {
			kind = "txt"
		}
		test["kind"] = kind
		test["source"] = source
		if kind == "zip" {
			archive, err := zip.OpenReader(source)
			Must(err)
			members := List(test, "members")
			valid := len(archive.File) == len(members)
			for i, file := range archive.File {
				if i >= len(members) {
					valid = false
					break
				}
				valid = valid && file.Name == Str(members[i], "name") && int64(file.UncompressedSize64) == Int(members[i], "uncompressed_bytes") && int64(file.CompressedSize64) == Int(members[i], "compressed_bytes") && file.UncompressedSize64 <= file.CompressedSize64*100
			}
			Must(archive.Close())
			h.Check("capacity_zip_metadata_"+name, valid)
		}
		result = append(result, test)
	}
	Write(filepath.Join(h.Out, "fixture-generation-proof.json"), Read(proofPath))
	h.Record["fixture_source"] = "reused_existing_files_bound_to_historical_generation_proof"
	return result
}
func runVMCapacity(h *Harness) {
	VerifyBinaryProof(h)
	s := newVMSuite(h)
	defer s.finish()
	inputs := vmCapacityInputs(h)
	h.Check("gates_closed", GatesClosed(s.start()))
	selected := map[string]bool{}
	for _, name := range h.Cases {
		selected[name] = true
	}
	done := 0
	for _, test := range inputs {
		name := Str(test, "id")
		if len(selected) > 0 && !selected[name] {
			continue
		}
		done++
		source := Str(test, "source")
		target := filepath.Join(h.InputDirectory, Str(test, "name"))
		vmCopyLarge(source, target)
		metadata := Object{"idempotency_key": name, "expected_type": Str(test, "kind"), "expected_sha256": Str(test, "sha256")}
		if name == "input-262144001" {
			before := vmLedger(h)
			code, rejected := vmSubmit(h, target, metadata)
			h.Check(name+"_rejected", code == 2 && ErrorCode(rejected) == "LIMIT_EXCEEDED")
			receipt := Map(rejected, "error", "receipt")
			job := Map(receipt, "job")
			h.Check(name+"_failed_hold", Str(receipt, "intake_status") == "FAILED" && Get(receipt, "input_receipt") == nil && Str(job, "phase") == "FAILED" && Str(job, "verdict") == "HOLD" && Equal(Get(job, "reason_codes"), []string{"LIMIT_EXCEEDED"}) && Equal(Get(job, "execution_errors"), []string{"LIMIT_EXCEEDED"}) && Bool(job, "runtime_cleanup_complete"))
			h.Check(name+"_no_original_or_reservation", Equal(vmLedger(h), before) && Int(before, "reservations") == 0 && Int(before, "resource_pins") == 0 && Int(before, "scan_queue") == 0 && Int(before, "raw_reserved") == 0)
			h.Stop(false)
			s.start()
			Must(os.Remove(target))
			code, replay := vmSubmit(h, target, metadata)
			h.Check(name+"_first_failure_preserved", code == 2 && ErrorCode(replay) == "INTAKE_TERMINAL_WITHOUT_INPUT" && Equal(Get(replay, "error", "receipt", "job"), job) && Equal(vmLedger(h), before))
			WriteJSON(filepath.Join(h.Out, name, "state.json"), Object{"initial_response": rejected, "replay": replay, "ledger": before})
			s.cases = append(s.cases, Object{"name": name, "job_id": job["job_id"], "verdict": "HOLD", "vm_started": false})
			continue
		}
		receipt, directory := s.submit(test, name)
		code, job := vmWaitCLI(h, Str(receipt, "job_id"))
		h.Check(name+"_terminal_hold", code == 10 && Str(job, "phase") == "FINISHED" && Str(job, "verdict") == "HOLD")
		database := s.persist(name, receipt, job, directory, true)
		report := ReadJSON(filepath.Join(directory, "output/report.json"))
		result := Map(report, "result")
		h.Check(name+"_av_pending_without_rejection", Str(report, "av_process_status") == "not_started" && (Str(report, "av_result") == "pending" || Str(report, "av_result") == "inconclusive") && Get(result, "required_checks_complete") == false && len(List(result, "confirmed_rejections")) == 0 && len(database["rejection_evidence"].([]Object)) == 0 && Get(job, "release", "eligible") == false)
		members, manifest := List(test, "members"), List(result, "manifest")
		h.Check(name+"_root_manifest", len(manifest) > 0 && Str(manifest[0], "sha256") == Str(test, "sha256") && Int(manifest[0], "byte_size") == Int(test, "bytes") && Bool(manifest[0], "av_required") && Int(result, "archive_entry_count") == int64(len(members)))
		if strings.HasSuffix(name, "-over") {
			complete := int64(0)
			if name == "cumulative-over" {
				complete = 10
			}
			h.Check(name+"_exact_limit_reason", Str(result, "structure_status") == "HOLD" && Equal(Get(result, "reason_codes"), []string{"LIMIT_EXCEEDED"}) && Contains(Get(job, "reason_codes"), "LIMIT_EXCEEDED") && Get(report, "manifest_complete") == false && Get(result, "structure_checks_complete") == false && Get(result, "format_checks_complete") == false)
			bytesValid := Int(result, "extracted_bytes") == 0
			if name != "file-over" {
				bytesValid = Int(result, "extracted_bytes") >= 1000<<20 && Int(result, "extracted_bytes") <= 1<<30
			}
			h.Check(name+"_bounded_incomplete_counts", Int(result, "extracted_file_count") == complete && Int(result, "required_av_input_count") == 1 && len(manifest) == 1 && bytesValid)
		} else {
			expected, observed := map[string]int{}, map[string]int{}
			var total int64
			for _, member := range members {
				key := fmt.Sprintf("%s:%d", Str(member, "sha256"), Int(member, "uncompressed_bytes"))
				expected[key]++
				total += Int(member, "uncompressed_bytes")
			}
			valid := true
			for _, item := range manifest[1:] {
				observed[fmt.Sprintf("%s:%d", Str(item, "sha256"), Int(item, "byte_size"))]++
				valid = valid && Bool(item, "av_required") && Str(item, "parent_id") == Str(manifest[0], "object_id")
			}
			h.Check(name+"_exact_boundary_accepted", Str(result, "structure_status") == "ACCEPT_FORMAT_STRUCTURE" && len(List(result, "reason_codes")) == 0 && Bool(report, "manifest_complete") && Bool(result, "structure_checks_complete") && Bool(result, "format_checks_complete"))
			h.Check(name+"_complete_manifest_and_counters", Equal(expected, observed) && len(manifest) == len(members)+1 && Int(result, "extracted_file_count") == int64(len(members)) && Int(result, "required_av_input_count") == int64(len(members)+1) && Int(result, "extracted_bytes") == total && valid)
		}
		Must(os.Remove(target))
		code, replay := vmSubmit(h, target, metadata)
		h.Check(name+"_first_receipt_preserved", code == 0 && Get(replay, "job_id") == Get(receipt, "job_id") && Equal(Get(replay, "input_receipt"), Get(receipt, "input_receipt")) && Get(replay, "current_input_checked") == false && Get(replay, "body_consumed") == false && Equal(s.database(job)["attempt"], database["attempt"]))
		ledger := vmLedger(h)
		h.Check(name+"_no_pending_resources", Int(ledger, "reservations") == 0 && Int(ledger, "resource_pins") == 0 && Int(ledger, "scan_queue") == 0 && Int(ledger, "raw_reserved") == 0)
	}
	h.Check("selected_capacity_cases_complete", done > 0 && (len(selected) == 0 || done == len(selected)))
	h.Record["cases"] = s.cases
}
