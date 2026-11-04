package verification

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func ReplaceOnce(source, marker, replacement string) string {
	if strings.Count(source, marker) != 1 {
		panic(Failure{"overlay_marker_not_unique:" + marker})
	}
	return strings.Replace(source, marker, replacement, 1)
}
func BuildOverlay(h *Harness, name, target string, changes map[string]string) Object {
	replace := Object{}
	hashes := Object{}
	for original, source := range changes {
		relative, err := filepath.Rel(h.Root, original)
		Must(err)
		path := filepath.Join(h.Out, "overlay-"+name, relative)
		Write(path, []byte(source))
		replace[original] = path
		hashes[path] = FileDigest(path)
	}
	overlay := filepath.Join(h.Out, name+"-overlay.json")
	WriteJSON(overlay, Object{"Replace": replace})
	command := []string{"go", "build", "-trimpath", "-buildvcs=false", "-overlay", overlay, "-o", target, "./cmd/filegate"}
	result := Execute(h.Root, command, nil, 3*time.Minute)
	Write(filepath.Join(h.Out, name+"-build.log"), append(result.Stdout, result.Stderr...))
	record := Object{"command": command, "exit_code": result.ExitCode, "overlay_sha256": FileDigest(overlay), "replacements_sha256": hashes, "build_stdout_bytes": len(result.Stdout), "build_stderr_bytes": len(result.Stderr)}
	h.Record[name+"_build"] = record
	h.Check(name+"_build", result.ExitCode == 0)
	record["binary_sha256"] = FileDigest(target)
	if target == h.Binary {
		h.Record["binary_sha256"] = record["binary_sha256"]
	}
	return record
}
func (h *Harness) CapacitySnapshot(id, reserved string) Object {
	_, job := h.Request("GET", "/v1/jobs/"+id, nil, nil, nil)
	rows := h.Query("SELECT object_id FROM reservations WHERE job_id=?", id)
	objects := h.Query("SELECT count(*) FROM objects WHERE job_id=?", id)
	reservedObjects := []string{}
	for _, row := range rows {
		reservedObjects = append(reservedObjects, row[0].(string))
	}
	partial := Object{}
	entries, err := os.ReadDir(filepath.Join(h.Data, "partial"))
	Must(err)
	for _, entry := range entries {
		info, err := entry.Info()
		Must(err)
		partial[entry.Name()] = info.Size()
	}
	return Object{"job": job, "reserved_objects": reservedObjects, "committed_objects": objects[0][0], "partial_files": partial, "reserved_object_published": reserved != "" && Exists(filepath.Join(h.Data, "objects", reserved))}
}
func (h *Harness) CapacitySuccess(key string, local bool) {
	var code int
	var receipt Object
	if local {
		path := filepath.Join(h.InputDirectory, "capacity.txt")
		Write(path, InputA)
		code, receipt = h.Submit("file", path, Object{"idempotency_key": key, "expected_sha256": Digest(InputA)}, nil)
	} else {
		code, receipt = h.Submit("upload", "capacity.txt", Object{"idempotency_key": key, "expected_sha256": Digest(InputA)}, InputA)
	}
	h.Check(key+"_committed_hold", code == 0 && Str(receipt, "input_receipt", "sha256") == Digest(InputA) && Int(receipt, "input_receipt", "byte_size") == int64(len(InputA)) && Str(receipt, "job", "verdict") == "HOLD" && Get(receipt, "job", "release", "eligible") == false)
	h.Check(key+"_original_matches", string(Read(filepath.Join(h.Data, "objects", Str(receipt, "input_receipt", "object_id")))) == string(InputA))
}
func ReadUploadResponse(h *Harness, c net.Conn) (int, Object) {
	response, err := http.ReadResponse(bufio.NewReader(c), nil)
	Must(err)
	body, err := io.ReadAll(response.Body)
	Must(err)
	Must(response.Body.Close())
	h.Responses = append(h.Responses, body)
	return response.StatusCode, Decode(body)
}
func atomicFixture(path string, body []byte) {
	pending := path + ".pending"
	Write(pending, body)
	file, err := os.OpenFile(pending, os.O_WRONLY, 0600)
	Must(err)
	Must(file.Sync())
	Must(file.Close())
	Must(os.Rename(pending, path))
}
func init() { Register("intake-capacity", runCapacity) }
func runCapacity(h *Harness) {
	if h.Binary == "" {
		h.Binary = filepath.Join(h.Out, "filegate")
	}
	fault := filepath.Join(h.Out, "capacity-fault.txt")
	path := filepath.Join(h.Root, "internal/broker/filesystem.go")
	marker := "\tif unix.Statfs(path, &st) != nil {"
	replacement := "\tstatfsErr := unix.Statfs(path, &st)\n\tif mode, err := os.ReadFile(" + string(Encoded(fault)) + "); err == nil {\n\t\tswitch string(mode) {\n\t\tcase \"pressure\": st.Bavail = 0\n\t\tcase \"monitor\": statfsErr = unix.EIO\n\t\t}\n\t}\n\tif statfsErr != nil {"
	BuildOverlay(h, "capacity", h.Binary, map[string]string{path: ReplaceOnce(string(Read(path)), marker, replacement)})
	h.Record["scope"] = "real stalled UDS upload with synthetic Statfs readback; no VM execution"
	h.Record["real_pressure_induced"] = false
	Write(fault, []byte("normal"))
	health := h.Start()
	h.Check("capacity_gate_closed", GatesClosed(health))
	h.CapacitySuccess("capacity-local-before", true)
	h.CapacitySuccess("capacity-upload-before", false)
	observations := []Object{}
	for _, test := range []struct {
		mode, expected string
		status         int
	}{{"pressure", "DISK_PRESSURE", 507}, {"monitor", "RESOURCE_MONITOR_FAILED", 503}} {
		metadata, c, id := h.BeginPartial("capacity-" + test.mode)
		deadline := time.Now().Add(3 * time.Second)
		var before Object
		for time.Now().Before(deadline) {
			before = h.CapacitySnapshot(id, "")
			one := false
			for _, size := range Map(before, "partial_files") {
				one = Int(Object{"v": size}, "v") == 1
			}
			if Str(before, "job", "phase") == "ACQUIRING" && len(Map(before, "partial_files")) == 1 && one {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		sizes := Map(before, "partial_files")
		one := false
		for _, size := range sizes {
			one = Int(Object{"v": size}, "v") == 1
		}
		h.Check(test.mode+"_waiting_after_first_byte", Str(before, "job", "phase") == "ACQUIRING" && len(Get(before, "reserved_objects").([]string)) == 1 && len(sizes) == 1 && one && Int(before, "committed_objects") == 0)
		time.Sleep(1100 * time.Millisecond)
		before = h.CapacitySnapshot(id, "")
		one = false
		for _, size := range Map(before, "partial_files") {
			one = Int(Object{"v": size}, "v") == 1
		}
		h.Check(test.mode+"_healthy_stalled_read_remains_active", Str(before, "job", "phase") == "ACQUIRING" && len(Map(before, "partial_files")) == 1 && one)
		object := Get(before, "reserved_objects").([]string)[0]
		observation := Object{"mode": test.mode, "expected_error": test.expected, "sent_body_bytes": 1, "declared_body_bytes": 1048576, "before": before}
		observations = append(observations, observation)
		WriteJSON(filepath.Join(h.Out, "capacity-observations.json"), observations)
		started := time.Now()
		atomicFixture(fault, []byte(test.mode))
		failed := h.WaitJob(id, true)
		elapsed := time.Since(started)
		after := h.CapacitySnapshot(id, object)
		observation["elapsed_seconds"] = elapsed.Seconds()
		observation["after"] = after
		WriteJSON(filepath.Join(h.Out, "capacity-observations.json"), observations)
		status, reply := ReadUploadResponse(h, c)
		Must(c.Close())
		observation["response"] = reply
		WriteJSON(filepath.Join(h.Out, "capacity-observations.json"), observations)
		h.Check(test.mode+"_stalled_read_interrupted", elapsed < 4*time.Second && status == test.status && ErrorCode(reply) == test.expected && Str(failed, "phase") == "FAILED" && Str(failed, "verdict") == "HOLD" && Get(failed, "input_receipt") == nil && Contains(Get(failed, "execution_errors"), test.expected) && Contains(Get(failed, "reason_codes"), test.expected), Object{"elapsed_seconds": elapsed.Seconds(), "sent_body_bytes": 1})
		h.Check(test.mode+"_partial_and_reservation_reclaimed", len(Get(after, "reserved_objects").([]string)) == 0 && len(Map(after, "partial_files")) == 0 && Int(after, "committed_objects") == 0 && Get(after, "reserved_object_published") == false)
		status, replay, closed, _ := h.UnreadUpload(metadata, "length")
		observation["replay"] = replay
		WriteJSON(filepath.Join(h.Out, "capacity-observations.json"), observations)
		h.Check(test.mode+"_failed_key_fixed", status == 409 && ErrorCode(replay) == "INTAKE_TERMINAL_WITHOUT_INPUT" && Str(replay, "error", "receipt", "job_id") == id && Get(replay, "error", "receipt", "body_consumed") == false && closed)
		Write(fault, []byte("normal"))
		h.CapacitySuccess("capacity-upload-after-"+test.mode, false)
	}
	_, c, id := h.BeginPartial("capacity-cancel")
	started := time.Now()
	status, _ := h.Request("POST", "/v1/jobs/"+id+"/cancel", Object{}, nil, nil)
	cancelled := h.WaitJob(id, true)
	Must(c.Close())
	after := h.CapacitySnapshot(id, "")
	h.Check("capacity_explicit_cancel_preserved", status == 200 && time.Since(started) < 2*time.Second && Str(cancelled, "phase") == "CANCELLED" && Str(cancelled, "verdict") == "HOLD" && Get(cancelled, "input_receipt") == nil && len(Get(after, "reserved_objects").([]string)) == 0 && len(Map(after, "partial_files")) == 0 && Int(after, "committed_objects") == 0)
	observations = append(observations, Object{"mode": "explicit-cancel", "after": after})
	WriteJSON(filepath.Join(h.Out, "capacity-observations.json"), observations)
	h.Stop(false)
	combined := string(bytesJoin(h.Logs, h.Responses))
	h.Check("capacity_no_body_or_pass_in_output", !strings.Contains(combined, "PRIVATE_BODY_MARKER") && !strings.Contains(combined, `"verdict":"PASS"`))
}
func bytesJoin(groups ...[][]byte) []byte {
	var out []byte
	for _, group := range groups {
		for _, body := range group {
			out = append(out, body...)
			out = append(out, '\n')
		}
	}
	return out
}
