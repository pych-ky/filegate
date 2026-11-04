package verification

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"filegate.local/filegate/internal/hostvm"
	updatecontrol "filegate.local/filegate/internal/update"
	"golang.org/x/sys/unix"
)

type deliveryRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type deliveryPlan struct {
	Schema            int         `json:"schema"`
	DataDirectory     string      `json:"data_directory"`
	Prefix            string      `json:"prefix"`
	Product           deliveryRef `json:"product"`
	InstalledManifest deliveryRef `json:"installed_manifest"`
	Launcher          deliveryRef `json:"launcher"`
	SourceRoot        string      `json:"source_root"`
	SourceBinding     deliveryRef `json:"source_binding"`
	Registration      deliveryRef `json:"registration"`
	Scan              struct {
		Runner    deliveryRef `json:"runner"`
		Workspace string      `json:"workspace"`
		Proof     deliveryRef `json:"proof"`
	} `json:"scan"`
	Stage3Completed bool   `json:"stage3_completed"`
	ExpectedUUID    string `json:"expected_uuid"`
	Original        struct {
		JobID  string `json:"job_id"`
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"byte_size"`
	} `json:"original"`
	Destination struct {
		ID   string `json:"destination_id"`
		Path string `json:"path"`
	} `json:"destination"`
	ReleaseKey     string       `json:"release_key"`
	ServeArguments []string     `json:"serve_arguments"`
	Baseline       *deliveryRef `json:"baseline"`
	Previous       *deliveryRef `json:"previous"`
}

var deliveryDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var deliveryJobID = regexp.MustCompile(`^job_[0-9a-f]{32}$`)
var deliveryTables = []string{"jobs", "attempts", "objects", "intakes", "reservations", "runtime_runs", "runtime_finalizations", "scan_definition_snapshots", "scan_release_snapshots", "scan_queue", "resource_pins", "releases", "release_publication_attempts", "release_authorizations", "release_destinations", "release_reservations", "release_tombstones", "update_attempts", "update_adoptions", "update_runtime", "update_waiters", "update_definition_caches", "update_retention"}
var deliveryProtectedTables = []string{"update_attempts", "update_adoptions", "update_runtime", "update_waiters", "update_definition_caches", "update_retention"}

func init() { Register("delivery-current", runDeliveryCurrent) }

func deliverySafePath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for _, part := range strings.Split(path, string(os.PathSeparator)) {
		if strings.HasPrefix(part, ".env") {
			return false
		}
		switch part {
		case "secrets", "credentials", "client.json", ".git-credentials", ".netrc", ".ssh", ".aws", ".codex", ".claude", "Keychains":
			return false
		}
	}
	return true
}
func deliveryRead(path string, maximum int64) []byte {
	if !deliverySafePath(path) {
		panic(Failure{"DELIVERY_NONSECRET_ARTIFACT_REQUIRED"})
	}
	canonical, err := filepath.EvalSymlinks(path)
	Must(err)
	if canonical != path {
		panic(Failure{"DELIVERY_CANONICAL_ARTIFACT_REQUIRED"})
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	Must(err)
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var before, after, named unix.Stat_t
	Must(unix.Fstat(fd, &before))
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Getuid()) || before.Nlink != 1 || before.Size < 0 || before.Size > maximum {
		panic(Failure{"DELIVERY_OWNED_BOUNDED_ARTIFACT_REQUIRED"})
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	Must(err)
	Must(unix.Fstat(fd, &after))
	Must(unix.Lstat(path, &named))
	if int64(len(body)) != before.Size || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || before.Dev != named.Dev || before.Ino != named.Ino || before.Size != named.Size || before.Mtim != named.Mtim || before.Ctim != named.Ctim {
		panic(Failure{"DELIVERY_ARTIFACT_CHANGED"})
	}
	return body
}
func deliveryReference(h *Harness, label string, ref deliveryRef, maximum int64) []byte {
	h.Check(label+"_reference", deliveryDigest.MatchString(ref.SHA256))
	body := deliveryRead(ref.Path, maximum)
	h.Check(label+"_sha256", Digest(body) == ref.SHA256)
	return body
}
func deliveryPrivate(h *Harness, label, path string) Object {
	h.Check(label+"_canonical_path", deliverySafePath(path))
	canonical, err := filepath.EvalSymlinks(path)
	Must(err)
	var info unix.Stat_t
	Must(unix.Lstat(path, &info))
	h.Check(label+"_owned_private_directory", canonical == path && info.Mode&unix.S_IFMT == unix.S_IFDIR && info.Mode&07777 == 0700 && info.Uid == uint32(os.Getuid()))
	return Object{"device": uint64(info.Dev), "inode": info.Ino, "uid": info.Uid}
}
func deliveryBinary(h *Harness, label string, ref deliveryRef, entry string) {
	body := deliveryReference(h, label, ref, 128<<20)
	h.Check(label+"_native_macho", len(body) >= 4 && bytes.Equal(body[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}))
	build, err := buildinfo.ReadFile(ref.Path)
	Must(err)
	h.Check(label+"_direct_go_executable", build.Path == "filegate.local/filegate/cmd/"+entry && build.Main.Path == "filegate.local/filegate")
	settings := Object{}
	for _, setting := range build.Settings {
		if setting.Key == "GOOS" || setting.Key == "GOARCH" || setting.Key == "CGO_ENABLED" {
			settings[setting.Key] = setting.Value
		}
	}
	h.Check(label+"_darwin_arm64", settings["GOOS"] == "darwin" && settings["GOARCH"] == "arm64")
	h.Record[label+"_go_build"] = Object{"version": build.GoVersion, "entry": build.Path, "settings": settings}
}
func deliveryRowSnapshot(h *Harness) Object {
	result := Object{}
	for _, table := range deliveryTables {
		rows := h.Query("SELECT * FROM " + table + " ORDER BY rowid")
		groups := Object{}
		for _, row := range rows {
			if len(row) == 0 {
				panic(Failure{"DELIVERY_DATABASE_ROW_INVALID"})
			}
			key := fmt.Sprint(row[0])
			values, _ := groups[key].([]string)
			values = append(values, Digest(Encoded(row)))
			groups[key] = values
		}
		for key, value := range groups {
			values := value.([]string)
			sort.Strings(values)
			groups[key] = values
		}
		result[table] = Object{"count": len(rows), "rows": groups}
	}
	return result
}
func deliveryInvariant(control Object) Object {
	value := Object{}
	for _, key := range []string{"binding", "generation", "state", "snapshot", "snapshot_sha256", "next_allowed_utc", "definition", "last_update_id", "active_update_id"} {
		value[key] = control[key]
	}
	return value
}
func deliveryProtected(rows Object) Object {
	out := Object{}
	for _, table := range deliveryProtectedTables {
		out[table] = rows[table]
	}
	return out
}
func deliveryOriginal(h *Harness, plan deliveryPlan) Object {
	rows := QueryObjects(h, "SELECT data FROM jobs WHERE id=?", plan.Original.JobID)
	h.Check("existing_original_job", len(rows) == 1)
	job := Map(rows[0])
	receipt := Map(job, "input_receipt")
	h.Check("original_receipt_matches_reviewed_harmless_input", Str(job, "job_id") == plan.Original.JobID && Str(receipt, "sha256") == plan.Original.SHA256 && Int(receipt, "byte_size") == plan.Original.Bytes && Bool(receipt, "content_available"))
	path := filepath.Join(h.Data, "objects", Str(receipt, "object_id"))
	var info unix.Stat_t
	Must(unix.Lstat(path, &info))
	h.Check("original_owned_readonly_inode", info.Mode&unix.S_IFMT == unix.S_IFREG && info.Mode&07777 == 0400 && info.Uid == uint32(os.Getuid()) && info.Nlink == 1 && info.Size == plan.Original.Bytes)
	h.Check("original_sha256_preserved", FileDigest(path) == plan.Original.SHA256)
	return receipt
}
func deliveryPrevious(h *Harness, label string, ref *deliveryRef, phase string, plan deliveryPlan) Object {
	h.Check(label+"_supplied", ref != nil)
	value := Decode(deliveryReference(h, label, *ref, 4<<20))
	h.Check(label+"_passed_same_existing_installation", Bool(value, "passed") && Str(value, "kind") == "filegate-delivery-phase" && Str(value, "delivery_mode") == phase && Str(value, "existing_data_directory") == h.Data && Str(value, "expected_uuid") == plan.ExpectedUUID && Str(value, "delivery_original_job_id") == plan.Original.JobID)
	return value
}
func deliveryBaseline(h *Harness, plan deliveryPlan, identity Object) Object {
	value := deliveryPrevious(h, "delivery_baseline", plan.Baseline, "capture", plan)
	h.Check("same_existing_directory_identity", Equal(value["data_identity"], identity))
	return Map(value, "baseline")
}

func deliveryMetadata(h *Harness, plan deliveryPlan, control Object) Object {
	deliveryPrivate(h, "installed_prefix", plan.Prefix)
	product := filepath.Join(plan.Prefix, "versions", plan.Product.SHA256, "filegate")
	h.Check("installed_product_exact_path", plan.Product.Path == product && h.Binary == product)
	deliveryBinary(h, "installed_product", plan.Product, "filegate")
	current, err := os.Readlink(filepath.Join(plan.Prefix, "current"))
	Must(err)
	h.Check("installed_current_pointer", current == "versions/"+plan.Product.SHA256)
	resolved, err := filepath.EvalSymlinks(filepath.Join(plan.Prefix, "current/filegate"))
	Must(err)
	h.Check("installed_current_binary_binding", resolved == product)
	h.Check("installed_manifest_exact_path", plan.InstalledManifest.Path == filepath.Join(filepath.Dir(product), "manifest.json"))
	installed := Decode(deliveryReference(h, "installed_manifest", plan.InstalledManifest, 65536))
	h.Check("installed_manifest_customer_flag_and_binary", Equal(installed, Object{"schema": 1, "binary_sha256": plan.Product.SHA256, "distribution": "local-development", "stage3_completed": plan.Stage3Completed}))
	sourceRoot, err := filepath.EvalSymlinks(plan.SourceRoot)
	Must(err)
	h.Check("source_root_canonical", sourceRoot == plan.SourceRoot)
	bindings := Decode(deliveryReference(h, "source_binding", plan.SourceBinding, 4<<20))
	h.Check("finite_host_source_binding", len(bindings) >= 100 && len(bindings) <= 1024)
	for _, required := range []string{"go.mod", "go.sum", "cmd/filegate/main.go", "cmd/filegate-install/main.go", "internal/acceptance/stages.go", "internal/broker/release_snapshot.go"} {
		h.Check("required_source_"+required, deliveryDigest.MatchString(Str(bindings, required)))
	}
	for name, expected := range bindings {
		h.Check("source_relative_go_only_"+name, !filepath.IsAbs(name) && filepath.Clean(name) == name && name != ".." && !strings.HasPrefix(name, "../") && !strings.HasSuffix(strings.ToLower(name), ".py") && !strings.HasSuffix(strings.ToLower(name), ".pyz") && deliveryDigest.MatchString(fmt.Sprint(expected)))
		body := deliveryRead(filepath.Join(sourceRoot, name), 4<<20)
		h.Check("reviewed_source_"+name, Digest(body) == expected)
	}
	declarations := regexp.MustCompile(`const\s+Stage3Completed\s*=\s*(true|false)\b`).FindAllStringSubmatch(string(deliveryRead(filepath.Join(sourceRoot, "internal/acceptance/stages.go"), 65536)), -1)
	h.Check("source_customer_flag_matches_installed_manifest", len(declarations) == 1 && declarations[0][1] == strconv.FormatBool(plan.Stage3Completed))
	h.Check("normal_registration_exact_data_path", plan.Registration.Path == filepath.Join(h.Data, "update-runtime.json"))
	registration := Decode(deliveryReference(h, "normal_registration", plan.Registration, 1<<20))
	_, hasPython := registration["python"]
	h.Check("normal_schema2_without_interpreter", Int(registration, "schema") == 2 && Int(registration, "request_schema") == 2 && !hasPython && Str(registration, "profile") == "filegate-official-update-v1" && registration["fixture_only"] == false && Str(registration, "runner") == filepath.Join(Str(registration, "workspace"), ".build/filegate-update"))
	registered, err := updatecontrol.RegisteredRuntime(h.Data)
	Must(err)
	h.Check("normal_runtime_strict_binding", registered != nil && registered.LibrarySHA256() == Str(control, "binding", "library_sha256") && Get(control, "binding", "fixture_only") == false)
	for path := range Map(registration, "sha256") {
		h.Check("active_pin_without_python_source_"+filepath.Base(path), !strings.HasSuffix(strings.ToLower(path), ".py") && !strings.HasSuffix(strings.ToLower(path), ".pyz") && !strings.HasSuffix(strings.ToLower(path), ".pyc"))
	}
	updateRunner := deliveryRef{Str(registration, "runner"), Str(registration, "sha256", Str(registration, "runner"))}
	updateHelper := deliveryRef{Str(registration, "helper"), Str(registration, "sha256", Str(registration, "helper"))}
	deliveryBinary(h, "normal_update_runner", updateRunner, "filegate-update")
	deliveryBinary(h, "normal_update_helper", updateHelper, "filegate-update-bridge")
	h.Check("scan_runner_fixed_go_path", plan.Scan.Runner.Path == filepath.Join(plan.Scan.Workspace, ".build/filegate-vm"))
	deliveryBinary(h, "scan_runner", plan.Scan.Runner, "filegate-vm")
	deliveryReference(h, "scan_native_proof", plan.Scan.Proof, 4<<20)
	receiptPath := filepath.Join(plan.Scan.Workspace, "experiments/vm/evidence/build.json")
	receipt := Decode(deliveryRead(receiptPath, 4<<20))
	h.Check("scan_image_go_runtime_only", Str(receipt, "implementation") == "go" && len(List(receipt, "python_runtime", "remaining_python_paths")) == 0 && Get(receipt, "python_runtime", "remaining_python_paths") != nil && Int(receipt, "python_runtime", "inspected_inodes") > 0 && Bool(receipt, "initramfs_inspection", "python_runtime_absent") && Bool(receipt, "initramfs_inspection", "required_boot_files_present") && Str(receipt, "host_runner", "path") == plan.Scan.Runner.Path && Str(receipt, "host_runner", "sha256") == plan.Scan.Runner.SHA256)
	h.Record["scan_build_sha256"] = FileDigest(receiptPath)
	deliveryBinary(h, "scan_helper", deliveryRef{filepath.Join(plan.Scan.Workspace, "experiments/vm/.build/filegate-bridge"), Str(receipt, "artifacts", ".build/filegate-bridge")}, "filegate-bridge")
	deliveryLauncher(h, plan, registration)
	return registration
}
func deliveryQuote(value string) string {
	if regexp.MustCompile(`^[a-zA-Z0-9_@%+=:,./-]+$`).MatchString(value) {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
func deliveryLauncher(h *Harness, plan deliveryPlan, registration Object) {
	args := plan.ServeArguments
	h.Check("launcher_fixed_serve_prefix", len(args) >= 4 && args[0] == filepath.Join(plan.Prefix, "current/filegate") && args[1] == "--data-dir" && args[2] == h.Data && args[3] == "serve" && (len(args)-4)%2 == 0)
	flags := map[string][]string{}
	for i := 4; i < len(args); i += 2 {
		key, value := args[i], args[i+1]
		switch key {
		case "--input-root", "--release-destination", "--vm-runner", "--vm-workspace", "--vm-proof", "--update-library-sha256":
			flags[key] = append(flags[key], value)
		default:
			h.Check("launcher_unknown_interpreter_or_flag", false)
		}
	}
	for key, expected := range map[string]string{"--vm-runner": plan.Scan.Runner.Path, "--vm-workspace": plan.Scan.Workspace, "--vm-proof": plan.Scan.Proof.Path, "--update-library-sha256": Str(registration, "library_sha256")} {
		h.Check("launcher_"+key, Equal(flags[key], []string{expected}))
	}
	h.Check("launcher_input_root_configured", len(flags["--input-root"]) > 0)
	h.Check("launcher_installed_path", plan.Launcher.Path == filepath.Join(plan.Prefix, "FileGate.command"))
	actual := deliveryReference(h, "ordinary_launcher", plan.Launcher, 65536)
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = deliveryQuote(arg)
	}
	binary, data := deliveryQuote(filepath.Join(plan.Prefix, "current/filegate")), deliveryQuote(h.Data)
	expected := "#!/bin/bash\nset -u\nbinary=" + binary + "\ndata=" + data + "\n" + "if \"$binary\" --data-dir \"$data\" health >/dev/null 2>&1; then\n  exec \"$binary\" --data-dir \"$data\" ui\nfi\n" + "server_pid=\nstop_owned_server() {\n  if [[ -n \"$server_pid\" ]]; then\n    kill -TERM \"$server_pid\" 2>/dev/null || true\n    wait \"$server_pid\" || true\n  fi\n}\n" + "trap stop_owned_server EXIT\ntrap 'exit 130' INT\ntrap 'exit 143' TERM\ntrap 'exit 129' HUP\n" + strings.Join(quoted, " ") + " &\nserver_pid=$!\n" + "for i in {1..70}; do\n  kill -0 \"$server_pid\" 2>/dev/null || exit 1\n  if \"$binary\" --data-dir \"$data\" health >/dev/null 2>&1; then\n    \"$binary\" --data-dir \"$data\" ui || exit $?\n    wait \"$server_pid\"\n    code=$?\n    server_pid=\n    exit \"$code\"\n  fi\n  sleep 0.5\ndone\n" + "printf 'FileGate did not become ready within 35 seconds.\\n' >&2\nexit 1\n"
	h.Check("ordinary_launcher_exact_finite_go_command_path", bytes.Equal(actual, []byte(expected)))
	var info unix.Stat_t
	Must(unix.Lstat(plan.Launcher.Path, &info))
	h.Check("ordinary_launcher_owner_executable", info.Mode&07777 == 0500)
	h.Record["python_invocations_on_verified_launcher_path"] = 0
	h.Record["launcher_proof_scope"] = "exact finite launcher bytes; Go Mach-O product and direct Go runtime runners; no process tracing or GUI dispatch"
}

func deliveryAdoption(h *Harness, control, registration Object) Object {
	definition := Map(control, "definition")
	id := Str(definition, "update_id")
	h.Check("current_official_definition_exists", regexp.MustCompile(`^update_[0-9a-f]{32}$`).MatchString(id))
	adoptions := QueryObjects(h, "SELECT data FROM update_adoptions WHERE update_id=?", id)
	attempts := QueryObjects(h, "SELECT data FROM update_attempts WHERE id=?", id)
	h.Check("single_current_signed_adoption", len(adoptions) == 1 && len(attempts) == 1)
	adoption, attempt := Map(adoptions[0]), Map(attempts[0])
	directory := filepath.Join(h.Data, "definitions", id)
	deliveryPrivate(h, "adopted_generation", directory)
	manifestPath, imagePath := filepath.Join(directory, "manifest.json"), filepath.Join(directory, "definition-image.json")
	manifestBody, imageBody := deliveryRead(manifestPath, 1<<20), deliveryRead(imagePath, 1<<20)
	manifest, imageManifest := Decode(manifestBody), Decode(imageBody)
	h.Check("adoption_final_manifest_generation_binding", Int(adoption, "schema") == 1 && Str(adoption, "manifest_sha256") == Digest(manifestBody) && Str(definition, "manifest_sha256") == Digest(manifestBody) && Str(definition, "image_manifest_sha256") == Digest(imageBody) && Equal(adoption["manifest"], manifest) && Equal(adoption["definition_image"], imageManifest) && Str(manifest, "update_id") == id && Str(attempt, "update_id") == id && Int(definition, "generation") == Int(attempt, "base_generation")+1 && Bool(attempt, "adoption_approved") && Bool(attempt, "origin_confirmed") && Bool(attempt, "control_committed") && Bool(attempt, "stop_confirmed") && Bool(attempt, "cleanup_confirmed") && Int(attempt, "reserved_bytes") == 0)
	runtime := h.Query("SELECT directory,manifest_sha256 FROM update_runtime WHERE update_id=?", id)
	h.Check("signed_adoption_runtime_history_binding", len(runtime) == 1 && runtime[0][0] == filepath.Join(h.Data, "updates", id) && runtime[0][1] == adoption["runtime_sha256"])
	runtimeDirectory := runtime[0][0].(string)
	requested := Decode(deliveryRead(filepath.Join(runtimeDirectory, "request.json"), 16384))
	finalBody := deliveryRead(filepath.Join(runtimeDirectory, "output/final.json"), 1<<20)
	final := Decode(finalBody)
	var received updatecontrol.Clock
	var previous updatecontrol.Snapshot
	Must(json.Unmarshal(Encoded(attempt["final_received"]), &received))
	Must(json.Unmarshal(Encoded(Get(requested, "restore", "control_snapshot")), &previous))
	validated, err := updatecontrol.ValidateFinal(finalBody, received, previous, updatecontrol.Binding{LibrarySHA256: Str(registration, "library_sha256"), FixtureOnly: false})
	Must(err)
	h.Check("fixed_adapter_signature_and_origin_final", validated.OriginVerified && validated.UpdateID == id && validated.SHA256 == Str(attempt, "final_sha256") && Digest(finalBody) == Str(manifest, "final_sha256") && Get(final, "fixture_only") == false && Bool(final, "all_required_origin_confirmations") && Bool(final, "all_required_artifacts_verified"))
	approved := Map(adoption, "approved")
	h.Check("signed_adoption_inside_original_600_seconds", Equal(approved["boot"], Get(attempt, "started", "boot")) && Int(attempt, "deadline_continuous_ns")-Int(attempt, "started", "continuous_ns") == 600000000000 && Int(attempt, "final_received", "continuous_ns") <= Int(approved, "continuous_ns") && Int(approved, "continuous_ns") < Int(attempt, "deadline_continuous_ns"))
	seen := map[string]bool{}
	files := List(manifest, "files")
	h.Check("three_signed_definition_files", len(files) == 3)
	for _, row := range files {
		name := Str(row, "name")
		h.Check("signed_definition_name_"+name, regexp.MustCompile(`^(main|daily|bytecode)\.(cvd|cld)$`).MatchString(name) && !seen[strings.Split(name, ".")[0]])
		seen[strings.Split(name, ".")[0]] = true
		path := filepath.Join(directory, name)
		var stat unix.Stat_t
		Must(unix.Lstat(path, &stat))
		h.Check("signed_definition_inode_"+name, stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&07777 == 0400 && stat.Uid == uint32(os.Getuid()) && stat.Nlink == 1 && stat.Size == Int(row, "bytes") && uint64(stat.Dev) == uint64(Int(row, "device")) && stat.Ino == uint64(Int(row, "inode")) && stat.Mtim.Nano() == Int(row, "modified_ns") && stat.Ctim.Nano() == Int(row, "changed_ns"))
		h.Check("signed_definition_sha256_"+name, FileDigest(path) == Str(row, "sha256"))
		matching := false
		for _, verified := range List(final, "definitions") {
			if Str(verified, "definition") == strings.Split(name, ".")[0] {
				matching = Bool(verified, "origin_confirmed") && Bool(verified, "artifact_verified") && Str(verified, "artifact", "sha256") == Str(row, "sha256") && Int(verified, "artifact", "bytes") == Int(row, "bytes")
			}
		}
		h.Check("signed_definition_matches_verified_final_"+name, matching)
	}
	value := Object{"update_id": id, "generation": definition["generation"], "confirmed": definition["confirmed"], "manifest_sha256": definition["manifest_sha256"], "image_manifest_sha256": definition["image_manifest_sha256"], "image_path": filepath.Join(directory, "definitions.ext4"), "image": imageManifest["image"], "profile": imageManifest["profile"], "binding": imageManifest["binding"]}
	Must(hostvm.ValidateDefinition(value, h.Data, true))
	var imageStat unix.Stat_t
	Must(unix.Lstat(Str(value, "image_path"), &imageStat))
	h.Check("adopted_image_readonly_identity", imageStat.Mode&unix.S_IFMT == unix.S_IFREG && imageStat.Mode&07777 == 0400 && imageStat.Uid == uint32(os.Getuid()) && imageStat.Nlink == 1 && imageStat.Size == 1<<30 && uint64(imageStat.Dev) == uint64(Int(value, "image", "device")) && imageStat.Ino == uint64(Int(value, "image", "inode")) && imageStat.Mtim.Nano() == Int(value, "image", "modified_ns") && imageStat.Ctim.Nano() == Int(value, "image", "changed_ns"))
	h.Check("adopted_image_sha256", FileDigest(Str(value, "image_path")) == Str(value, "image", "sha256"))
	h.Record["signature_proof_scope"] = "durable fixed-adapter fc_test_database verification Final, approval deadline, candidate/image/profile bindings and current file SHA256; no signature rerun or new update"
	return value
}

func deliveryService(h *Harness, plan deliveryPlan) Object {
	h.Check("delivery_peer_identity_host", runtime.GOOS == "darwin")
	connection, err := net.DialTimeout("unix", h.Socket, 5*time.Second)
	Must(err)
	defer connection.Close()
	raw, err := connection.(*net.UnixConn).SyscallConn()
	Must(err)
	pid := 0
	var identityErr error
	// sys/un.h defines SOL_LOCAL=0 and LOCAL_PEERPID=2 on macOS.
	Must(raw.Control(func(fd uintptr) { pid, identityErr = unix.GetsockoptInt(int(fd), 0, 2) }))
	Must(identityErr)
	identity, err := hostvm.NativeIdentity(pid)
	Must(err)
	h.Check("ordinary_existing_service_identity", identity != nil && Int(identity, "uid") == int64(os.Getuid()) && Int(identity, "start_abstime") > 0 && Int(identity, "exit_abstime") == 0)
	r := Execute(h.Root, []string{"/bin/ps", "-p", strconv.Itoa(pid), "-o", "comm="}, nil, 5*time.Second)
	h.Check("ordinary_service_executable_available", r.ExitCode == 0 && len(r.Stderr) == 0)
	executable := strings.TrimSpace(string(r.Stdout))
	canonical, err := filepath.EvalSymlinks(executable)
	Must(err)
	h.Check("ordinary_service_is_installed_go_product", canonical == plan.Product.Path && FileDigest(canonical) == plan.Product.SHA256)
	code, health := h.CLI("health")
	h.Check("ordinary_cli_health_and_customer_flag", code == 0 && Bool(health, "stage0_passed") && Bool(health, "pass_enabled") && Bool(health, "release_enabled") && Get(health, "customer_operation_enabled") == plan.Stage3Completed)
	code, _ = h.CLI("list", "--limit", "20")
	h.Check("ordinary_cli_list_available", code == 0)
	code, _ = h.CLI("destinations")
	h.Check("ordinary_cli_destinations_available", code == 0)
	return Object{"pid": pid, "start_abstime": identity["start_abstime"], "uid": identity["uid"], "binary_sha256": plan.Product.SHA256}
}
func deliveryInspect(h *Harness, plan deliveryPlan) Object {
	code, job := h.CLI("inspect", plan.Original.JobID)
	h.Check("ordinary_existing_job_available", code == 0 && Str(job, "job_id") == plan.Original.JobID && Str(job, "input_receipt", "sha256") == plan.Original.SHA256 && Int(job, "input_receipt", "byte_size") == plan.Original.Bytes && Bool(job, "input_receipt", "content_available"))
	return job
}
func deliveryScanProof(h *Harness, plan deliveryPlan, job, definition Object) Object {
	attempt := Str(job, "attempt_id")
	h.Check("genuine_installed_host_PASS", Str(job, "phase") == "FINISHED" && Str(job, "verdict") == "PASS" && Bool(job, "coverage", "required_checks_complete") && Bool(job, "runtime_cleanup_complete") && Bool(job, "release", "eligible"))
	directory := filepath.Join(h.Data, "runtime", attempt)
	out := filepath.Join(directory, "output")
	request := Decode(deliveryRead(filepath.Join(directory, "request.json"), 16384))
	summary := Decode(deliveryRead(filepath.Join(out, "results.json"), 1<<20))
	reportBody := deliveryRead(filepath.Join(out, "report.json"), 1<<20)
	report := Decode(reportBody)
	h.Check("genuine_scan_dispatch_original_and_adopted_definition", Int(request, "schema_version") == 3 && Str(request, "job_id") == plan.Original.JobID && Str(request, "attempt_id") == attempt && Str(request, "expected_sha256") == plan.Original.SHA256 && Int(request, "byte_size") == plan.Original.Bytes && Equal(request["definition"], definition))
	h.Check("genuine_scan_report_accepted_complete_clean", Bool(summary, "passed") && Bool(summary, "report_accepted") && Str(summary, "report_sha256") == Digest(reportBody) && Int(report, "schema_version") == 2 && Str(report, "job_id") == plan.Original.JobID && Str(report, "attempt_id") == attempt && Equal(report["input"], Object{"sha256": plan.Original.SHA256, "byte_size": plan.Original.Bytes}) && Bool(report, "report_complete") && Bool(report, "manifest_complete") && Get(report, "result", "required_checks_complete") == false && Bool(report, "result", "structure_checks_complete") && Bool(report, "result", "format_checks_complete") && Str(report, "result", "structure_status") == "ACCEPT_FORMAT_STRUCTURE" && Str(report, "av_process_status") == "completed" && Str(report, "av_result") == "clean" && Bool(report, "av", "results_complete") && Bool(report, "av", "binding_verified") && Equal(Get(report, "av", "binding"), definition["binding"]) && Int(report, "av", "required_input_count") > 0 && Int(report, "av", "required_input_count") == Int(report, "av", "normal_result_count"))
	required, normal := map[string]bool{}, map[string]bool{}
	for _, item := range List(report, "result", "manifest") {
		if Bool(item, "av_required") {
			key := string(Encoded([]any{Get(item, "object_id"), Get(item, "sha256"), Get(item, "byte_size")}))
			h.Check("required_scan_object_unique", !required[key])
			required[key] = true
		}
	}
	for _, item := range List(report, "av", "objects") {
		key := string(Encoded([]any{Get(item, "object_id"), Get(item, "sha256"), Get(item, "byte_size")}))
		h.Check("normal_scan_object_verified_once", Bool(item, "input_verified") && Bool(item, "normal_result_present") && !normal[key])
		normal[key] = true
	}
	h.Check("all_required_scan_objects_have_normal_results", Equal(required, normal) && int64(len(required)) == Int(report, "av", "required_input_count"))
	complete := Decode(deliveryRead(filepath.Join(out, "cleanup-complete.json"), 1<<20))
	intent := Decode(deliveryRead(filepath.Join(out, "cleanup-intent.json"), 1<<20))
	proof := Decode(deliveryRead(filepath.Join(out, "stop-proof.json"), 1<<20))
	nativeBody := deliveryRead(filepath.Join(out, "watchdog/results.json"), 16<<20)
	native := Decode(nativeBody)
	bound := Object{"job_id": plan.Original.JobID, "attempt_id": attempt, "input_sha256": plan.Original.SHA256, "byte_size": plan.Original.Bytes}
	same := true
	for _, value := range []Object{complete, intent, proof} {
		for key, want := range bound {
			same = same && Equal(value[key], want)
		}
	}
	h.Check("genuine_scan_STOP_cleanup_hash_chain", same && Str(complete, "cleanup_intent_sha256") == FileDigest(filepath.Join(out, "cleanup-intent.json")) && Str(complete, "stop_proof_sha256") == FileDigest(filepath.Join(out, "stop-proof.json")) && Str(intent, "stop_proof_sha256") == FileDigest(filepath.Join(out, "stop-proof.json")) && Str(intent, "slot_owner_sha256") == FileDigest(filepath.Join(out, "slot-owner.json")) && Bool(proof, "stopped") && Equal(summary["native_evidence"], Object{"path": "watchdog/results.json", "sha256": Digest(nativeBody)}) && Equal(proof["evidence"], summary["native_evidence"]))
	stopped := len(List(native, "cleanup_after")) > 0
	for _, row := range List(native, "cleanup_after") {
		stopped = stopped && Get(row, "same_identity_live") == false
	}
	absent := true
	for _, row := range List(intent, "directories") {
		absent = absent && !Exists(Str(row, "path"))
	}
	h.Check("genuine_scan_guardian_reservation_zero", Bool(native, "qemu_started") && Bool(native, "guardian_result_verified") && Bool(native, "cleanup_all_exited") && Bool(native, "temporary_service_absent") && Get(native, "emergency_owned_cleanup") != true && Str(native, "terminal", "reason") == "EXCHANGE_COMPLETE" && Bool(native, "terminal", "all_exited") && stopped && absent && Bool(complete, "raw_reclaimed") && Bool(complete, "external_directories_reclaimed") && Bool(summary, "raw_reclaimed") && Bool(summary, "vm_slot_finalized") && Int(summary, "reservation_charge_bytes") == 0)
	producer := Decode(deliveryRead(filepath.Join(out, "watchdog/producer-source.json"), 1<<20))
	h.Check("genuine_scan_direct_go_runner", Str(producer, "runner") == plan.Scan.Runner.Path && Str(producer, "runner_sha256") == plan.Scan.Runner.SHA256)
	h.Check("genuine_scan_same_reviewed_go_build", Str(producer, "vm_build_sha256") == Str(h.Record, "scan_build_sha256"))
	config := Decode(deliveryRead(filepath.Join(out, "watchdog/config.json"), 1<<20))
	argv := List(config, "vm_argv")
	nicNone := false
	for i, value := range argv {
		if value == "-nic" && i+1 < len(argv) {
			nicNone = argv[i+1] == "none"
		}
	}
	h.Check("genuine_scan_300_seconds_and_no_network", Str(config, "owner_kind") == "scan" && Int(config, "continuous_deadline_ns")-Int(config, "continuous_start_ns") == 300000000000 && nicNone && Str(config, "helper_pins", Str(definition, "image_path")) == Str(definition, "image", "sha256"))
	return Object{"attempt_id": attempt, "report": Object{"path": filepath.Join(out, "report.json"), "sha256": Digest(reportBody)}, "native": Object{"path": filepath.Join(out, "watchdog/results.json"), "sha256": Digest(nativeBody)}, "runner_sha256": plan.Scan.Runner.SHA256}
}
func deliveryCheckDelta(h *Harness, before, after Object, phase, job, attempt, release, destination string) {
	allowed := map[string]string{}
	if phase == "rescan" {
		allowed = map[string]string{"jobs": job, "attempts": attempt, "runtime_runs": attempt, "runtime_finalizations": attempt, "scan_definition_snapshots": attempt, "scan_release_snapshots": attempt}
	}
	if phase == "release" {
		allowed = map[string]string{"releases": release, "release_publication_attempts": release, "release_authorizations": release, "release_destinations": destination}
	}
	for _, table := range deliveryTables {
		left, right := Map(before, table, "rows"), Map(after, table, "rows")
		l, r := Object{}, Object{}
		for k, v := range left {
			l[k] = v
		}
		for k, v := range right {
			r[k] = v
		}
		if id, ok := allowed[table]; ok {
			if table == "jobs" || table == "release_destinations" {
				delete(l, id)
				delete(r, id)
				h.Check("only_target_row_changes_"+table, Equal(l, r) && Int(before, table, "count") == Int(after, table, "count"))
			} else {
				h.Check("one_new_runtime_or_publication_row_"+table, left[id] == nil && right[id] != nil && Int(after, table, "count") == Int(before, table, "count")+1)
				delete(r, id)
				h.Check("old_rows_unchanged_"+table, Equal(l, r))
			}
		} else {
			h.Check("unchanged_delivery_table_"+table, Equal(before[table], after[table]))
		}
	}
}
func deliveryPublication(h *Harness, plan deliveryPlan, published Object) {
	h.Check("committed_same_original_publication", Str(published, "job_id") == plan.Original.JobID && Str(published, "destination_id") == plan.Destination.ID && Str(published, "state") == "COMMITTED" && Bool(published, "success") && Bool(published, "publication_confirmed") && Bool(published, "resources_finalized"))
	name := Str(published, "output_name")
	h.Check("publication_name_is_basename", name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsRune(name, 0))
	deliveryPrivate(h, "publication_destination", plan.Destination.Path)
	destinations := QueryObjects(h, "SELECT data FROM release_destinations WHERE id=?", plan.Destination.ID)
	h.Check("publication_uses_reviewed_configured_destination", len(destinations) == 1 && Str(destinations[0], "id") == plan.Destination.ID && Str(destinations[0], "path") == plan.Destination.Path && Get(destinations[0], "disabled") == false)
	path := filepath.Join(plan.Destination.Path, name)
	var info unix.Stat_t
	Must(unix.Lstat(path, &info))
	h.Check("published_original_inode_and_SHA", info.Mode&unix.S_IFMT == unix.S_IFREG && info.Uid == uint32(os.Getuid()) && info.Nlink == 1 && info.Size == plan.Original.Bytes && FileDigest(path) == plan.Original.SHA256)
	h.Record["publication_file"] = Object{"path": path, "sha256": plan.Original.SHA256, "byte_size": plan.Original.Bytes}
}

func deliveryMapping() Object {
	return Object{"old_sources": []Object{{"path": "final-stage3-metadata-e2e-20261104/run.py", "sha256": "78a8cac89008b3152be6fe0928c85f11490f971ca2d23e99a4770de30b02e677", "original_condition_count": 45}, {"path": "final-local-placement-20261104/run.py", "sha256": "e54ebad7e765bf93b23d9082c399c945fb72b0403ce6801752a15e3b94f2b04c", "original_condition_count": 61}}, "covered": []string{"existing installation UUID, ban snapshot, definition and unchanged update history", "schema2 normal registration and pinned direct Go runners/helpers", "adopted signatures through durable fixed-adapter Final and current definition/image hashes", "installed manifest binary/customer flag and reviewed source binding", "reviewed ordinary Go launcher without an interpreter invocation", "one existing harmless original SHA", "public CLI real rescan PASS, publication and restart persistence in separate phases"}, "not_replayed": []string{"legacy/default/qualified installer matrix and synthetic negative install/tamper fixtures", "installation, runtime replacement, service lifecycle, launcher placement and browser launch; root owns those operations", "all original 45 and 61 conditions as unconditional equal-scope assertions", "all historical fixture directories or arbitrary original files; this suite checks the reviewed existing job"}, "old_python_execution_required": false}
}
func runDeliveryCurrent(h *Harness) {
	mode := h.Mode
	if mode == "" {
		mode = "metadata"
	}
	h.Check("delivery_phase", mode == "capture" || mode == "metadata" || mode == "available" || mode == "rescan" || mode == "release" || mode == "reopen")
	h.Check("delivery_existing_state_and_reviewed_plan_required", h.Paths["state-directory"] != "" && h.BinaryProof != "")
	body := deliveryRead(h.BinaryProof, 65536)
	var plan deliveryPlan
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	Must(decoder.Decode(&plan))
	if decoder.Decode(new(any)) != io.EOF {
		panic(Failure{"DELIVERY_PLAN_TRAILING_DATA"})
	}
	h.Check("delivery_reviewed_scope", plan.Schema == 1 && plan.DataDirectory == h.Paths["state-directory"] && deliveryJobID.MatchString(plan.Original.JobID) && deliveryDigest.MatchString(plan.Original.SHA256) && plan.Original.Bytes > 0 && plan.ExpectedUUID != "")
	h.Data = plan.DataDirectory
	h.Socket = filepath.Join(h.Data, "filegate.sock")
	identity := deliveryPrivate(h, "existing_data", h.Data)
	h.Check("existing_state_database", Exists(filepath.Join(h.Data, "state.sqlite")))
	h.Record["kind"] = "filegate-delivery-phase"
	h.Record["delivery_mode"] = mode
	h.Record["existing_data_directory"] = h.Data
	h.Record["data_identity"] = identity
	h.Record["expected_uuid"] = plan.ExpectedUUID
	h.Record["delivery_original_job_id"] = plan.Original.JobID
	h.Record["delivery_plan_sha256"] = Digest(body)
	h.Record["reviewed_stage3_completed"] = plan.Stage3Completed
	h.Record["existing_files_copied"] = false
	h.Record["db_seeded_or_clock_changed"] = false
	h.Record["new_update_requested"] = false
	h.Record["service_lifecycle_owned_by_root"] = true
	h.Record["UI_or_bootstrap_requested"] = false
	h.Record["delivery_complete"] = false
	h.Record["legacy_mapping"] = deliveryMapping()
	WriteJSON(filepath.Join(h.Out, "delivery-scope-mapping.json"), deliveryMapping())
	initial := SnapshotUpdate(filepath.Join(h.Data, "state.sqlite"), true, false)
	control := Map(initial, "control")
	h.Check("same_reviewed_original_UUID", Str(control, "snapshot", "uuid") == plan.ExpectedUUID)
	h.Check("no_active_or_reserved_update", Str(control, "active_update_id") == "" && Int(initial, "reserved_bytes") == 0)
	before := deliveryRowSnapshot(h)
	h.Check("existing_state_has_no_inflight_intake_scan_or_publication", Int(before, "reservations", "count") == 0 && Int(before, "scan_queue", "count") == 0 && Int(before, "resource_pins", "count") == 0 && Int(before, "release_reservations", "count") == 0)
	receipt := deliveryOriginal(h, plan)
	invariant := deliveryInvariant(control)
	h.Record["control_invariant"] = invariant
	h.Record["protected_update_tables"] = deliveryProtected(before)
	if mode == "capture" {
		after := SnapshotUpdate(filepath.Join(h.Data, "state.sqlite"), true, false)
		h.Check("capture_is_readonly", Equal(invariant, deliveryInvariant(Map(after, "control"))) && Equal(before, deliveryRowSnapshot(h)))
		h.Record["baseline"] = Object{"control_invariant": invariant, "protected_update_tables": deliveryProtected(before), "original_receipt": receipt, "data_identity": identity}
		h.Record["scope"] = "read-only capture of existing normal state; no source/runtime/install acceptance or lifecycle operation"
		return
	}
	baseline := deliveryBaseline(h, plan, identity)
	h.Check("UUID_bans_generation_definition_and_history_preserved", Equal(invariant, baseline["control_invariant"]) && Equal(deliveryProtected(before), baseline["protected_update_tables"]) && Equal(receipt, baseline["original_receipt"]))
	registration := deliveryMetadata(h, plan, control)
	definition := deliveryAdoption(h, control, registration)
	h.Record["normal_registration_sha256"] = plan.Registration.SHA256
	h.Record["installed_product_sha256"] = plan.Product.SHA256
	h.Record["adopted_definition"] = Object{"update_id": definition["update_id"], "manifest_sha256": definition["manifest_sha256"], "image_manifest_sha256": definition["image_manifest_sha256"]}
	h.Record["scope"] = "existing normal Go installation delivery phase; no data recreation, SQL writes, file copies, update retry, install or service lifecycle by this harness"
	var service Object
	var job Object
	attempt, release := "", ""
	if mode != "metadata" {
		service = deliveryService(h, plan)
		h.Record["service_identity"] = service
		h.Record["existing_service_retained"] = true
		job = deliveryInspect(h, plan)
	}
	switch mode {
	case "rescan":
		now, err := updatecontrol.ReadClock()
		Must(err)
		confirmed := Map(definition, "confirmed")
		h.Check("fresh_existing_definition_before_rescan_no_update", now.Boot == Str(confirmed, "boot") && now.UTC >= Int(confirmed, "utc") && now.UTC-Int(confirmed, "utc") <= 85800 && now.ContinuousNS >= uint64(Int(confirmed, "continuous_ns")) && now.ContinuousNS-uint64(Int(confirmed, "continuous_ns")) <= 85800000000000)
		oldAttempt := Str(job, "attempt_id")
		code, rescan := h.CLI("rescan", plan.Original.JobID)
		attempt = Str(rescan, "attempt_id")
		h.Check("ordinary_installed_host_rescan_admitted", code == 0 && attempt != "" && attempt != oldAttempt && Equal(rescan["input_receipt"], receipt))
		deadline := time.Now().Add(360 * time.Second)
		next := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			job = deliveryInspect(h, plan)
			phase := Str(job, "phase")
			if Str(job, "finished_at") != "" && (phase == "FINISHED" || phase == "FAILED" || phase == "CANCELLED") {
				break
			}
			if time.Now().After(next) {
				fmt.Println(string(Encoded(Object{"event": "DELIVERY_RESCAN_WAITING", "attempt_id": attempt})))
				next = next.Add(30 * time.Second)
			}
			time.Sleep(150 * time.Millisecond)
		}
		h.Check("installed_host_rescan_attempt_preserved", Str(job, "attempt_id") == attempt)
		h.Record["genuine_scan_proof"] = deliveryScanProof(h, plan, job, definition)
		h.Record["scan_attempt_id"] = attempt
	case "release":
		previous := deliveryPrevious(h, "prior_genuine_go_PASS", plan.Previous, "rescan", plan)
		attempt = Str(previous, "scan_attempt_id")
		h.Check("publication_uses_same_verified_go_scan", Str(previous, "installed_product_sha256") == plan.Product.SHA256 && Str(previous, "normal_registration_sha256") == plan.Registration.SHA256 && Str(job, "attempt_id") == attempt)
		h.Record["genuine_scan_proof"] = deliveryScanProof(h, plan, job, definition)
		h.Check("reviewed_publication_destination_and_key", plan.Destination.ID != "" && plan.Destination.Path != "" && plan.ReleaseKey != "")
		code, value := h.CLI("release", plan.Original.JobID, "--destination", plan.Destination.ID, "--idempotency-key", plan.ReleaseKey)
		release = Str(value, "release_id")
		h.Check("ordinary_publication_new_idempotent_reservation", code == 0 && release != "" && Get(value, "replayed") == false)
		deadline := time.Now().Add(40 * time.Second)
		published := value
		for time.Now().Before(deadline) {
			code, published = h.CLI("release-status", release)
			h.Check("publication_status_available", code == 0)
			state := Str(published, "state")
			if state == "COMMITTED" || state == "ABORTED" || state == "PUBLISHED_UNVERIFIED" || state == "REVALIDATION_REQUIRED" || state == "RECOVERY_REQUIRED" {
				break
			}
			time.Sleep(30 * time.Millisecond)
		}
		deliveryPublication(h, plan, published)
		records := QueryObjects(h, "SELECT data FROM releases WHERE id=?", release)
		h.Check("published_authorization_bound_to_existing_original", len(records) == 1 && Str(records[0], "object_id") == Str(receipt, "object_id") && Str(records[0], "sha256") == plan.Original.SHA256 && Int(records[0], "byte_size") == plan.Original.Bytes && Str(records[0], "authorization", "attempt_id") == attempt && Str(records[0], "destination", "path") == plan.Destination.Path)
		h.Record["scan_attempt_id"] = attempt
		h.Record["release_receipt"] = published
	case "reopen":
		previous := deliveryPrevious(h, "prior_real_publication", plan.Previous, "release", plan)
		h.Check("same_installed_product_and_registered_runtime_after_restart", Str(previous, "installed_product_sha256") == plan.Product.SHA256 && Str(previous, "normal_registration_sha256") == plan.Registration.SHA256)
		old := Map(previous, "service_identity")
		h.Check("ordinary_restart_changed_process_start_identity", !Equal(old, service) && hostvm.IdentityReadback(old)["same_identity_live"] == false)
		attempt = Str(previous, "scan_attempt_id")
		h.Check("same_genuine_PASS_after_ordinary_restart", Str(job, "attempt_id") == attempt)
		h.Record["genuine_scan_proof"] = deliveryScanProof(h, plan, job, definition)
		release = Str(previous, "release_receipt", "release_id")
		code, published := h.CLI("release-status", release)
		h.Check("existing_publication_after_restart", code == 0 && Str(published, "release_id") == release)
		deliveryPublication(h, plan, published)
		h.Record["scan_attempt_id"] = attempt
		h.Record["release_receipt"] = published
		h.Check("restart_preserved_all_delivery_rows", Equal(deliveryRowSnapshot(h), previous["delivery_rows_after"]))
		h.Record["delivery_complete"] = plan.Stage3Completed
	}
	afterState := SnapshotUpdate(filepath.Join(h.Data, "state.sqlite"), true, false)
	after := deliveryRowSnapshot(h)
	h.Check("original_UUID_bans_definition_and_update_history_unchanged", Equal(deliveryInvariant(Map(afterState, "control")), baseline["control_invariant"]) && Equal(deliveryProtected(after), baseline["protected_update_tables"]))
	h.Check("same_original_receipt_after_delivery_phase", Equal(deliveryOriginal(h, plan), receipt))
	deliveryCheckDelta(h, before, after, mode, plan.Original.JobID, attempt, release, plan.Destination.ID)
	h.Record["delivery_rows_after"] = after
	h.Record["normal_registration_unchanged_after_phase"] = FileDigest(plan.Registration.Path) == plan.Registration.SHA256
	h.Check("normal_registration_unchanged_after_phase", Bool(h.Record, "normal_registration_unchanged_after_phase"))
	if mode != "reopen" {
		h.Record["delivery_complete"] = false
	}
}
