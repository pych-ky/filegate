package verification

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// The proof CLI exposes guard results without changing the product entry point.
const vmPrepareProofMain = `package main
import (
 "context"
 "fmt"
 "os"
 "path/filepath"
 "filegate.local/filegate/internal/hostvm"
 "golang.org/x/sys/unix"
)
func main() {
 unix.Umask(0077)
 if len(os.Args)!=3 || os.Args[1]!="--run-directory" { os.Exit(2) }
 executable,err:=os.Executable()
 if err!=nil { os.Exit(2) }
 executable,err=filepath.EvalSymlinks(executable)
 if err!=nil { os.Exit(2) }
 root:=filepath.Dir(filepath.Dir(executable))
 runtime,err:=hostvm.New(root)
 if err==nil { _,err=runtime.PrepareFixture(context.Background(),os.Args[2],"transfer") }
 if err==nil { fmt.Fprintln(os.Stderr,"UNEXPECTED_ALLOCATION");os.Exit(2) }
 code:=err.Error()
 if os.IsNotExist(err) {
  if _,missing:=os.Lstat(filepath.Join(root,"experiments/vm/evidence/build.json"));os.IsNotExist(missing) {
   code="PREPARATION_BUILD_RECEIPT_REQUIRED"
  }
 }
 switch code {
 case "PREPARATION_BUILD_RECEIPT_REQUIRED","PREPARATION_DIRECTORY_SCOPE_INVALID","PREPARATION_DIRECTORY_NOT_EMPTY","OWNED_PATH_INVALID":
  fmt.Fprintln(os.Stderr,code)
 default:
  fmt.Fprintln(os.Stderr,"PREPARATION_UNEXPECTED_FAILURE")
 }
 os.Exit(1)
}
`

func vmProofName(prefix string) string {
	value := make([]byte, 16)
	_, err := rand.Read(value)
	Must(err)
	return filepath.Join("/private/tmp", prefix+hex.EncodeToString(value))
}

func runVMPrepareContract(h *Harness) {
	workspace := filepath.Join(h.Out, "prepare-workspace")
	Must(os.MkdirAll(filepath.Join(workspace, ".build"), 0700))
	binary := filepath.Join(workspace, ".build/filegate-vm")
	entry := filepath.Join(h.Out, "prepare-main.go")
	Write(entry, []byte(vmPrepareProofMain))
	overlay := filepath.Join(h.Out, "prepare-overlay.json")
	WriteJSON(overlay, Object{"Replace": Object{filepath.Join(h.Root, "cmd/filegate-vm/main.go"): entry}})
	arguments := []string{"go", "build", "-trimpath", "-buildvcs=false", "-overlay", overlay, "-o", binary, "./cmd/filegate-vm"}
	built := Execute(h.Root, arguments, nil, 3*time.Minute)
	Write(filepath.Join(h.Out, "prepare-build.log"), append(built.Stdout, built.Stderr...))
	h.Record["prepare_cli_build"] = Object{"argv": arguments, "exit_code": built.ExitCode, "overlay_sha256": FileDigest(overlay), "entrypoint_sha256": FileDigest(entry)}
	h.Check("prepare_proof_cli_build", built.ExitCode == 0)
	h.Record["prepare_cli_sha256"] = FileDigest(binary)
	h.Record["evidence_kind"] = "real_Go_prepare_CLI_guards_before_allocation_only"
	h.Record["allocation_executed"], h.Record["vm_started"] = false, false
	h.Record["contract_changes"] = []string{"canonical /private/tmp paths are required; /tmp alias is refused", "a missing build receipt stops valid directories before dependencies and allocation", "proof-only main exposes typed errors; the hostvm preparation implementation is unchanged"}

	created := []string{}
	directory := func(prefix string) string {
		path := vmProofName(prefix)
		Must(os.Mkdir(path, 0700))
		created = append(created, path)
		return path
	}
	file := func(path string, body []byte) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		Must(err)
		_, err = f.Write(body)
		Must(err)
		Must(f.Close())
		created = append(created, path)
	}
	valid := directory("filegate-vm-")
	wrongMode := directory("filegate-vm-")
	Must(os.Chmod(wrongMode, 0755))
	container := directory("filegate-prepare-container-")
	link := vmProofName("filegate-vm-")
	Must(os.Symlink(valid, link))
	created = append(created, link)
	wrongParent := filepath.Join(container, filepath.Base(vmProofName("filegate-vm-")))
	Must(os.Mkdir(wrongParent, 0700))
	created = append(created, wrongParent)
	wrongPrefix := directory("filegate-prepare-other-")
	existingRaw := directory("filegate-vm-")
	raw := filepath.Join(existingRaw, "work.raw")
	file(raw, []byte("synthetic existing raw refusal fixture\n"))
	rawSHA := FileDigest(raw)
	nonempty := directory("filegate-vm-")
	file(filepath.Join(nonempty, "marker"), []byte("synthetic\n"))
	ordinary := vmProofName("filegate-vm-")
	file(ordinary, []byte("synthetic\n"))
	missing := vmProofName("filegate-vm-")
	h.Record["owned_fixture_paths"] = created
	rows := []Object{}
	for _, test := range []struct{ name, path, failure string }{
		{"owned_empty_0700", valid, "PREPARATION_BUILD_RECEIPT_REQUIRED"},
		{"tmp_parent_alias", filepath.Join("/tmp", filepath.Base(valid)), "PREPARATION_DIRECTORY_SCOPE_INVALID"},
		{"mode_0755", wrongMode, "OWNED_PATH_INVALID"},
		{"symlink", link, "PREPARATION_DIRECTORY_SCOPE_INVALID"},
		{"wrong_parent", wrongParent, "PREPARATION_DIRECTORY_SCOPE_INVALID"},
		{"wrong_prefix", wrongPrefix, "PREPARATION_DIRECTORY_SCOPE_INVALID"},
		{"existing_raw", existingRaw, "PREPARATION_DIRECTORY_NOT_EMPTY"},
		{"nonempty", nonempty, "PREPARATION_DIRECTORY_NOT_EMPTY"},
		{"regular_file", ordinary, "OWNED_PATH_INVALID"},
		{"missing", missing, "PREPARATION_DIRECTORY_SCOPE_INVALID"},
	} {
		command := exec.Command(binary, "--run-directory", test.path)
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, "PATH=") {
				command.Env = append(command.Env, value)
			}
		}
		command.Env = append(command.Env, "PATH=")
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Start()
		Must(err)
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		code := 0
		select {
		case err = <-done:
			if err != nil {
				status, ok := err.(*exec.ExitError)
				h.Check(test.name+"_exit_status", ok)
				code = status.ExitCode()
			}
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-done
			h.Check(test.name+"_bounded", false)
		}
		row := Object{"id": test.name, "argv": command.Args, "environment_override": Object{"PATH": ""}, "expected_exit": 1, "expected_stderr": test.failure + "\n", "exit_code": code, "stdout": stdout.String(), "stderr": stderr.String()}
		rows = append(rows, row)
		h.Record["cases"] = rows
		WriteJSON(filepath.Join(h.Out, "prepare-cases.json"), rows)
		h.Check(test.name, code == 1 && stdout.Len() == 0 && stderr.String() == test.failure+"\n", row)
	}
	entries, err := os.ReadDir(valid)
	Must(err)
	h.Check("valid_directory_remains_empty", len(entries) == 0)
	h.Check("existing_raw_remains_unchanged", FileDigest(raw) == rawSHA)
	var identity unix.Stat_t
	Must(unix.Lstat(valid, &identity))
	h.Record["valid_directory_identity"] = Object{"uid": identity.Uid, "mode": identity.Mode & 07777, "inode": identity.Ino, "device": identity.Dev}
	h.Record["existing_raw_sha256"] = rawSHA
	h.Record["unproven"] = []string{"different-owner refusal", "allocation and prepared.json publication", "directory replacement during allocation", "actual QEMU/HVF or guest execution"}
	for index := len(created) - 1; index >= 0; index-- {
		Must(os.Remove(created[index]))
	}
	h.Record["owned_fixture_paths_removed"] = true
}

func init() { Register("prepare-contract", runVMPrepareContract) }
