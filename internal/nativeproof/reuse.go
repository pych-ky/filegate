package nativeproof

import (
	"io"
	"os"
	"path/filepath"
	"time"

	"filegate.local/filegate/internal/hostvm"
	"golang.org/x/sys/unix"
)

// adoptedReceiptSHA is the adopted candidate-10 scan build receipt that pins the native binary and its launchagent_death proof; reuse accepts no other receipt.
const adoptedReceiptSHA = "bfb5503a69a170e498d04911d2ee36317d492920837d41569941c9de49320e10"

func adoptedBinaryPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library/Application Support/FileGate/verification/experiments/host/.build/integrated-watchdog"), nil
}

// adoptedChain checks receipt → proof → binary/source/host and returns the proof; it never consults a compiler or build record.
func adoptedChain(r *hostvm.Runtime, receiptPath, proofPath, binarySHA, sourceSHA string) (object, error) {
	source, err := adoptedBinaryPath()
	if err != nil {
		return nil, err
	}
	receiptSHA, err := hostvm.HashFile(receiptPath)
	if err != nil || receiptSHA != adoptedReceiptSHA {
		return nil, failure("NATIVE_REUSE_RECEIPT_MISMATCH")
	}
	receipt, _, err := hostvm.Read(receiptPath, 1<<20)
	if err != nil {
		return nil, err
	}
	proofSHA, err := hostvm.HashFile(proofPath)
	inputs := hostvm.Map(receipt, "external_input_sha256")
	if err != nil || hostvm.Str(receipt, "native_proof_sha256") != proofSHA || hostvm.Str(inputs, proofPath) != proofSHA || hostvm.Str(inputs, source) != binarySHA {
		return nil, failure("NATIVE_REUSE_PROOF_MISMATCH")
	}
	proof, _, err := hostvm.Read(proofPath, 16<<20)
	if err != nil || hostvm.Str(proof, "kind") != "launchagent_death" || proof["passed"] != true || hostvm.Str(proof, "status") != "verified" ||
		hostvm.Str(proof, "binary_sha256") != binarySHA || hostvm.Str(proof, "native_source_sha256") != sourceSHA {
		return nil, failure("NATIVE_REUSE_PROOF_MISMATCH")
	}
	host, err := r.HostVersion()
	if err != nil {
		return nil, err
	}
	platform, err := r.NativePlatform()
	if err != nil || !hostvm.Equal(host, proof["host"]) || !hostvm.Equal(platform, proof["native_platform"]) {
		return nil, failure("NATIVE_REUSE_OS_TARGET_CHANGED")
	}
	return proof, nil
}

func fileIdentity(path string) (object, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return nil, err
	}
	return object{"device": int64(stat.Dev), "inode": int64(stat.Ino), "mode": int64(stat.Mode), "uid": int64(stat.Uid), "size": stat.Size, "mtime_ns": stat.Mtim.Nano()}, nil
}

// Reuse copies the adopted native binary bytes into a new directory with a reuse record linked by hashes to the adopted receipt and proof; it is not a build.
func Reuse(repo, out, receiptPath, proofPath string) (report object, returned error) {
	if _, err := canonical(repo); err != nil {
		return nil, err
	}
	source, err := adoptedBinaryPath()
	if err != nil {
		return nil, err
	}
	if canonicalPath, err := filepath.EvalSymlinks(source); err != nil || canonicalPath != source {
		return nil, failure("NATIVE_REUSE_SOURCE_NOT_CANONICAL")
	}
	before, err := fileIdentity(source)
	if err != nil {
		return nil, err
	}
	if uint32(hostvm.Int(before, "mode"))&unix.S_IFMT != unix.S_IFREG || uint32(hostvm.Int(before, "mode"))&07777 != 0700 || hostvm.Int(before, "uid") != int64(os.Getuid()) {
		return nil, failure("NATIVE_REUSE_SOURCE_IDENTITY_INVALID")
	}
	binarySHA, err := hostvm.HashFile(source)
	if err != nil {
		return nil, err
	}
	repoSource := filepath.Join(repo, "experiments/host/integrated_watchdog.m")
	sourceSHA, err := hostvm.HashFile(repoSource)
	if err != nil {
		return nil, err
	}
	if err = freshDirectory(out, repo); err != nil {
		return nil, err
	}
	binary := filepath.Join(out, "integrated-watchdog")
	report = object{"schema": 1, "kind": "go_native_monitor_reuse", "passed": false, "compiled": false, "binary": binary, "binary_sha256": binarySHA, "source_sha256": sourceSHA,
		"reused_from": object{"path": source, "identity_before": before}, "baseline_receipt": object{"path": receiptPath, "sha256": adoptedReceiptSHA}, "python_dependency": false,
		"scope":       "bytes copied from the adopted native binary pinned by the adopted receipt and launchagent_death proof; not a fresh compilation; no compiler, flags or build success are claimed",
		"created_utc": time.Now().UTC().Format(time.RFC3339)}
	in, err := os.OpenFile(source, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return report, err
	}
	defer in.Close()
	target, err := os.OpenFile(binary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0500)
	if err != nil {
		return report, err
	}
	_, err = io.Copy(target, in)
	if err == nil {
		err = target.Sync()
	}
	if closed := target.Close(); err == nil {
		err = closed
	}
	if err != nil {
		return report, err
	}
	if err = copyNewFile(repoSource, filepath.Join(out, "integrated_watchdog.m")); err != nil {
		return report, err
	}
	after, err := fileIdentity(source)
	afterSHA, hashErr := hostvm.HashFile(source)
	copied, copyErr := hostvm.HashFile(binary)
	if err != nil || hashErr != nil || copyErr != nil || !hostvm.Equal(after, before) || afterSHA != binarySHA || copied != binarySHA {
		return report, failure("NATIVE_REUSE_SOURCE_CHANGED_DURING_COPY")
	}
	report["reused_from"].(object)["identity_after"] = after
	r := &hostvm.Runtime{Root: repo, NativeBinary: binary, NativeSource: repoSource}
	proof, err := adoptedChain(r, receiptPath, proofPath, binarySHA, sourceSHA)
	if err != nil {
		return report, err
	}
	report["adopted_proof"] = object{"path": proofPath, "sha256": mustHash(proofPath), "kind": proof["kind"], "status": proof["status"]}
	report["host"], report["native_platform"] = proof["host"], proof["native_platform"]
	report["passed"] = true
	_, err = hostvm.WriteNew(filepath.Join(out, "reuse.json"), report)
	return report, err
}

func mustHash(path string) string {
	sum, _ := hostvm.HashFile(path)
	return sum
}

func copyNewFile(source, target string) error {
	body, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return saveBytes(target, body)
}

// reuseBinding re-validates a reuse directory against the adopted receipt and proof every time it is used.
func reuseBinding(repo, directory string) (*hostvm.Runtime, object, error) {
	record, _, err := hostvm.Read(filepath.Join(directory, "reuse.json"), 1<<20)
	if err != nil {
		return nil, nil, err
	}
	binary := filepath.Join(directory, "integrated-watchdog")
	if _, err = hostvm.Owned(binary, unix.S_IFREG, 0500); err != nil {
		return nil, nil, err
	}
	actual, err := hostvm.HashFile(binary)
	if err != nil {
		return nil, nil, err
	}
	source := filepath.Join(repo, "experiments/host/integrated_watchdog.m")
	sourceSHA, err := hostvm.HashFile(source)
	if err != nil {
		return nil, nil, err
	}
	copiedSHA, err := hostvm.HashFile(filepath.Join(directory, "integrated_watchdog.m"))
	if err != nil || hostvm.Int(record, "schema") != 1 || hostvm.Str(record, "kind") != "go_native_monitor_reuse" || record["passed"] != true || record["compiled"] != false ||
		hostvm.Str(record, "binary") != binary || hostvm.Str(record, "binary_sha256") != actual || hostvm.Str(record, "source_sha256") != sourceSHA || copiedSHA != sourceSHA ||
		hostvm.Str(hostvm.Map(record, "baseline_receipt"), "sha256") != adoptedReceiptSHA {
		return nil, nil, failure("NATIVE_REUSE_BINDING_INVALID")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, err
	}
	r := &hostvm.Runtime{Root: repo, NativeBinary: binary, NativeSource: source, State: filepath.Join(home, "Library/Application Support/FileGate/verification/experiments/host/.build")}
	if _, err = adoptedChain(r, hostvm.Str(hostvm.Map(record, "baseline_receipt"), "path"), hostvm.Str(hostvm.Map(record, "adopted_proof"), "path"), actual, sourceSHA); err != nil {
		return nil, nil, err
	}
	return r, record, nil
}
