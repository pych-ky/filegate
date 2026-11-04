package av

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"filegate.local/filegate/internal/inspect"
	"golang.org/x/sys/unix"
)

const work = "/job/adapter-tmp/filegate-av"

func environment() bool {
	if runtime.GOOS != "linux" || runtime.GOARCH != "arm64" || os.Geteuid() != 65534 || os.Getegid() != 65534 {
		return false
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagLoopback == 0 {
		return false
	}
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, 16385))
	return err == nil && len(body) <= 16384 && strings.Contains(string(body), "NoNewPrivs:\t1\n") && strings.Contains(string(body), "CapEff:\t0000000000000000\n")
}

func inputs(format inspect.Result) ([]ObjectResult, []string, error) {
	if len(format.Manifest) == 0 || len(format.Manifest) > 10001 || format.RequiredAVInputCount < 1 || format.RequiredAVInputCount > 10001 {
		return nil, nil, invalid
	}
	objects := []ObjectResult{}
	paths := []string{}
	ids, names := map[string]bool{}, map[string]bool{}
	var extracted int64
	for index, object := range format.Manifest {
		if !objectID.MatchString(object.ID) || ids[object.ID] {
			return nil, nil, invalid
		}
		ids[object.ID] = true
		if !object.AVRequired {
			if index == 0 || object.Kind != "verified_empty_directory" || object.AVExclusionReason != "VERIFIED_EMPTY_DIRECTORY" || object.ByteSize != 0 || object.Path != "" || object.SHA256 != "" {
				return nil, nil, invalid
			}
			continue
		}
		if !validDigest(object.SHA256) || object.ByteSize < 0 || object.ByteSize > inspect.InputLimit || object.AVExclusionReason != "" {
			return nil, nil, invalid
		}
		path := "/job/input/object"
		if index == 0 {
			if object.ParentID != "" || object.Path != "" {
				return nil, nil, invalid
			}
		} else {
			if !storedName.MatchString(object.Path) || names[object.Path] || object.ByteSize > inspect.FileLimit {
				return nil, nil, invalid
			}
			names[object.Path] = true
			extracted += object.ByteSize
			path = "/job/extract/" + object.Path
		}
		objects = append(objects, ObjectResult{ObjectID: object.ID, SHA256: object.SHA256, ByteSize: object.ByteSize, Status: "pending", ReasonCode: "INCOMPLETE_REQUIRED_CHECKS"})
		paths = append(paths, path)
	}
	if len(objects) != format.RequiredAVInputCount || extracted > inspect.TotalLimit {
		return nil, nil, invalid
	}
	return objects, paths, nil
}

// Run does not adopt definitions or authorize PASS; those are host decisions.
func Run(ctx context.Context, format inspect.Result) Result {
	pending := NotStarted("INCOMPLETE_REQUIRED_CHECKS")
	if format.StructureStatus != "ACCEPT_FORMAT_STRUCTURE" || !format.StructureChecksComplete || !format.FormatChecksComplete {
		return pending
	}
	profile, binding, err := loadProfile()
	if err != nil {
		return pending
	}
	objects, paths, err := inputs(format)
	if err != nil {
		return pending
	}
	result := Result{SchemaVersion: 1, ProfileID: ProfileID, ProcessStatus: "failed", AVResult: "inconclusive", Binding: binding, RequiredInputCount: len(objects), Objects: objects, ReasonCodes: []string{}, ConfirmedDetections: []Detection{}}
	if !environment() || ctx.Err() != nil || verifyRuntime(ctx, profile, binding) != nil {
		finalize(&result)
		return result
	}
	for index, object := range objects {
		if hashFile(ctx, paths[index], object.ByteSize, object.SHA256, false) != nil {
			finalize(&result)
			return result
		}
	}
	if os.Mkdir(work, 0700) != nil {
		finalize(&result)
		return result
	}
	list, err := os.OpenFile(work+"/inputs.list", os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		finalize(&result)
		return result
	}
	_, writeErr := io.WriteString(list, strings.Join(paths, "\n")+"\n")
	syncErr, closeErr := list.Sync(), list.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		finalize(&result)
		return result
	}
	defer func() { os.Remove(work + "/inputs.list"); os.Remove(work) }()
	execution, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout, stderr := newCapture(StdoutLimit, cancel), newCapture(StderrLimit, cancel)
	command := exec.CommandContext(execution, scanner, arguments(profile, work)...)
	command.Dir = work
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "HOME=" + work, "TMPDIR=" + work, "TMP=" + work, "TEMP=" + work}
	command.Stdout, command.Stderr = stdout, stderr
	command.WaitDelay = 2 * time.Second
	if command.Start() != nil {
		finalize(&result)
		return result
	}
	waitErr := command.Wait()
	exit := command.ProcessState.ExitCode()
	result.ExitCode = &exit
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.ProcessStatus = "timed_out"
	} else if (waitErr == nil && exit == 0) || (exit == 1 && !stdout.overflow && !stderr.overflow && ctx.Err() == nil) {
		result.ProcessStatus = "completed"
	}
	result.BindingVerified = verifyRuntime(ctx, profile, binding) == nil
	for index, object := range result.Objects {
		err := hashFile(ctx, paths[index], object.ByteSize, object.SHA256, false)
		result.Objects[index].InputVerified = err == nil
		if err != nil {
			result.Objects[index].verificationFailure = "SCANNER_ERROR"
			if errors.Is(err, hashMismatch) {
				result.Objects[index].verificationFailure = "INPUT_HASH_MISMATCH"
			}
		}
	}
	normalize(&result, paths, stdout, stderr)
	return result
}
