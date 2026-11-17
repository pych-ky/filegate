package buildtools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const hostGo = "go version go1.27.3 darwin/arm64"
const observationSHA = "9911ded74d6240baf219dab9bb9b9cb185c913274dd63d42993d69df04dbcbca"
const oldObservationSHA = "2820f79fce99925c4bbf2301c2bae1c1276e8940439ce61926aadb473be7dd2e"
const rootfsSHA = "4d3f80afaebd447c5591a63a73bde380a149fe8b2d85488cafabb2ff97551f50"

type BuildOptions struct {
	Repository             string
	Verification           string
	Baseline               string
	BaselineProof          string
	NativeProof            string
	NativeBinary           string
	ReplacementNativeProof string
	BaselineBuild          string
	AdapterBuild           string
	FreshclamBinary        string
	FreshclamBuild         string
	Out                    string
	ReuseRegistration      string
	ParentRegistration     string
	GuestFixtures          bool
	Inspector              bool
	CheckInputs            bool
}

type CommandRecord struct {
	Argv           []string `json:"argv"`
	ExitCode       int      `json:"exit_code"`
	StdoutBytes    int      `json:"stdout_bytes"`
	StderrBytes    int      `json:"stderr_bytes"`
	StdoutArtifact string   `json:"stdout_artifact"`
	StderrArtifact string   `json:"stderr_artifact"`
	StdoutSHA256   string   `json:"stdout_sha256"`
	StderrSHA256   string   `json:"stderr_sha256"`
	Truncated      bool     `json:"output_truncated"`
}

func command(ctx context.Context, directory string, environment []string, argv ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = directory
	cmd.Env = environment
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("%s failed: %w: %s", filepath.Base(argv[0]), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func goEnvironment(target string) []string {
	values := map[string]string{"GOOS": target, "GOARCH": "arm64", "GOARM64": "v8.0", "CGO_ENABLED": "0", "GOFLAGS": "-mod=readonly", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off"}
	if target == "darwin" {
		values["CGO_ENABLED"] = "1"
	}
	return environment(values)
}

func environment(values map[string]string) []string {
	result := []string{}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, replacing := values[name]; !replacing {
			result = append(result, entry)
		}
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		result = append(result, name+"="+values[name])
	}
	return result
}

func requireToolchain(ctx context.Context) error {
	body, _, err := command(ctx, "", nil, "go", "version")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(body)) != hostGo {
		return errors.New("fixed Go1.27.3 darwin/arm64 toolchain required")
	}
	return nil
}

func verifyPins(pins map[string]string) error {
	for path, expected := range pins {
		if !validSHA(expected) {
			return fmt.Errorf("invalid source digest: %s", path)
		}
		actual, err := SHA(path)
		if err != nil || actual != expected {
			return fmt.Errorf("pinned source/artifact changed: %s", path)
		}
	}
	return nil
}

func copyFixed(source, target string) error {
	expected, err := SHA(source)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(target); err == nil {
		actual, hashErr := SHA(target)
		if hashErr != nil || actual != expected {
			return fmt.Errorf("existing fixed asset differs: %s", target)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return copyNew(source, target, 0)
}

func copyNew(source, target string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("copy source must be regular")
	}
	if mode == 0 {
		mode = info.Mode().Perm()
	}
	if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return err
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Chmod(mode)
	}
	if err == nil {
		err = out.Sync()
	}
	closed := out.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	before, err := SHA(source)
	if err != nil {
		return err
	}
	after, err := SHA(target)
	if err != nil || before != after {
		return errors.New("copy content changed")
	}
	return nil
}

func sourcePins(repository string) (map[string]string, error) {
	pins := map[string]string{}
	for _, name := range []string{"go.mod", "go.sum"} {
		path := filepath.Join(repository, name)
		value, err := SHA(path)
		if err != nil {
			return nil, err
		}
		pins[path] = value
	}
	for _, base := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(repository, base), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			name, err := filepath.Rel(repository, path)
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("source symlink rejected: %s", name)
			}
			if entry.IsDir() {
				return nil
			}
			if !managed(filepath.ToSlash(name)) {
				return fmt.Errorf("source not eligible for pinning: %s", name)
			}
			switch filepath.Ext(path) {
			case ".go", ".c", ".h", ".m", ".s", ".S", ".html", ".css", ".js", ".json":
				value, err := SHA(path)
				if err != nil {
					return err
				}
				pins[path] = value
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for _, base := range []string{"experiments/vm", "experiments/contracts/image_fixture", "experiments/productav/driver"} {
		err := filepath.WalkDir(filepath.Join(repository, base), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if strings.HasPrefix(entry.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Ext(path) != ".go" && entry.Name() != "go.mod" && entry.Name() != "go.sum" {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("Go source symlink rejected")
			}
			value, err := SHA(path)
			if err != nil {
				return err
			}
			pins[path] = value
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"experiments/host/integrated_watchdog.m", "experiments/vm/init", "experiments/av/scan-manifest.json", "experiments/av/observation-specification.json", "experiments/av/adopted-bindings.json", "experiments/av/remaining_candidate/boundary_observer.c", "experiments/av/xml_error_observer.c", "experiments/av/xml_dict_probe.c"} {
		path := filepath.Join(repository, name)
		value, err := SHA(path)
		if err != nil {
			return nil, err
		}
		pins[path] = value
	}
	for _, pattern := range []string{"experiments/av/evidence/*.json", "experiments/contracts/*.json", "experiments/contracts/go.mod", "experiments/contracts/go.sum", "experiments/vm/fixtures.json"} {
		paths, err := filepath.Glob(filepath.Join(repository, pattern))
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			value, err := SHA(path)
			if err != nil {
				return nil, err
			}
			pins[path] = value
		}
	}
	return pins, nil
}

func buildLock(repository, verification string) (func(), error) {
	locks := []*os.File{}
	closeAll := func() {
		for _, f := range locks {
			f.Close()
		}
	}
	workspace := filepath.Join(repository, "workspace.lock")
	if _, err := os.Stat(filepath.Join(repository, "workspace-state.json")); err != nil {
		return nil, errors.New("build requires an external managed workspace")
	}
	var actual, inherited unix.Stat_t
	if unix.Lstat(workspace, &actual) != nil || actual.Mode&unix.S_IFMT != unix.S_IFREG || actual.Uid != uint32(os.Getuid()) || actual.Mode&07777 != 0600 {
		return nil, errors.New("workspace lock identity invalid")
	}
	borrowed := unix.Fstat(3, &inherited) == nil && actual.Dev == inherited.Dev && actual.Ino == inherited.Ino && unix.Flock(3, unix.LOCK_EX|unix.LOCK_NB) == nil
	if !borrowed {
		fd, err := unix.Open(workspace, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		f := os.NewFile(uintptr(fd), workspace)
		locks = append(locks, f)
		if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
			closeAll()
			return nil, errors.New("workspace is in use")
		}
	}
	defaultVerification, err := DefaultVerification()
	if err != nil {
		closeAll()
		return nil, err
	}
	seen := map[string]bool{}
	for _, base := range []string{verification, defaultVerification} {
		if seen[base] {
			continue
		}
		seen[base] = true
		state := filepath.Join(base, "experiments/host/.build")
		if err := os.MkdirAll(state, 0700); err != nil {
			closeAll()
			return nil, err
		}
		path := filepath.Join(state, "vm-slot.lock")
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			closeAll()
			return nil, err
		}
		f := os.NewFile(uintptr(fd), path)
		locks = append(locks, f)
		if err = privateFile(path); err != nil {
			closeAll()
			return nil, err
		}
		if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
			closeAll()
			return nil, errors.New("VM slot prevents image construction")
		}
	}
	for _, base := range []string{repository, verification, defaultVerification} {
		if _, err := os.Lstat(filepath.Join(base, "experiments/host/.build/active-vm.json")); !errors.Is(err, os.ErrNotExist) {
			closeAll()
			return nil, errors.New("unresolved VM intent prevents construction")
		}
	}
	return closeAll, nil
}
