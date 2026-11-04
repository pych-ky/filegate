package buildtools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type WorkspaceOptions struct {
	Repository   string
	Root         string
	Verification string
}

type sourceEntry struct {
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

type workspaceState struct {
	Schema     int                    `json:"schema"`
	Repository string                 `json:"repository"`
	Sources    map[string]sourceEntry `json:"sources"`
}

type WorkspaceResult struct {
	Workspace string `json:"workspace"`
	Sources   int    `json:"sources"`
	Copied    int    `json:"copied"`
	Removed   int    `json:"removed"`
}

func DefaultVerification() (string, error) {
	home, err := os.UserHomeDir()
	return filepath.Join(home, "Library/Application Support/FileGate/verification"), err
}

func Repository(path string) (string, error) {
	if path != "" {
		return canonical(path)
	}
	command := exec.Command("git", "rev-parse", "--show-toplevel")
	body, err := command.Output()
	if err != nil {
		return "", err
	}
	return canonical(strings.TrimSpace(string(body)))
}

func workspaceOptions(options WorkspaceOptions) (WorkspaceOptions, error) {
	var err error
	if options.Repository, err = Repository(options.Repository); err != nil {
		return options, err
	}
	if options.Verification == "" {
		options.Verification, err = DefaultVerification()
		if err != nil {
			return options, err
		}
	}
	if options.Root == "" {
		options.Root = options.Verification
	}
	if options.Root, err = canonical(options.Root); err != nil {
		return options, err
	}
	if options.Verification, err = canonical(options.Verification); err != nil {
		return options, err
	}
	if within(options.Root, options.Repository) || within(options.Repository, options.Root) {
		return options, errors.New("workspace must be outside the repository and its ancestors")
	}
	return options, nil
}

func within(path, base string) bool {
	name, err := filepath.Rel(base, path)
	return err == nil && name != ".." && !strings.HasPrefix(name, ".."+string(filepath.Separator))
}

func managed(name string) bool {
	if filepath.IsAbs(name) || filepath.ToSlash(filepath.Clean(name)) != name {
		return false
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".py", ".pyi", ".pyc", ".pyo", ".pyw", ".pyz", ".whl":
		return false
	}
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if part == ".." || strings.HasPrefix(part, ".env") || part == "secrets" || part == "credentials" || part == "client.json" {
			return false
		}
	}
	switch name {
	case "README.md", "BASIC_DESIGN.md", "AGENTS.md", "HANDOFF.md", "IMPLEMENTATION_STATUS.md", "DEVELOPMENT.md", "go.mod", "go.sum":
		return true
	}
	return len(parts) > 1 && (parts[0] == "experiments" || parts[0] == "cmd" || parts[0] == "internal" || parts[0] == "scripts")
}

func WorkspacePath(options WorkspaceOptions) (string, error) {
	checked, err := workspaceOptions(options)
	return checked.Root, err
}

func Workspace(ctx context.Context, options WorkspaceOptions, argv []string, cwd string, stdout, stderr io.Writer) (WorkspaceResult, int, error) {
	options, err := workspaceOptions(options)
	if err != nil {
		return WorkspaceResult{}, 1, err
	}
	if err = os.MkdirAll(options.Root, 0700); err != nil {
		return WorkspaceResult{}, 1, err
	}
	lockPath, err := checked(options.Root, "workspace.lock")
	if err != nil {
		return WorkspaceResult{}, 1, err
	}
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return WorkspaceResult{}, 1, err
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	defer lock.Close()
	if err = privateFile(lockPath); err != nil {
		return WorkspaceResult{}, 1, err
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return WorkspaceResult{}, 1, errors.New("workspace is already in use")
	}
	var slots []*os.File
	defer func() {
		for _, file := range slots {
			file.Close()
		}
	}()
	seen := map[string]bool{}
	defaultVerification, defaultErr := DefaultVerification()
	if defaultErr != nil {
		return WorkspaceResult{}, 1, defaultErr
	}
	for _, base := range []string{options.Repository, options.Root, options.Verification, defaultVerification} {
		if seen[base] {
			continue
		}
		seen[base] = true
		name, checkErr := checked(base, "experiments/host/.build/vm-slot.lock")
		if checkErr != nil {
			return WorkspaceResult{}, 1, checkErr
		}
		slot, openErr := os.Open(name)
		if openErr == nil {
			slots = append(slots, slot)
			if unix.Flock(int(slot.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
				return WorkspaceResult{}, 1, fmt.Errorf("VM slot prevents synchronization: %s", name)
			}
		} else if !errors.Is(openErr, os.ErrNotExist) {
			return WorkspaceResult{}, 1, openErr
		}
		intent, checkErr := checked(base, "experiments/host/.build/active-vm.json")
		if checkErr != nil {
			return WorkspaceResult{}, 1, checkErr
		}
		if _, statErr := os.Lstat(intent); !errors.Is(statErr, os.ErrNotExist) {
			return WorkspaceResult{}, 1, errors.New("active VM intent prevents synchronization")
		}
	}
	result, err := syncSources(ctx, options)
	for _, slot := range slots {
		slot.Close()
	}
	slots = nil
	if err != nil || len(argv) == 0 {
		return result, 0, err
	}
	if cwd == "" {
		cwd = "."
	}
	directory, err := checked(options.Root, cwd)
	if err != nil {
		return result, 1, err
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return result, 1, errors.New("workspace working directory does not exist")
	}
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Dir, command.Stdin, command.Stdout, command.Stderr = directory, os.Stdin, stdout, stderr
	command.ExtraFiles = []*os.File{lock}
	err = command.Run()
	if err == nil {
		return result, 0, nil
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		if status, ok := exited.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return result, 128 + int(status.Signal()), nil
		}
		return result, exited.ExitCode(), nil
	}
	return result, 1, err
}

func syncSources(ctx context.Context, options WorkspaceOptions) (WorkspaceResult, error) {
	statePath, err := checked(options.Root, "workspace-state.json")
	if err != nil {
		return WorkspaceResult{}, err
	}
	previous := workspaceState{Schema: 1, Repository: options.Repository, Sources: map[string]sourceEntry{}}
	if _, err = os.Lstat(statePath); err == nil {
		if err = privateFile(statePath); err != nil {
			return WorkspaceResult{}, err
		}
		if err = readJSON(statePath, &previous); err != nil {
			return WorkspaceResult{}, err
		}
		if previous.Schema != 1 || previous.Repository != options.Repository || previous.Sources == nil {
			return WorkspaceResult{}, errors.New("workspace state does not match repository")
		}
		for name, entry := range previous.Sources {
			if !managed(name) || !validSHA(entry.SHA256) || entry.Mode > 07777 {
				return WorkspaceResult{}, errors.New("invalid managed source in workspace state")
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return WorkspaceResult{}, err
	}
	command := exec.CommandContext(ctx, "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	command.Dir = options.Repository
	listed, err := command.Output()
	if err != nil {
		return WorkspaceResult{}, err
	}
	sources := map[string][]byte{}
	entries := map[string]sourceEntry{}
	for _, encoded := range bytes.Split(listed, []byte{0}) {
		name := string(encoded)
		if name == "" || !managed(name) {
			continue
		}
		path, err := checked(options.Repository, name)
		if err != nil {
			return WorkspaceResult{}, err
		}
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return WorkspaceResult{}, fmt.Errorf("managed source is not a regular file: %s", name)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return WorkspaceResult{}, err
		}
		sources[name] = body
		entries[name] = sourceEntry{digest(body), permissionBits(info.Mode())}
	}
	names := map[string]bool{}
	for name := range previous.Sources {
		names[name] = true
	}
	for name := range entries {
		names[name] = true
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	var changes, removals []string
	for _, name := range ordered {
		path, err := checked(options.Root, name)
		if err != nil {
			return WorkspaceResult{}, err
		}
		var actual sourceEntry
		info, err := os.Stat(path)
		exists := err == nil
		if exists {
			if !info.Mode().IsRegular() {
				return WorkspaceResult{}, fmt.Errorf("workspace destination is not regular: %s", name)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return WorkspaceResult{}, err
			}
			actual = sourceEntry{digest(body), permissionBits(info.Mode())}
		} else if !errors.Is(err, os.ErrNotExist) {
			return WorkspaceResult{}, err
		}
		old, hadOld := previous.Sources[name]
		desired, wanted := entries[name]
		matchesOld := exists && actual == old
		matchesDesired := wanted && exists && actual == desired || !wanted && !exists
		if hadOld && !matchesOld && !matchesDesired {
			return WorkspaceResult{}, fmt.Errorf("workspace source edited or removed: %s", name)
		}
		if !wanted {
			if exists {
				removals = append(removals, name)
			}
			continue
		}
		if !hadOld && exists && actual != desired {
			return WorkspaceResult{}, fmt.Errorf("existing workspace source differs: %s", name)
		}
		if !exists || actual != desired {
			changes = append(changes, name)
		}
	}
	for _, name := range changes {
		path, _ := checked(options.Root, name)
		if err = atomicFile(path, sources[name], fileMode(entries[name].Mode)); err != nil {
			return WorkspaceResult{}, err
		}
	}
	for _, name := range removals {
		path, _ := checked(options.Root, name)
		if err = os.Remove(path); err != nil {
			return WorkspaceResult{}, err
		}
	}
	body, err := json.MarshalIndent(workspaceState{1, options.Repository, entries}, "", "  ")
	if err == nil {
		err = atomicFile(statePath, append(body, '\n'), 0600)
	}
	return WorkspaceResult{options.Root, len(entries), len(changes), len(removals)}, err
}
