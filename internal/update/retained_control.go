package update

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// RetainedControlBytes returns the management bytes of a retained runtime directory that the caller opened without following
// a link, under the runtime usage rules. output/final.json and its .pending belong to the report pool, and candidate payload
// is not control.
func RetainedControlBytes(runtime int) (int64, error) {
	u := &usageTotal{seen: make(map[usageIdentity]string)}
	rules := usageRules(map[string]int64{"request.json": 16384, "launch-intent.json": 16384, "producer.lock": 0}, false)
	if err := u.retained(runtime, "runtime", rules, nil, map[string]bool{"output": true}); err != nil {
		return 0, err
	}
	output, err := retainedChild(runtime, "output")
	if errors.Is(err, os.ErrNotExist) {
		return u.management, nil
	}
	if err != nil {
		return 0, err
	}
	defer unix.Close(output)
	skip := map[string]bool{"final.json": true, "final.json.pending": true}
	if err = u.retained(output, "runtime/output", runtimeOutputRules(), skip, map[string]bool{"candidates": true, "watchdog": true}); err != nil {
		return 0, err
	}
	watchdog, err := retainedChild(output, "watchdog")
	if errors.Is(err, os.ErrNotExist) {
		return u.management, nil
	}
	if err != nil {
		return 0, err
	}
	defer unix.Close(watchdog)
	// Legacy runtimes retain the supervisor source as evidence; only this accounting path accepts it.
	rules = runtimeWatchdogRules()
	rules["supervisor.py"] = usageRule{limit: 65536}
	if err = u.retained(watchdog, "runtime/output/watchdog", rules, nil, nil); err != nil {
		return 0, err
	}
	return u.management, nil
}

// retained accounts one directory read through fd as directory does: child directories must be private and are not read
// here, skipped names are another pool's, and every other entry needs a rule.
func (u *usageTotal) retained(fd int, label string, rules map[string]usageRule, skip, children map[string]bool) error {
	dup, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(dup), label)
	defer directory.Close()
	entries, err := directory.ReadDir(257)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 256 {
		return Invalid
	}
	for _, entry := range entries {
		name := entry.Name()
		var child unix.Stat_t
		if err = unix.Fstatat(fd, name, &child, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
			continue
		} else if err != nil {
			return err
		}
		if children[name] {
			if child.Mode&unix.S_IFMT != unix.S_IFDIR || child.Mode&0777 != 0700 || child.Uid != uint32(os.Getuid()) {
				return Invalid
			}
			continue
		}
		if skip[name] {
			continue
		}
		rule, known := rules[name]
		if !known {
			return Invalid
		}
		if err = u.file(fd, label, name, child, rule, true); err != nil {
			return err
		}
	}
	return nil
}

// retainedChild opens a private child directory without following a link; a missing child is os.ErrNotExist.
func retainedChild(parent int, name string) (int, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, os.ErrNotExist
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return -1, Invalid
	}
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0777 != 0700 || st.Uid != uint32(os.Getuid()) {
		unix.Close(fd)
		return -1, Invalid
	}
	return fd, nil
}
