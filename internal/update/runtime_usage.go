package update

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

type usageRule struct {
	limit    int64
	readonly bool
	socket   bool
}

type usageIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type usageTotal struct {
	written    int64
	management int64
	seen       map[usageIdentity]string
}

func usageRules(limits map[string]int64, pending bool) map[string]usageRule {
	rules := make(map[string]usageRule, 2*len(limits))
	for name, limit := range limits {
		rules[name] = usageRule{limit: limit}
		if pending && strings.HasSuffix(name, ".json") {
			rules[name+".pending"] = usageRule{limit: limit}
		}
	}
	return rules
}

func (u *usageTotal) file(fd int, directory, name string, info unix.Stat_t, rule usageRule, management bool) error {
	if info.Uid != uint32(os.Getuid()) || info.Size < 0 || info.Size > rule.limit || info.Blocks < 0 || info.Blocks > math.MaxInt64/512 {
		return Invalid
	}
	mode := info.Mode & 0777
	if rule.socket {
		if info.Mode&unix.S_IFMT != unix.S_IFSOCK || (mode != 0600 && mode != 0700) {
			return Invalid
		}
		return nil
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG || (mode != 0600 && !(rule.readonly && mode == 0400)) {
		return Invalid
	}
	key := usageIdentity{uint64(info.Dev), info.Ino}
	path := filepath.Join(directory, name)
	credit := true
	if info.Nlink != 1 {
		base := strings.TrimSuffix(name, ".pending")
		if info.Nlink != 2 || !management || (base != "preparation-owner.json" && base != "native-bootstrap-owner.json" && base != "native-bootstrap-dispatched.json") {
			return Invalid
		}
		other := base + ".pending"
		if name != base {
			other = base
		}
		var pair unix.Stat_t
		if err := unix.Fstatat(fd, other, &pair, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			if pair.Dev != info.Dev || pair.Ino != info.Ino || pair.Mode != info.Mode || pair.Uid != info.Uid || pair.Gid != info.Gid ||
				pair.Size != info.Size || pair.Mtim != info.Mtim || (pair.Nlink != 1 && pair.Nlink != 2) {
				return Invalid
			}
		} else if errors.Is(err, os.ErrNotExist) {
			// Keep the reservation during the link/unlink observation window.
			credit = false
		} else {
			return err
		}
	}
	if previous, exists := u.seen[key]; exists {
		if !management || (previous != path+".pending" && path != previous+".pending") {
			return Invalid
		}
		return nil
	}
	u.seen[key] = path
	if management {
		u.management += max(info.Size, info.Blocks*512)
	} else {
		u.management += max(int64(0), info.Blocks*512-info.Size)
	}
	if u.management > 64<<20 {
		return Invalid
	}
	if credit {
		u.written += info.Blocks * 512
	}
	return nil
}

func (u *usageTotal) directory(path string, expected *usageIdentity, rules map[string]usageRule, children map[string]bool,
	visit func(int, string, unix.Stat_t) (bool, error)) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), path)
	defer directory.Close()
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Mode&0777 != 0700 || info.Uid != uint32(os.Getuid()) ||
		expected != nil && *expected != (usageIdentity{uint64(info.Dev), info.Ino}) {
		return Invalid
	}
	entries, err := directory.ReadDir(257)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 256 {
		return Invalid
	}
	for _, entry := range entries {
		name := entry.Name()
		var child unix.Stat_t
		if err = unix.Fstatat(fd, name, &child, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, os.ErrNotExist) {
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
		if visit != nil {
			handled, err := visit(fd, name, child)
			if err != nil {
				return err
			}
			if handled {
				continue
			}
		}
		rule, known := rules[name]
		if !known {
			return Invalid
		}
		if err = u.file(fd, path, name, child, rule, true); err != nil {
			return err
		}
	}
	return nil
}

func usageRecord(path string, maximum int64, target any) (bool, error) {
	body, err := runtimeRead(path, maximum)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if maximum < 0 || maximum > 1<<20 {
		return false, Invalid
	}
	if _, err = decode(body, int(maximum)); err != nil || json.Unmarshal(body, target) != nil {
		return false, Invalid
	}
	return true, nil
}

func runtimeWritten(directory string, requested runtimeRequest) (int64, error) {
	written, err := measureRuntimeWritten(directory, requested)
	if err != nil {
		return 0, Error("RESOURCE_MONITOR_FAILED")
	}
	return written, nil
}

func runtimeOutputRules() map[string]usageRule {
	limits := map[string]int64{"runner.lock": 0, "network.lock": 0, "final.json": 1 << 20, "final-accepted.json": 1024,
		"candidate-directory-intent.json": 4096, "candidate-directory.json": 4096, "candidates.json": 16384,
		"image-plan.json": 4096, "image-owner.json": 4096, "definition-image.json": 65536,
		"network-intent.json": 4096, "network-closed.json": 4096}
	for _, name := range []string{"resource-intent", "slot-owner", "preparation-intent", "preparation", "prepared-identity", "vm-started",
		"native-intent", "native-directory", "native-bootstrap-result", "native-start", "native-recovery", "native-previous-boot",
		"stop-proof", "cleanup-intent", "cleanup-complete", "raw-cleanup", "recovery-results", "startup-complete", "update-complete", "update-pending", "prepared"} {
		limits[name+".json"] = 65536
	}
	for _, name := range []string{"preparation-owner", "native-bootstrap-owner", "native-bootstrap-dispatched"} {
		limits[name+".json"] = 16384
	}
	for _, name := range []string{"main", "daily", "bytecode"} {
		limits["candidate-plan-"+name+".json"], limits["candidate-owner-"+name+".json"] = 4096, 4096
	}
	rules := usageRules(limits, true)
	rules["prepared.json"] = usageRule{limit: 1 << 20}
	rules["prepared.json.pending"] = usageRule{limit: 1 << 20}
	for _, name := range []string{"image-profile.json", "image-install.txt"} {
		rules[name] = usageRule{limit: 65536, readonly: true}
	}
	return rules
}

func runtimeWatchdogRules() map[string]usageRule {
	return usageRules(map[string]int64{"config.json": 65536, "watchdog.plist": 65536, "guardian-result.json": 65536,
		"events.jsonl": 4 << 20, "producer-source.json": 1 << 20, "producer-source.json.pending": 1 << 20, "integrated_watchdog.m": 1 << 20,
		"results.json": 16 << 20, "results.json.pending": 16 << 20, "launch-result.json": 16 << 20, "launch-result.json.pending": 16 << 20}, false)
}

func measureRuntimeWritten(directory string, requested runtimeRequest) (int64, error) {
	if requested.Profile != normalRuntimeProfile || requested.FixtureOnly || requested.Attempt.ReservedBytes != WorkspaceReservation ||
		filepath.Base(directory) != requested.AttemptID || requested.Attempt.ID != requested.AttemptID || !filepath.IsAbs(directory) {
		return 0, Invalid
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || canonical != directory {
		return 0, Invalid
	}
	u := &usageTotal{seen: make(map[usageIdentity]string)}
	if err = u.directory(directory, nil, usageRules(map[string]int64{"request.json": 16384, "launch-intent.json": 16384, "producer.lock": 0}, false),
		map[string]bool{"output": true}, nil); err != nil {
		return 0, err
	}
	out := filepath.Join(directory, "output")
	rules := runtimeOutputRules()
	if err = u.directory(out, nil, rules, map[string]bool{"candidates": true, "watchdog": true}, nil); err != nil {
		return 0, err
	}
	watchdog := runtimeWatchdogRules()
	if err = u.directory(filepath.Join(out, "watchdog"), nil, watchdog, nil, nil); err != nil {
		return 0, err
	}
	if err = u.candidates(out, requested.AttemptID); err != nil {
		return 0, err
	}
	if err = u.external(out, requested); err != nil {
		return 0, err
	}
	if u.written < 0 || u.written > WorkspaceReservation {
		return 0, Invalid
	}
	return u.written, nil
}

func (u *usageTotal) candidates(out, id string) error {
	var owner candidateDirectory
	known, err := usageRecord(filepath.Join(out, "candidate-directory.json"), 4096, &owner)
	if err != nil {
		return err
	}
	path := filepath.Join(out, "candidates")
	if !known {
		if emptyErr := u.directory(path, nil, nil, nil, nil); emptyErr == nil {
			return nil
		} else {
			known, err = usageRecord(filepath.Join(out, "candidate-directory.json"), 4096, &owner)
			if err != nil {
				return err
			}
			if !known {
				return emptyErr
			}
		}
	}
	if owner.Schema != 1 || owner.UpdateID != id || owner.Inode == 0 {
		return Invalid
	}
	seen, total := map[string]usageIdentity{}, int64(0)
	return u.directory(path, &usageIdentity{owner.Device, owner.Inode}, nil, nil, func(fd int, name string, info unix.Stat_t) (bool, error) {
		base := strings.TrimSuffix(name, ".pending")
		key := usageIdentity{uint64(info.Dev), info.Ino}
		if previous, exists := seen[base]; exists {
			if previous != key || info.Nlink != 1 {
				return true, Invalid
			}
			return true, nil
		}
		seen[base] = key
		if base == "definitions.ext4" {
			var image struct {
				Schema        int    `json:"schema"`
				UpdateID      string `json:"update_id"`
				Name          string `json:"name"`
				Bytes         int64  `json:"bytes"`
				ProfileSHA256 string `json:"profile_sha256"`
				Device        uint64 `json:"device"`
				Inode         uint64 `json:"inode"`
			}
			known, err := usageRecord(filepath.Join(out, "image-owner.json"), 4096, &image)
			if err != nil {
				return true, err
			}
			if !known && info.Size == 0 && name == "definitions.ext4.pending" {
				known, err = usageRecord(filepath.Join(out, "image-plan.json"), 4096, &image)
				if err != nil || image.Device != owner.Device || image.Inode != owner.Inode {
					return true, Invalid
				}
			} else if image.Device != uint64(info.Dev) || image.Inode != info.Ino {
				return true, Invalid
			}
			if !known || image.Schema != 1 || image.UpdateID != id || image.Name != base || image.Bytes != DefinitionImageBytes || !digestPattern.MatchString(image.ProfileSHA256) {
				return true, Invalid
			}
			return true, u.file(fd, path, name, info, usageRule{limit: DefinitionImageBytes, readonly: true}, false)
		}
		if !candidateName(base) {
			return true, Invalid
		}
		label, _, _ := strings.Cut(base, ".")
		var candidate candidateOwner
		known, err := usageRecord(filepath.Join(out, "candidate-owner-"+label+".json"), 4096, &candidate)
		if err != nil {
			return true, err
		}
		if !known && info.Size == 0 && name == base+".pending" {
			known, err = usageRecord(filepath.Join(out, "candidate-plan-"+label+".json"), 4096, &candidate)
			if err != nil || candidate.Device != owner.Device || candidate.Inode != owner.Inode {
				return true, Invalid
			}
		} else if candidate.Device != uint64(info.Dev) || candidate.Inode != info.Ino {
			return true, Invalid
		}
		if !known || candidate.Schema != 1 || candidate.UpdateID != id || candidate.Name != base || !digestPattern.MatchString(candidate.SHA256) ||
			candidate.Bytes <= 0 || candidate.Bytes > DefinitionCandidateLimit {
			return true, Invalid
		}
		total += candidate.Bytes
		if total > DefinitionCandidateLimit {
			return true, Invalid
		}
		return true, u.file(fd, path, name, info, usageRule{limit: candidate.Bytes, readonly: true}, false)
	})
}

func (u *usageTotal) external(out string, requested runtimeRequest) error {
	var preparation struct {
		Schema      int           `json:"schema"`
		JobID       string        `json:"job_id"`
		AttemptID   string        `json:"attempt_id"`
		Directory   string        `json:"run_directory"`
		Identity    usageIdentity `json:"run_directory_identity"`
		Reservation int64         `json:"reservation_charge_bytes"`
	}
	known, err := usageRecord(filepath.Join(out, "preparation-intent.json"), 65536, &preparation)
	if err != nil {
		return err
	}
	if known {
		if preparation.Schema != 1 || preparation.JobID != requested.JobID || preparation.AttemptID != requested.AttemptID ||
			preparation.Reservation != 4<<30 || preparation.Identity.Inode == 0 || !usageTemporary(preparation.Directory, "filegate-vm-") {
			return Invalid
		}
		var prepared struct {
			Directory string        `json:"run_directory"`
			Identity  usageIdentity `json:"raw_identity"`
		}
		bound, err := usageRecord(filepath.Join(out, "prepared-identity.json"), 65536, &prepared)
		if err != nil || bound && prepared.Directory != preparation.Directory {
			return Invalid
		}
		rules := usageRules(map[string]int64{"prepared.json": 1 << 20, "normal-exchange.json": 1 << 20, "normal-exchange.json.pending": 1 << 20}, false)
		rules["channel.sock"] = usageRule{socket: true}
		if err = u.directory(preparation.Directory, &preparation.Identity, rules, nil, func(fd int, name string, info unix.Stat_t) (bool, error) {
			if name != "work.raw" {
				return false, nil
			}
			if bound && prepared.Identity != (usageIdentity{uint64(info.Dev), info.Ino}) {
				return true, Invalid
			}
			return true, u.file(fd, preparation.Directory, name, info, usageRule{limit: 4 << 30}, false)
		}); err != nil {
			return err
		}
	}
	var native struct {
		Schema      int    `json:"schema"`
		JobID       string `json:"job_id"`
		AttemptID   string `json:"attempt_id"`
		InputSHA256 string `json:"input_sha256"`
		Directory   string `json:"control_directory"`
		Config      struct {
			OwnerKind string `json:"owner_kind"`
			Start     uint64 `json:"continuous_start_ns"`
			Deadline  uint64 `json:"continuous_deadline_ns"`
		} `json:"config"`
	}
	known, err = usageRecord(filepath.Join(out, "native-intent.json"), 65536, &native)
	if err != nil || !known {
		return err
	}
	if native.Schema != 2 || native.JobID != requested.JobID || native.AttemptID != requested.AttemptID || native.InputSHA256 != requested.ExpectedSHA ||
		native.Config.OwnerKind != "update" || native.Config.Start != requested.Attempt.Started.ContinuousNS || native.Config.Deadline != requested.Attempt.DeadlineContinuousNS ||
		!usageTemporary(native.Directory, "fgw-") {
		return Invalid
	}
	var owner struct {
		Schema      int    `json:"schema"`
		JobID       string `json:"job_id"`
		AttemptID   string `json:"attempt_id"`
		InputSHA256 string `json:"input_sha256"`
		Device      uint64 `json:"device"`
		Inode       uint64 `json:"inode"`
	}
	known, err = usageRecord(filepath.Join(out, "native-directory.json"), 65536, &owner)
	if err != nil || !known {
		return err
	}
	if owner.Schema != 1 || owner.JobID != requested.JobID || owner.AttemptID != requested.AttemptID || owner.InputSHA256 != requested.ExpectedSHA || owner.Inode == 0 {
		return Invalid
	}
	rules := usageRules(map[string]int64{"config.json": 65536, "watchdog.plist": 65536, "guardian-result.json": 65536, "events.jsonl": 4 << 20}, false)
	rules["watch.sock"] = usageRule{socket: true}
	return u.directory(native.Directory, &usageIdentity{owner.Device, owner.Inode}, rules, nil, nil)
}

func usageTemporary(path, prefix string) bool {
	return filepath.Dir(path) == "/private/tmp" && regexp.MustCompile("^"+regexp.QuoteMeta(prefix)+"[0-9a-f]{32}$").MatchString(filepath.Base(path))
}
