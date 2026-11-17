package update

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type RetentionResult struct {
	DefinitionsRemoved int
	RuntimesRemoved    int
	HistoriesRemoved   int
	Pending            int
}

type retentionIdentity struct {
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	Mode       uint32 `json:"mode"`
	Size       int64  `json:"size"`
	ModifiedNS int64  `json:"modified_ns"`
	ChangedNS  int64  `json:"changed_ns"`
}

type retentionEntry struct {
	Name     string            `json:"name"`
	Identity retentionIdentity `json:"identity"`
}

type retentionPlan struct {
	Schema   int               `json:"schema"`
	UpdateID string            `json:"update_id"`
	Kind     string            `json:"kind"`
	Path     string            `json:"path"`
	Parent   retentionIdentity `json:"parent"`
	Root     retentionIdentity `json:"root"`
	Entries  []retentionEntry  `json:"entries"`
}

type retainedUpdate struct {
	attempt           Attempt
	directory         string
	runtimeSHA        string
	state             string
	adoption          *adoptionRecord
	resolved          int64
	definitionRemoved bool
	runtimeRemoved    bool
	pending           []byte
}

func retentionStat(s unix.Stat_t) retentionIdentity {
	return retentionIdentity{uint64(s.Dev), s.Ino, uint32(s.Mode), s.Size, s.Mtim.Nano(), s.Ctim.Nano()}
}

func retentionDirectory(s unix.Stat_t) bool {
	return s.Mode&unix.S_IFMT == unix.S_IFDIR && s.Mode&0777 == 0700 && s.Uid == uint32(os.Getuid())
}

func retentionSameDirectory(s unix.Stat_t, expected retentionIdentity) bool {
	return retentionDirectory(s) && uint64(s.Dev) == expected.Device && s.Ino == expected.Inode
}

// Prune retains live references and the current control record independently of history.
// admit runs in each NEW optional writing transaction before its first write; nil (startup resumeOnly) admits all. Already
// durable plans finish first without it, and its error is returned unchanged.
func (s *Store) Prune(dataDir string, cutoff int64, protected map[string]bool, resumeOnly bool, admit func(*sql.Tx) error) (RetentionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result RetentionResult
	canonical, err := filepath.EvalSymlinks(dataDir)
	if err != nil || canonical != dataDir || !filepath.IsAbs(dataDir) || cutoff <= 0 || cutoff > MaxUTC {
		return result, Invalid
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return result, err
	}
	control, err := loadControl(tx)
	if errors.Is(err, sql.ErrNoRows) {
		tx.Rollback()
		return result, nil
	}
	if err != nil || control.Binding.FixtureOnly {
		tx.Rollback()
		return result, Invalid
	}
	rows, err := tx.Query("SELECT a.id,a.reserved_bytes,a.data,coalesce(r.directory,''),coalesce(r.manifest_sha256,''),coalesce(r.state,''),d.data FROM update_attempts a LEFT JOIN update_runtime r ON r.update_id=a.id LEFT JOIN update_adoptions d ON d.update_id=a.id ORDER BY a.id")
	if err != nil {
		tx.Rollback()
		return result, err
	}
	var all []retainedUpdate
	for rows.Next() {
		var r retainedUpdate
		var body, adoption []byte
		var rowID string
		var reserved int64
		if err = rows.Scan(&rowID, &reserved, &body, &r.directory, &r.runtimeSHA, &r.state, &adoption); err != nil {
			break
		}
		if decodeStored(body, &r.attempt) != nil || r.attempt.ID != rowID || !identifier.MatchString(rowID) || !strings.HasPrefix(rowID, "update_") || r.attempt.ReservedBytes != reserved {
			err = Invalid
			break
		}
		if adoption != nil {
			var a adoptionRecord
			if decodeStored(adoption, &a) != nil || a.Schema != 1 || a.Manifest.UpdateID != r.attempt.ID || a.Directory.UpdateID != r.attempt.ID || a.ManifestSHA != sha256Text(encoded(a.Manifest)) {
				err = Invalid
				break
			}
			r.adoption = &a
		}
		all = append(all, r)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		tx.Rollback()
		return result, err
	}
	pins := make(map[string]bool, len(protected)+1)
	for id, keep := range protected {
		pins[id] = keep
	}
	pins[control.ActiveUpdateID] = true
	if err = pinDefinitionCaches(tx, all, pins); err != nil {
		tx.Rollback()
		return result, err
	}
	rows, err = tx.Query("SELECT DISTINCT update_id FROM update_waiters")
	if err != nil {
		tx.Rollback()
		return result, err
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		pins[id] = true
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		tx.Rollback()
		return result, err
	}
	var unanchored []*retainedUpdate
	anchors := map[string]int64{}
	for i := range all {
		r := &all[i]
		a := r.attempt
		if a.State != "FINISHED" || !a.StopConfirmed || !a.CleanupConfirmed || a.ReservedBytes != 0 ||
			(r.directory != "" && (r.state != "FINISHED" || r.directory != filepath.Join(dataDir, "updates", a.ID))) ||
			(a.AdoptionApproved && (r.adoption == nil || r.directory == "")) {
			pins[a.ID] = true
			continue
		}
		err = tx.QueryRow("SELECT resolved_at,definition_removed,runtime_removed,pending FROM update_retention WHERE update_id=?", a.ID).
			Scan(&r.resolved, &r.definitionRemoved, &r.runtimeRemoved, &r.pending)
		if errors.Is(err, sql.ErrNoRows) {
			err = nil
			if !resumeOnly {
				anchor := a.FinishedUTC
				if anchor <= 0 || anchor > MaxUTC {
					anchor = cutoff
				}
				unanchored, anchors[a.ID] = append(unanchored, r), anchor
			}
			continue
		}
		if err != nil {
			tx.Rollback()
			return result, err
		}
	}
	if err = tx.Commit(); err != nil {
		return result, err
	}
	current := ""
	if control.Definition != nil {
		current = control.Definition.UpdateID
	}
	// Already durable plans are owed: they finish before any new unit can be refused, and are never admitted.
	held := map[string]bool{}
	for i := range all {
		r := &all[i]
		id := r.attempt.ID
		if pins[id] || r.resolved == 0 || r.pending == nil {
			continue
		}
		held[id] = true
		var plan retentionPlan
		if retentionDecode(r.pending, &plan) != nil || plan.UpdateID != id || (plan.Kind == "definition" && id == current) {
			result.Pending++
			continue
		}
		if err = s.finishRetention(dataDir, plan); err != nil {
			if _, e := s.db.Exec("UPDATE update_retention SET reason='CLEANUP_PENDING' WHERE update_id=?", id); e != nil {
				return result, e
			}
			result.Pending++
			continue
		}
		held[id] = false
		if plan.Kind == "definition" {
			r.definitionRemoved = true
			result.DefinitionsRemoved++
		} else {
			r.runtimeRemoved = true
			result.RuntimesRemoved++
		}
	}
	if resumeOnly {
		return result, nil
	}
	// New anchors are optional writes, at most 500 per admitted transaction.
	for start := 0; start < len(unanchored); start += 500 {
		if err = s.retentionTx(admit, func(tx *sql.Tx) error {
			for _, r := range unanchored[start:min(start+500, len(unanchored))] {
				if _, err := tx.Exec("INSERT OR IGNORE INTO update_retention(update_id,resolved_at) VALUES(?,?)", r.attempt.ID, anchors[r.attempt.ID]); err != nil {
					return err
				}
				if err := tx.QueryRow("SELECT resolved_at,definition_removed,runtime_removed,pending FROM update_retention WHERE update_id=?", r.attempt.ID).
					Scan(&r.resolved, &r.definitionRemoved, &r.runtimeRemoved, &r.pending); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return result, unwrapRefusal(err)
		}
	}
	for i := range all {
		r := &all[i]
		id := r.attempt.ID
		if pins[id] || r.resolved == 0 || held[id] {
			continue
		}
		if id != current && r.adoption != nil && !r.definitionRemoved {
			persisted := false
			plan, e := definitionRetentionPlan(dataDir, *r)
			if e == nil {
				e = s.beginRetention(plan, admit)
				persisted = e == nil
			}
			if refusal(e) {
				return result, unwrapRefusal(e)
			}
			if e == nil {
				e = s.finishRetention(dataDir, plan)
			}
			if e != nil {
				if err = s.cleanupReason(id, persisted, admit); err != nil {
					return result, unwrapRefusal(err)
				}
				result.Pending++
				continue
			}
			r.definitionRemoved = true
			result.DefinitionsRemoved++
		}
		if r.resolved >= cutoff-30*86400 {
			continue
		}
		if !r.runtimeRemoved {
			persisted := false
			if r.directory == "" {
				err = s.retentionTx(admit, func(tx *sql.Tx) error {
					_, err := tx.Exec("UPDATE update_retention SET runtime_removed=1 WHERE update_id=?", id)
					return err
				})
			} else {
				var plan retentionPlan
				plan, err = s.runtimeRetentionPlan(dataDir, *r)
				if err == nil {
					err = s.beginRetention(plan, admit)
					persisted = err == nil
				}
				if err == nil {
					err = s.finishRetention(dataDir, plan)
				}
			}
			if refusal(err) {
				return result, unwrapRefusal(err)
			}
			if err != nil {
				if e := s.cleanupReason(id, persisted, admit); e != nil {
					return result, unwrapRefusal(e)
				}
				result.Pending++
				continue
			}
			r.runtimeRemoved = true
			result.RuntimesRemoved++
		}
		if id == current || id == control.LastUpdateID || r.adoption != nil && !r.definitionRemoved {
			continue
		}
		if err = s.retentionTx(admit, func(tx *sql.Tx) error {
			for _, query := range []string{"DELETE FROM update_adoptions WHERE update_id=?", "DELETE FROM update_runtime WHERE update_id=?", "DELETE FROM update_attempts WHERE id=?"} {
				if _, err := tx.Exec(query, id); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return result, unwrapRefusal(err)
		}
		result.HistoriesRemoved++
	}
	return result, nil
}

// retentionRefusal carries an admit error through a retention helper so Prune can return it unchanged.
type retentionRefusal struct{ err error }

func (r retentionRefusal) Error() string { return r.err.Error() }

func refusal(err error) bool {
	var r retentionRefusal
	return errors.As(err, &r)
}

func unwrapRefusal(err error) error {
	var r retentionRefusal
	if errors.As(err, &r) {
		return r.err
	}
	return err
}

// cleanupReason records CLEANUP_PENDING: owed and unadmitted once the plan is durable, otherwise a new optional write.
func (s *Store) cleanupReason(id string, persisted bool, admit func(*sql.Tx) error) error {
	const query = "UPDATE update_retention SET reason='CLEANUP_PENDING' WHERE update_id=?"
	if persisted {
		_, err := s.db.Exec(query, id)
		return err
	}
	return s.retentionTx(admit, func(tx *sql.Tx) error {
		_, err := tx.Exec(query, id)
		return err
	})
}

// retentionTx runs one new optional retention write after admit accepts it in the same immediate transaction.
func (s *Store) retentionTx(admit func(*sql.Tx) error, write func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if admit != nil {
		if err = admit(tx); err != nil {
			return retentionRefusal{err}
		}
	}
	if err = write(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func retentionDecode(body []byte, target any) error {
	if len(body) > 65536 {
		return Invalid
	}
	if _, err := decode(body, 65536); err != nil {
		return Invalid
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return Invalid
	}
	return nil
}

func (s *Store) beginRetention(plan retentionPlan, admit func(*sql.Tx) error) error {
	body := encoded(plan)
	if len(body) > 65536 {
		return Invalid
	}
	return s.retentionTx(admit, func(tx *sql.Tx) error {
		changed, err := tx.Exec("UPDATE update_retention SET pending=?,reason='' WHERE update_id=? AND pending IS NULL", body, plan.UpdateID)
		if err != nil {
			return err
		}
		if count, err := changed.RowsAffected(); err != nil || count != 1 {
			return Invalid
		}
		return nil
	})
}

func captureRetention(path, id, kind string, rules map[string]usageRule, directories map[string]bool) (retentionPlan, error) {
	plan := retentionPlan{Schema: 1, UpdateID: id, Kind: kind, Path: path, Entries: []retentionEntry{}}
	var info unix.Stat_t
	if unix.Lstat(filepath.Dir(path), &info) != nil || !retentionDirectory(info) {
		return plan, Invalid
	}
	plan.Parent = retentionStat(info)
	if unix.Lstat(path, &info) != nil || !retentionDirectory(info) {
		return plan, Invalid
	}
	plan.Root = retentionStat(info)
	var walk func(string) error
	walk = func(relative string) error {
		items, err := os.ReadDir(filepath.Join(path, relative))
		if err != nil {
			return err
		}
		for _, item := range items {
			name := filepath.Join(relative, item.Name())
			if len(plan.Entries) >= 256 || unix.Lstat(filepath.Join(path, name), &info) != nil {
				return Invalid
			}
			if directories[name] {
				if !retentionDirectory(info) {
					return Invalid
				}
				plan.Entries = append(plan.Entries, retentionEntry{name, retentionStat(info)})
				if err = walk(name); err != nil {
					return err
				}
				continue
			}
			rule, ok := rules[name]
			if !ok || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Getuid()) || info.Nlink != 1 || info.Size < 0 || info.Size > rule.limit ||
				(info.Mode&0777 != 0600 && !(rule.readonly && info.Mode&0777 == 0400)) {
				return Invalid
			}
			plan.Entries = append(plan.Entries, retentionEntry{name, retentionStat(info)})
		}
		return nil
	}
	err := walk("")
	sort.Slice(plan.Entries, func(i, j int) bool { return plan.Entries[i].Name < plan.Entries[j].Name })
	return plan, err
}

func definitionRetentionPlan(dataDir string, r retainedUpdate) (retentionPlan, error) {
	a := r.adoption
	expected := ImageProfile{ProfileID: a.DefinitionImage.Profile.ProfileID, ScannerManifestSHA256: a.DefinitionImage.Binding.ScannerManifestSHA256,
		BinarySHA256: a.DefinitionImage.Binding.BinarySHA256, ConfigurationSHA256: a.DefinitionImage.Binding.ConfigurationSHA256, ObservationSHA256: a.DefinitionImage.Binding.ObservationSHA256}
	if a.Directory.UpdateID != r.attempt.ID || a.Directory.Inode == 0 || validateDefinitionImage(a.DefinitionImage, a.Manifest, expected) != nil {
		return retentionPlan{}, Invalid
	}
	path := filepath.Join(dataDir, "definitions", r.attempt.ID)
	rules := map[string]usageRule{"manifest.json": {limit: 16384}, "definition-image.json": {limit: 65536}, "definitions.ext4": {limit: DefinitionImageBytes, readonly: true}}
	for _, f := range a.Manifest.Files {
		if !candidateName(f.Name) {
			return retentionPlan{}, Invalid
		}
		rules[f.Name] = usageRule{limit: DefinitionCandidateLimit, readonly: true}
	}
	plan, err := captureRetention(path, r.attempt.ID, "definition", rules, nil)
	if err != nil || len(plan.Entries) != 6 || matchCandidateDirectory(path, a.Directory) != nil {
		return plan, Invalid
	}
	for _, f := range append(append([]candidateFile{}, a.Manifest.Files...), a.DefinitionImage.Image) {
		if candidateIdentity(context.Background(), filepath.Join(path, f.Name), f) != nil {
			return plan, Invalid
		}
	}
	for name, value := range map[string]any{"manifest.json": a.Manifest, "definition-image.json": a.DefinitionImage} {
		body, err := runtimeRead(filepath.Join(path, name), 65536)
		if err != nil || !bytes.Equal(body, encoded(value)) {
			return plan, Invalid
		}
	}
	after, err := captureRetention(path, r.attempt.ID, "definition", rules, nil)
	if err != nil || !reflect.DeepEqual(plan, after) {
		return plan, Invalid
	}
	return plan, nil
}

func (s *Store) runtimeRetentionPlan(dataDir string, r retainedUpdate) (retentionPlan, error) {
	path := filepath.Join(dataDir, "updates", r.attempt.ID)
	unstarted := !r.attempt.AdoptionApproved && !r.attempt.ControlCommitted && !r.attempt.OriginConfirmed && r.attempt.FinalSHA256 == ""
	var absent unix.Stat_t
	if err := unix.Lstat(path, &absent); errors.Is(err, os.ErrNotExist) && unstarted {
		if unix.Lstat(filepath.Dir(path), &absent) != nil || !retentionDirectory(absent) {
			return retentionPlan{}, Invalid
		}
		return retentionPlan{Schema: 1, UpdateID: r.attempt.ID, Kind: "runtime", Path: path, Parent: retentionStat(absent), Entries: []retentionEntry{}}, nil
	}
	rules := map[string]usageRule{"request.json": {limit: 16384}, "launch-intent.json": {limit: 16384}, "producer.lock": {limit: 0}}
	for name, rule := range runtimeOutputRules() {
		rules[filepath.Join("output", name)] = rule
	}
	for name, rule := range runtimeWatchdogRules() {
		rules[filepath.Join("output/watchdog", name)] = rule
	}
	dirs := map[string]bool{"output": true, "output/watchdog": true}
	plan, err := captureRetention(path, r.attempt.ID, "runtime", rules, dirs)
	if err != nil {
		return plan, err
	}
	if unstarted {
		if _, err := os.Lstat(filepath.Join(path, "output")); errors.Is(err, os.ErrNotExist) {
			for _, entry := range plan.Entries {
				if entry.Name != "request.json" && entry.Name != "producer.lock" && entry.Name != "launch-intent.json" {
					return plan, Invalid
				}
			}
			return plan, nil
		}
	}
	body, err := runtimeRead(filepath.Join(path, "request.json"), 16384)
	var requested normalRuntimeRequest
	if err != nil || runtimeJSON(body, &requested) != nil || requested.Profile != normalRuntimeProfile || requested.FixtureOnly || requested.ManifestSHA != r.runtimeSHA || requested.Attempt.ID != r.attempt.ID || requested.AttemptID != r.attempt.ID || requested.JobID != "update_"+r.attempt.ID || requested.Restore.UpdateID != r.attempt.ID || requested.Restore.BaseGeneration != r.attempt.BaseGeneration || requested.ByteSize != int64(len(encoded(requested.Restore))) || requested.ExpectedSHA != sha256Text(encoded(requested.Restore)) || s.validateDefinitionCacheRequest(body, requested) != nil {
		return plan, Invalid
	}
	requestSHA := sha256Text(body)
	body, err = runtimeRead(filepath.Join(path, "output/update-complete.json"), 16384)
	if errors.Is(err, os.ErrNotExist) {
		return plan, Invalid
	} else {
		var receipt fixtureRuntimeReceipt
		if err != nil || runtimeJSON(body, &receipt) != nil || receipt.Schema != 1 || receipt.Profile != normalRuntimeProfile || receipt.FixtureOnly || receipt.UpdateID != r.attempt.ID ||
			receipt.BaseGeneration != r.attempt.BaseGeneration || receipt.RequestSHA256 != requestSHA || !receipt.StopConfirmed || !receipt.CleanupConfirmed || !receipt.NetworkEnabled || receipt.AdoptionEnabled || (r.attempt.ControlCommitted && receipt.FinalSHA256 != r.attempt.FinalSHA256) {
			return plan, Invalid
		}
		if receipt.StartupOnly {
			err = validateFixtureStartup(path, requested.runtimeRequest, receipt)
		} else {
			err = validateFixtureCleanup(path, requested.runtimeRequest, receipt.CleanupSHA256)
		}
		if err != nil {
			return plan, err
		}
	}
	after, err := captureRetention(path, r.attempt.ID, "runtime", rules, dirs)
	if err != nil || !reflect.DeepEqual(plan, after) {
		return plan, Invalid
	}
	return plan, nil
}

func (s *Store) finishRetention(dataDir string, plan retentionPlan) error {
	parent := "updates"
	column := "runtime_removed"
	if plan.Kind == "definition" {
		parent, column = "definitions", "definition_removed"
	} else if plan.Kind != "runtime" {
		return Invalid
	}
	if plan.Schema != 1 || !identifier.MatchString(plan.UpdateID) || plan.Path != filepath.Join(dataDir, parent, plan.UpdateID) || len(plan.Entries) > 256 {
		return Invalid
	}
	fd, err := unix.Open(filepath.Dir(plan.Path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || !retentionSameDirectory(info, plan.Parent) {
		return Invalid
	}
	root, err := unix.Openat(fd, plan.UpdateID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		defer unix.Close(root)
		if unix.Fstat(root, &info) != nil || !retentionSameDirectory(info, plan.Root) {
			return Invalid
		}
		if plan.Kind == "runtime" {
			producer, openErr := unix.Openat(root, "producer.lock", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if openErr == nil {
				defer unix.Close(producer)
				if unix.Flock(producer, unix.LOCK_EX|unix.LOCK_NB) != nil {
					return Error("CLEANUP_PENDING")
				}
			} else if !errors.Is(openErr, os.ErrNotExist) {
				return openErr
			}
		}
		expected := map[string]retentionIdentity{}
		for _, e := range plan.Entries {
			if e.Name == "." || filepath.IsAbs(e.Name) || filepath.Clean(e.Name) != e.Name || strings.HasPrefix(e.Name, "../") || expected[e.Name].Inode != 0 {
				return Invalid
			}
			expected[e.Name] = e.Identity
		}
		if err = verifyRetentionTree(root, "", expected); err != nil {
			return err
		}
		entries := append([]retentionEntry{}, plan.Entries...)
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name > entries[j].Name })
		for _, entry := range entries {
			parentFD, openErr := retentionOpenParent(root, filepath.Dir(entry.Name))
			if errors.Is(openErr, os.ErrNotExist) {
				continue
			}
			if openErr != nil {
				return openErr
			}
			name := filepath.Base(entry.Name)
			err = unix.Fstatat(parentFD, name, &info, unix.AT_SYMLINK_NOFOLLOW)
			if err == nil {
				if !retentionEntryMatches(info, entry.Identity) {
					unix.Close(parentFD)
					return Invalid
				}
				flags := 0
				if info.Mode&unix.S_IFMT == unix.S_IFDIR {
					flags = unix.AT_REMOVEDIR
				}
				err = unix.Unlinkat(parentFD, name, flags)
			}
			if errors.Is(err, os.ErrNotExist) {
				err = nil
			}
			if err == nil {
				err = unix.Fsync(parentFD)
			}
			unix.Close(parentFD)
			if err != nil {
				return err
			}
		}
		if err = unix.Fsync(root); err != nil {
			return err
		}
		if unix.Fstatat(fd, plan.UpdateID, &info, unix.AT_SYMLINK_NOFOLLOW) != nil || !retentionSameDirectory(info, plan.Root) {
			return Invalid
		}
		if err = unix.Unlinkat(fd, plan.UpdateID, unix.AT_REMOVEDIR); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = unix.Fsync(fd); err != nil {
		return err
	}
	changed, err := s.db.Exec("UPDATE update_retention SET "+column+"=1,pending=NULL,reason='' WHERE update_id=? AND pending=?", plan.UpdateID, encoded(plan))
	if err != nil {
		return err
	}
	count, err := changed.RowsAffected()
	if err != nil || count != 1 {
		return Invalid
	}
	return nil
}

func retentionEntryMatches(info unix.Stat_t, expected retentionIdentity) bool {
	if expected.Mode&unix.S_IFMT == unix.S_IFDIR {
		return retentionSameDirectory(info, expected)
	}
	return info.Mode&unix.S_IFMT == unix.S_IFREG && info.Uid == uint32(os.Getuid()) && info.Nlink == 1 && retentionStat(info) == expected
}

func retentionOpenParent(root int, relative string) (int, error) {
	fd, err := unix.Dup(root)
	if err != nil {
		return -1, err
	}
	if relative == "." {
		return fd, nil
	}
	for _, name := range strings.Split(relative, string(filepath.Separator)) {
		next, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	return fd, nil
}

func verifyRetentionTree(fd int, relative string, expected map[string]retentionIdentity) error {
	duplicate, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(duplicate), relative)
	entries, err := dir.ReadDir(257)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 256 {
		return Invalid
	}
	for _, entry := range entries {
		name := filepath.Join(relative, entry.Name())
		want, ok := expected[name]
		var info unix.Stat_t
		if !ok || unix.Fstatat(fd, entry.Name(), &info, unix.AT_SYMLINK_NOFOLLOW) != nil || !retentionEntryMatches(info, want) {
			return Invalid
		}
		if info.Mode&unix.S_IFMT == unix.S_IFDIR {
			child, e := unix.Openat(fd, entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e != nil {
				return e
			}
			e = verifyRetentionTree(child, name, expected)
			unix.Close(child)
			if e != nil {
				return e
			}
		}
	}
	return nil
}
