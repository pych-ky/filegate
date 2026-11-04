package update

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const candidateLimit int64 = DefinitionCandidateLimit

type candidateFile struct {
	Name       string `json:"name"`
	SHA256     string `json:"sha256"`
	Bytes      int64  `json:"bytes"`
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	ModifiedNS int64  `json:"modified_ns"`
	ChangedNS  int64  `json:"changed_ns"`
}

type candidateManifest struct {
	Schema         int             `json:"schema"`
	UpdateID       string          `json:"update_id"`
	BaseGeneration int64           `json:"base_generation"`
	FinalSHA256    string          `json:"final_sha256"`
	Files          []candidateFile `json:"files"`
}

type candidateDirectory struct {
	Schema   int    `json:"schema"`
	UpdateID string `json:"update_id"`
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
}

type candidateOwner struct {
	candidateFile
	Schema   int    `json:"schema"`
	UpdateID string `json:"update_id"`
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
}

type imageFileOwner struct {
	Schema        int    `json:"schema"`
	UpdateID      string `json:"update_id"`
	Name          string `json:"name"`
	Bytes         int64  `json:"bytes"`
	ProfileSHA256 string `json:"profile_sha256"`
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
}

func ownedImageFile(output, id, name string, info unix.Stat_t, directory candidateDirectory) error {
	body, err := runtimeRead(filepath.Join(output, "image-owner.json"), 4096)
	var owner imageFileOwner
	if errors.Is(err, os.ErrNotExist) && name == "definitions.ext4.pending" && info.Size == 0 {
		body, err = runtimeRead(filepath.Join(output, "image-plan.json"), 4096)
		if err != nil || runtimeJSON(body, &owner) != nil || owner.Device != directory.Device || owner.Inode != directory.Inode {
			return Invalid
		}
	} else if err != nil || runtimeJSON(body, &owner) != nil || owner.Device != uint64(info.Dev) || owner.Inode != info.Ino {
		return Invalid
	}
	if owner.Schema != 1 || owner.UpdateID != id || owner.Name != "definitions.ext4" || owner.Bytes != DefinitionImageBytes ||
		!digestPattern.MatchString(owner.ProfileSHA256) || info.Size < 0 || info.Size > owner.Bytes {
		return Invalid
	}
	return nil
}

type adoptionRecord struct {
	Schema          int                     `json:"schema"`
	RuntimeSHA      string                  `json:"runtime_sha256"`
	Manifest        candidateManifest       `json:"manifest"`
	ManifestSHA     string                  `json:"manifest_sha256"`
	Directory       candidateDirectory      `json:"directory"`
	Approved        Clock                   `json:"approved"`
	DefinitionImage DefinitionImageManifest `json:"definition_image"`
}

func candidateName(name string) bool {
	base, suffix, ok := strings.Cut(name, ".")
	return ok && (base == "main" || base == "daily" || base == "bytecode") && (suffix == "cvd" || suffix == "cld")
}

func candidateIdentity(ctx context.Context, path string, expected candidateFile) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Getuid()) || info.Nlink != 1 ||
		info.Mode&0777 != 0400 || info.Size != expected.Bytes || uint64(info.Dev) != expected.Device || info.Ino != expected.Inode ||
		info.Mtim.Nano() != expected.ModifiedNS || info.Ctim.Nano() != expected.ChangedNS {
		return Invalid
	}
	return nil
}

func readCandidateDirectory(output, id string) (candidateDirectory, error) {
	var owner candidateDirectory
	body, err := runtimeRead(filepath.Join(output, "candidate-directory.json"), 4096)
	if err != nil || runtimeJSON(body, &owner) != nil || owner.Schema != 1 || owner.UpdateID != id || owner.Inode == 0 {
		return owner, Invalid
	}
	return owner, nil
}

func matchCandidateDirectory(path string, owner candidateDirectory) error {
	var info unix.Stat_t
	if unix.Lstat(path, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Uid != uint32(os.Getuid()) || info.Mode&0777 != 0700 ||
		uint64(info.Dev) != owner.Device || info.Ino != owner.Inode {
		return Invalid
	}
	return nil
}

// The broker holds its cancellation/pressure mutex through the adoption decision.
func (s *Store) AdoptRuntime(ctx context.Context, runtime *Runtime, id string) (bool, error) {
	directory, state, err := s.runtimeRecord(runtime, id)
	if err != nil || state != "STOPPED" {
		return false, Invalid
	}
	a, err := s.Attempt(id)
	if err != nil {
		return false, err
	}
	if a.AdoptionApproved {
		return true, s.completeAdoption(runtime, directory, id)
	}
	if !a.OriginConfirmed {
		return false, s.discardRuntimeCandidates(runtime, directory, id)
	}
	if a.Reason != "" || !a.ControlCommitted || !a.StopConfirmed || a.FinalReceived == nil || !a.FinalReceived.Valid() {
		return false, Invalid
	}
	output := filepath.Join(directory, "output")
	body, err := runtimeRead(filepath.Join(output, "candidates.json"), 16384)
	var manifest candidateManifest
	if err != nil || runtimeJSON(body, &manifest) != nil || manifest.Schema != 1 || manifest.UpdateID != id ||
		manifest.BaseGeneration != a.BaseGeneration || manifest.FinalSHA256 != a.FinalSHA256 || len(manifest.Files) != 3 {
		return false, Invalid
	}
	finalBytes, err := runtimeRead(filepath.Join(output, "final.json"), 1<<20)
	if err != nil || sha256Text(finalBytes) != a.FinalSHA256 {
		return false, Invalid
	}
	final, err := decode(finalBytes, 1<<20)
	if err != nil {
		return false, err
	}
	rows, ok := final["definitions"].([]any)
	if !ok || len(rows) != 3 {
		return false, Invalid
	}
	names, total := map[string]bool{}, int64(0)
	for _, file := range manifest.Files {
		name := strings.Split(file.Name, ".")[0]
		if !candidateName(file.Name) || names[name] || !digestPattern.MatchString(file.SHA256) || file.Bytes <= 0 || file.Bytes > candidateLimit {
			return false, Invalid
		}
		names[name], total = true, total+file.Bytes
		matched := false
		for _, item := range rows {
			row, ok := item.(map[string]any)
			if !ok || row["definition"] != name {
				continue
			}
			artifact, ok := row["artifact"].(map[string]any)
			if !ok {
				return false, Invalid
			}
			size, ok := number(artifact["bytes"], candidateLimit)
			matched = ok && size == file.Bytes && artifact["sha256"] == file.SHA256 && row["origin_confirmed"] == true && row["artifact_verified"] == true
		}
		if !matched || total > candidateLimit {
			return false, Invalid
		}
		if err = candidateIdentity(ctx, filepath.Join(output, "candidates", file.Name), file); err != nil {
			return false, err
		}
	}
	owner, err := readCandidateDirectory(output, id)
	if err != nil || matchCandidateDirectory(filepath.Join(output, "candidates"), owner) != nil {
		return false, Invalid
	}
	image, _, err := readDefinitionImage(filepath.Join(output, "definition-image.json"), manifest, runtime.manifest.ImageProfile)
	if err != nil || candidateIdentity(ctx, filepath.Join(output, "candidates", "definitions.ext4"), image.Image) != nil {
		return false, Invalid
	}
	entries, err := os.ReadDir(filepath.Join(output, "candidates"))
	if err != nil || len(entries) != 4 {
		return false, Invalid
	}
	root := filepath.Join(filepath.Dir(filepath.Dir(directory)), "definitions")
	if err = os.MkdirAll(root, 0700); err != nil {
		return false, err
	}
	if err = runtimeSyncDirectory(filepath.Dir(root)); err != nil {
		return false, err
	}
	if _, err = os.Lstat(filepath.Join(root, id)); !errors.Is(err, os.ErrNotExist) {
		return false, Invalid
	}
	now, err := ReadClock()
	if err != nil {
		return false, err
	}
	record := adoptionRecord{Schema: 1, RuntimeSHA: runtime.digest, Manifest: manifest, ManifestSHA: sha256Text(encoded(manifest)), Directory: owner, Approved: now}
	record.DefinitionImage = image
	_, err = s.apply(now, func(tx *sql.Tx, c *Control, now Clock) error {
		current, err := loadAttempt(tx, id)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return Error(runtimeReason(context.Cause(ctx)))
		}
		if c.Binding.FixtureOnly || c.Binding.LibrarySHA256 != runtime.LibrarySHA256() || c.Generation != current.BaseGeneration+1 || current.Reason != "" ||
			!current.StopConfirmed || !current.ControlCommitted || !current.OriginConfirmed || current.FinalSHA256 != record.Manifest.FinalSHA256 {
			return Invalid
		}
		approvalNow, clockErr := ReadClock()
		if clockErr != nil {
			return clockErr
		}
		if err = advance(c, approvalNow); err != nil {
			return err
		}
		record.Approved = approvalNow
		if err = deadline(current, approvalNow); err != nil {
			return err
		}
		if _, err = tx.Exec("INSERT INTO update_adoptions(update_id,data) VALUES(?,?)", id, encoded(record)); err != nil {
			return err
		}
		current.AdoptionApproved = true
		return saveAttempt(tx, current)
	})
	if err != nil {
		return false, err
	}
	return true, s.completeAdoption(runtime, directory, id)
}

func (s *Store) completeAdoption(runtime *Runtime, directory, id string) error {
	var raw []byte
	if err := s.db.QueryRow("SELECT data FROM update_adoptions WHERE update_id=?", id).Scan(&raw); err != nil {
		return err
	}
	var r adoptionRecord
	if decodeStored(raw, &r) != nil || r.Schema != 1 || r.RuntimeSHA != runtime.digest || r.Manifest.UpdateID != id || !r.Approved.Valid() ||
		r.ManifestSHA != sha256Text(encoded(r.Manifest)) || r.Directory.UpdateID != id || len(r.Manifest.Files) != 3 ||
		validateDefinitionImage(r.DefinitionImage, r.Manifest, runtime.manifest.ImageProfile) != nil {
		return Invalid
	}
	root := filepath.Join(filepath.Dir(filepath.Dir(directory)), "definitions")
	target, source := filepath.Join(root, id), filepath.Join(directory, "output/candidates")
	if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
		if matchCandidateDirectory(source, r.Directory) != nil {
			return Invalid
		}
		if err = runtimeRename(source, target); err != nil {
			return err
		}
		if err = runtimeSyncDirectory(filepath.Dir(source)); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if matchCandidateDirectory(target, r.Directory) != nil {
		return Invalid
	}
	for _, file := range r.Manifest.Files {
		path := filepath.Join(target, file.Name)
		if !candidateName(file.Name) || candidateIdentity(context.Background(), path, file) != nil {
			return Invalid
		}

	}
	if err := candidateIdentity(context.Background(), filepath.Join(target, "definitions.ext4"), r.DefinitionImage.Image); err != nil {
		return err
	}
	for _, record := range []struct {
		name    string
		value   any
		maximum int64
	}{{"manifest.json", r.Manifest, 16384}, {"definition-image.json", r.DefinitionImage, 64 << 10}} {
		manifestPath := filepath.Join(target, record.name)
		body := encoded(record.value)
		if existing, err := runtimeRead(manifestPath, record.maximum); err == nil {
			if !bytes.Equal(existing, body) {
				if !bytes.HasPrefix(body, existing) {
					return Invalid
				}
				if err = os.Remove(manifestPath); err != nil {
					return err
				}
				if err = runtimeSyncDirectory(target); err != nil {
					return err
				}
				if err = runtimeWrite(manifestPath, record.value); err != nil {
					return err
				}
			}
		} else if errors.Is(err, os.ErrNotExist) {
			if err = runtimeWrite(manifestPath, record.value); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	if err := runtimeSyncDirectory(target); err != nil {
		return err
	}
	if err := runtimeSyncDirectory(root); err != nil {
		return err
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 6 {
		return Invalid
	}
	allowed := map[string]bool{"manifest.json": true, "definitions.ext4": true, "definition-image.json": true}
	for _, file := range r.Manifest.Files {
		allowed[file.Name] = true
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return Invalid
		}
	}
	now, err := ReadClock()
	if err != nil {
		return err
	}
	_, err = s.apply(now, func(tx *sql.Tx, c *Control, now Clock) error {
		a, err := loadAttempt(tx, id)
		if err != nil {
			return err
		}
		if !a.AdoptionApproved || !a.StopConfirmed || a.FinalReceived == nil || a.FinalSHA256 != r.Manifest.FinalSHA256 ||
			c.Binding.FixtureOnly || c.Generation != a.BaseGeneration+1 || deadline(a, r.Approved) != nil {
			return Invalid
		}
		c.Definition = &DefinitionSet{UpdateID: id, Generation: c.Generation, Confirmed: *a.FinalReceived, ManifestSHA256: r.ManifestSHA, ImageManifestSHA256: sha256Text(encoded(r.DefinitionImage))}
		a.CleanupConfirmed, a.ReservedBytes, a.State, a.FinishedUTC = true, 0, "FINISHED", now.UTC
		if err = saveAttempt(tx, a); err != nil {
			return err
		}
		_, err = tx.Exec("UPDATE update_runtime SET state='FINISHED' WHERE update_id=?", id)
		return err
	})
	return err
}

func (s *Store) discardRuntimeCandidates(runtime *Runtime, directory, id string) error {
	output := filepath.Join(directory, "output")
	path := filepath.Join(output, "candidates")
	entries, err := os.ReadDir(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		owner, e := readCandidateDirectory(output, id)
		if e != nil {
			body, intentErr := runtimeRead(filepath.Join(output, "candidate-directory-intent.json"), 4096)
			var intent candidateDirectory
			var info unix.Stat_t
			if intentErr != nil || runtimeJSON(body, &intent) != nil || intent.Schema != 1 || intent.UpdateID != id ||
				matchCandidateDirectory(output, intent) != nil || len(entries) != 0 || unix.Lstat(path, &info) != nil ||
				info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Mode&0777 != 0700 || info.Uid != uint32(os.Getuid()) {
				return Invalid
			}
			owner = candidateDirectory{1, id, uint64(info.Dev), info.Ino}
		}
		if matchCandidateDirectory(path, owner) != nil {
			return Invalid
		}
		for _, entry := range entries {
			name := strings.TrimSuffix(entry.Name(), ".pending")
			if !candidateName(name) && name != "definitions.ext4" {
				return Invalid
			}
			if name == "definitions.ext4" {
				item := filepath.Join(path, entry.Name())
				var info unix.Stat_t
				if unix.Lstat(item, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Getuid()) ||
					(info.Mode&0777 != 0600 && info.Mode&0777 != 0400) || info.Nlink != 1 || ownedImageFile(output, id, entry.Name(), info, owner) != nil {
					return Invalid
				}
				if e = os.Remove(item); e != nil {
					return e
				}
				continue
			}
			body, e := runtimeRead(filepath.Join(output, "candidate-owner-"+strings.Split(name, ".")[0]+".json"), 4096)
			var file candidateOwner
			var info unix.Stat_t
			item := filepath.Join(path, entry.Name())
			if unix.Lstat(item, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Getuid()) || (info.Mode&0777 != 0600 && info.Mode&0777 != 0400) || info.Nlink != 1 ||
				info.Size < 0 {
				return Invalid
			}
			if errors.Is(e, os.ErrNotExist) && info.Size == 0 && entry.Name() == name+".pending" {
				body, e = runtimeRead(filepath.Join(output, "candidate-plan-"+strings.Split(name, ".")[0]+".json"), 4096)
				if e != nil || runtimeJSON(body, &file) != nil || file.Device != owner.Device || file.Inode != owner.Inode {
					return Invalid
				}
			} else {
				if e != nil || runtimeJSON(body, &file) != nil || uint64(info.Dev) != file.Device || info.Ino != file.Inode {
					return Invalid
				}
			}
			if file.Schema != 1 || file.UpdateID != id || file.Name != name || !digestPattern.MatchString(file.SHA256) || file.Bytes <= 0 || file.Bytes > candidateLimit || info.Size > file.Bytes {
				return Invalid
			}
			if e = os.Remove(item); e != nil {
				return e
			}
		}
		if err = runtimeSyncDirectory(path); err != nil {
			return err
		}
		if err = os.Remove(path); err != nil {
			return err
		}
		if err = runtimeSyncDirectory(output); err != nil {
			return err
		}
	}
	now, err := ReadClock()
	if err != nil {
		return err
	}
	if _, err = s.Stopped(id, true, now); err != nil {
		return err
	}
	_, err = s.db.Exec("UPDATE update_runtime SET state='FINISHED' WHERE update_id=?", id)
	return err
}
