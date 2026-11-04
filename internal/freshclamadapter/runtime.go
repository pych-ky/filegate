package freshclamadapter

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const Prefix = "/opt/filegate-av"
const LibraryPath = Prefix + "/lib/libfreshclam.so.3"

var libraryName = regexp.MustCompile(`^lib(?:clamav|freshclam|clamunrar|clamunrar_iface)\.so(?:\.[0-9]+)*$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type elfBinding struct {
	Machine string   `json:"machine"`
	Needed  []string `json:"needed"`
	SONAME  []string `json:"soname"`
	RPath   []string `json:"rpath"`
}

type libraryEntry struct {
	Path    string     `json:"path"`
	Symlink string     `json:"symlink"`
	Bytes   int64      `json:"bytes"`
	SHA256  string     `json:"sha256"`
	ELF     elfBinding `json:"elf"`
}

func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

func sameIdentity(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func readFile(path string, maximum int64, rootOwned bool) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, invalid
	}
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 || before.Size > maximum || rootOwned && (before.Uid != 0 || before.Gid != 0 || before.Mode&0222 != 0) {
		return nil, invalid
	}
	data, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil || int64(len(data)) != before.Size || unix.Fstat(int(f.Fd()), &after) != nil || !sameIdentity(before, after) {
		return nil, invalid
	}
	return data, nil
}

func FileDigest(path string) (string, int64, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", 0, invalid
	}
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 {
		return "", 0, invalid
	}
	h := sha256.New()
	if _, err = io.CopyN(h, f, before.Size); err != nil || unix.Fstat(int(f.Fd()), &after) != nil || !sameIdentity(before, after) {
		return "", 0, invalid
	}
	return hex.EncodeToString(h.Sum(nil)), before.Size, nil
}

func elfIdentity(data []byte) (elfBinding, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return elfBinding{}, invalid
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_AARCH64 {
		return elfBinding{}, invalid
	}
	v := elfBinding{Machine: "AArch64"}
	if v.Needed, err = f.DynString(elf.DT_NEEDED); err != nil {
		return v, invalid
	}
	if v.SONAME, err = f.DynString(elf.DT_SONAME); err != nil {
		return v, invalid
	}
	if v.RPath, err = f.DynString(elf.DT_RPATH); err != nil {
		return v, invalid
	}
	run, err := f.DynString(elf.DT_RUNPATH)
	if err != nil {
		return v, invalid
	}
	v.RPath = append(v.RPath, run...)
	return v, nil
}

func librarySet() ([]string, error) {
	for _, path := range []string{Prefix, Prefix + "/lib", Prefix + "/fixed-adapter.json"} {
		var info unix.Stat_t
		if unix.Lstat(path, &info) != nil || info.Mode&unix.S_IFMT == unix.S_IFLNK || info.Uid != 0 || info.Gid != 0 || info.Mode&0222 != 0 {
			return nil, invalid
		}
	}
	body, err := readFile(Prefix+"/fixed-adapter.json", Limit, true)
	if err != nil {
		return nil, err
	}
	binding, err := document(body)
	if err != nil {
		return nil, err
	}
	manifest, ok := binding["manifest"].(map[string]any)
	if !ok {
		return nil, invalid
	}
	encoded, err := json.Marshal(manifest["entries"])
	if err != nil {
		return nil, invalid
	}
	var entries []libraryEntry
	if json.Unmarshal(encoded, &entries) != nil || len(entries) < 4 || len(entries) > 32 {
		return nil, invalid
	}
	names, families := map[string]bool{}, map[string]bool{}
	var regular []string
	var total int64
	for _, row := range entries {
		if !strings.HasPrefix(row.Path, "lib/") || !libraryName.MatchString(strings.TrimPrefix(row.Path, "lib/")) || names[row.Path] {
			return nil, invalid
		}
		names[row.Path] = true
		path := Prefix + "/" + row.Path
		var info unix.Stat_t
		if unix.Lstat(path, &info) != nil || info.Uid != 0 || info.Gid != 0 {
			return nil, invalid
		}
		if row.Symlink != "" {
			target, err := os.Readlink(path)
			resolved, resolveErr := filepath.EvalSymlinks(path)
			if err != nil || resolveErr != nil || !libraryName.MatchString(row.Symlink) || target != row.Symlink || filepath.Dir(resolved) != Prefix+"/lib" {
				return nil, invalid
			}
			continue
		}
		if info.Size != row.Bytes || !digestPattern.MatchString(row.SHA256) {
			return nil, invalid
		}
		data, err := readFile(path, 128<<20, true)
		if err != nil || digest(data) != row.SHA256 {
			return nil, invalid
		}
		total += int64(len(data))
		if total > 128<<20 {
			return nil, invalid
		}
		actual, err := elfIdentity(data)
		if err != nil || actual.Machine != row.ELF.Machine || !slices.Equal(actual.Needed, row.ELF.Needed) || !slices.Equal(actual.SONAME, row.ELF.SONAME) || !slices.Equal(actual.RPath, row.ELF.RPath) || !slices.Equal(actual.RPath, []string{"$ORIGIN"}) || len(actual.SONAME) != 1 {
			return nil, invalid
		}
		regular = append(regular, row.Path)
		families[strings.Split(filepath.Base(row.Path), ".so")[0]] = true
	}
	listing, err := os.ReadDir(Prefix + "/lib")
	if err != nil || len(listing) != len(names) {
		return nil, invalid
	}
	for _, entry := range listing {
		if !names["lib/"+entry.Name()] {
			return nil, invalid
		}
	}
	for _, row := range entries {
		if row.Symlink != "" {
			if !names["lib/"+row.Symlink] {
				return nil, invalid
			}
			continue
		}
		for _, name := range append(slices.Clone(row.ELF.SONAME), row.ELF.Needed...) {
			if strings.HasPrefix(name, "libclam") || strings.HasPrefix(name, "libfreshclam") {
				if !names["lib/"+name] {
					return nil, invalid
				}
			}
		}
	}
	if len(families) != 4 || !families["libclamav"] || !families["libfreshclam"] || !families["libclamunrar"] || !families["libclamunrar_iface"] {
		return nil, invalid
	}
	sort.Strings(regular)
	return regular, nil
}

func mapped(regular []string, complete bool) error {
	body, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return invalid
	}
	found := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.HasPrefix(fields[5], "/") {
			continue
		}
		path := strings.Join(fields[5:], " ")
		if !libraryName.MatchString(strings.TrimSuffix(filepath.Base(path), " (deleted)")) {
			continue
		}
		name := "lib/" + filepath.Base(path)
		if filepath.Dir(path) != Prefix+"/lib" || !slices.Contains(regular, name) {
			return invalid
		}
		found[name] = true
	}
	if complete && len(found) != len(regular) {
		return invalid
	}
	return nil
}

func loadRuntime(requested string) (library, string, error) {
	path, err := filepath.EvalSymlinks(requested)
	expected, targetErr := filepath.EvalSymlinks(LibraryPath)
	if err != nil || targetErr != nil || path != expected {
		return nil, "", invalid
	}
	regular, err := librarySet()
	if err != nil || mapped(regular, false) != nil {
		return nil, "", invalid
	}
	l, err := newLibrary()
	if err != nil {
		return nil, "", err
	}
	success := false
	defer func() {
		if !success {
			l.close()
		}
	}()
	for _, relative := range regular {
		if l.load(Prefix+"/"+relative) != nil {
			return nil, "", invalid
		}
	}
	if mapped(regular, true) != nil || l.bind(path) != nil {
		return nil, "", invalid
	}
	h, _, err := FileDigest(path)
	if err != nil {
		return nil, "", err
	}
	success = true
	return l, h, nil
}
