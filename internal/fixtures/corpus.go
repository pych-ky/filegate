package fixtures

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type corpusFile struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type corpusManifest struct {
	Schema            int                   `json:"schema"`
	Kind              string                `json:"kind"`
	ArchiveSHA256     string                `json:"archive_sha256"`
	ArchiveBytes      int64                 `json:"archive_bytes"`
	FileCount         int                   `json:"file_count"`
	UncompressedBytes int64                 `json:"uncompressed_bytes"`
	Files             map[string]corpusFile `json:"files"`
	Manifests         map[string]string     `json:"manifests"`
	CaseCounts        map[string]int        `json:"case_counts"`
	Profiles          map[string]string     `json:"profiles_sha256"`
}

func corpusPath(name string) bool {
	return filepath.IsLocal(name) && filepath.ToSlash(filepath.Clean(name)) == name &&
		!strings.HasSuffix(name, ".py") && (strings.HasPrefix(name, "inputs/") ||
		name == "fixture-manifest.json" || name == "image-manifest.json" || name == "ooxml-manifest.json")
}

func readOwned(path string, limit int64, readonly bool) ([]byte, unix.Stat_t, error) {
	var before, after, named unix.Stat_t
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, before, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Size < 0 || before.Size > limit ||
		readonly && (before.Uid != 0 || before.Gid != 0 || before.Mode&0222 != 0) {
		return nil, before, invalid
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Lstat(path, &named) != nil ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Mtim != after.Mtim || before.Ctim != after.Ctim ||
		before.Dev != named.Dev || before.Ino != named.Ino || before.Mode != named.Mode || before.Mtim != named.Mtim || before.Ctim != named.Ctim {
		return nil, before, invalid
	}
	return body, before, nil
}

func ExtractCorpus(archive, manifest, target string, readonly bool) (*corpusManifest, error) {
	body, _, err := readOwned(manifest, 1<<20, readonly)
	var spec corpusManifest
	if err != nil || decode(body, &spec) != nil || spec.Schema != 1 || spec.Kind != "immutable_finite_format_fixture_corpus" ||
		spec.FileCount < 1 || spec.FileCount > 1024 || len(spec.Files) != spec.FileCount || spec.ArchiveBytes < 1 || spec.ArchiveBytes > 64<<20 ||
		spec.UncompressedBytes < 1 || spec.UncompressedBytes > 256<<20 || len(spec.Manifests) != 3 {
		return nil, invalid
	}
	data, _, err := readOwned(archive, 64<<20, readonly)
	if err != nil || int64(len(data)) != spec.ArchiveBytes || digest(data) != spec.ArchiveSHA256 {
		return nil, invalid
	}
	for name, file := range spec.Files {
		if !corpusPath(name) || file.Bytes < 0 || file.Bytes > 128<<20 || len(file.SHA256) != 64 {
			return nil, invalid
		}
	}
	if err = os.Mkdir(target, 0700); err != nil {
		return nil, err
	}
	if err = os.Mkdir(filepath.Join(target, "inputs"), 0700); err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	reader := tar.NewReader(io.LimitReader(gz, spec.UncompressedBytes+int64(spec.FileCount)*4096+1))
	seen, total := make(map[string]bool), int64(0)
	for {
		header, next := reader.Next()
		if next == io.EOF {
			break
		}
		if next != nil || header.Typeflag != tar.TypeReg || !corpusPath(header.Name) || seen[header.Name] {
			return nil, invalid
		}
		expected, ok := spec.Files[header.Name]
		total += header.Size
		if !ok || header.Size != expected.Bytes || total > spec.UncompressedBytes {
			return nil, invalid
		}
		value, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(value)) != header.Size || digest(value) != expected.SHA256 {
			return nil, invalid
		}
		path := filepath.Join(target, header.Name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, err = f.Write(value)
		closed := f.Close()
		if err != nil || closed != nil {
			return nil, invalid
		}
		seen[header.Name] = true
	}
	if len(seen) != spec.FileCount || total != spec.UncompressedBytes {
		return nil, invalid
	}
	for name, expected := range spec.Manifests {
		if spec.Files[name].SHA256 != expected {
			return nil, invalid
		}
	}
	return &spec, nil
}

type formatCase struct {
	ID       string         `json:"id"`
	Input    string         `json:"input"`
	SHA256   string         `json:"sha256"`
	Bytes    int64          `json:"bytes"`
	Metadata map[string]any `json:"metadata"`
	Expected map[string]any `json:"expected"`
}

func readCases(path string) ([]formatCase, []formatCase, error) {
	body, err := os.ReadFile(path)
	var value struct {
		Cases []formatCase `json:"cases"`
		Text  []formatCase `json:"text_cases"`
	}
	if err != nil || json.Unmarshal(body, &value) != nil {
		return nil, nil, invalid
	}
	return value.Cases, value.Text, nil
}
