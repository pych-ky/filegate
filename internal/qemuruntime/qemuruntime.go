// Package qemuruntime pins the fixed QEMU 11.1.2 keg and the recursive closure of its non-system dynamic libraries.
// The closure is captured once when a build receipt is constructed; runtime boundaries only verify it and never rewrite it.
package qemuruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	Version    = "11.1.2"
	Keg        = "/opt/homebrew/Cellar/qemu/" + Version
	SystemName = "qemu-system-aarch64"
	ImageName  = "qemu-img"
	Kind       = "qemu_fixed_keg_dylib_closure"
	// System install names are served by dyld from the OS shared cache or the sealed system volume; they are not hashed, only bound to the sw_vers build.
	SystemPolicy = "system_install_names_resolved_by_dyld_shared_cache_or_sealed_system_volume_not_hashed_bound_to_sw_vers"
	// Libraries opened later with dlopen do not appear in load commands and are outside this closure.
	DynamicLoadPolicy = "dlopen_modules_not_covered_static_load_commands_only"
	fileLimit         = 256 << 20
	closureLimit      = 128
)

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Edge struct {
	From        string `json:"from"`
	Command     string `json:"command"`
	InstallName string `json:"install_name"`
	Resolved    string `json:"resolved,omitempty"`
}

type Manifest struct {
	Schema            int               `json:"schema"`
	Kind              string            `json:"kind"`
	Keg               string            `json:"keg"`
	Version           string            `json:"version"`
	HostOS            string            `json:"host_os"`
	Executables       map[string]File   `json:"executables"`
	Libraries         map[string]string `json:"libraries"`
	Edges             []Edge            `json:"edges"`
	SystemEdges       []Edge            `json:"system_edges"`
	SystemPolicy      string            `json:"system_policy"`
	DynamicLoadPolicy string            `json:"dynamic_load_policy"`
}

// Every file in the closure, executables included, keyed by canonical path.
func (m Manifest) Files() map[string]string {
	files := map[string]string{}
	for _, file := range m.Executables {
		files[file.Path] = file.SHA256
	}
	for path, digest := range m.Libraries {
		files[path] = digest
	}
	return files
}

func (m Manifest) System() File { return m.Executables[SystemName] }
func (m Manifest) Image() File  { return m.Executables[ImageName] }

// scope separates the fixed requirement from the derivation so isolated copies can exercise the same code.
type scope struct {
	keg         string
	cellar      string
	system      []string
	executables map[string]string
}

var fixed = scope{keg: Keg, cellar: "/opt/homebrew/Cellar/", system: []string{"/usr/lib/", "/System/Library/"}, executables: map[string]string{SystemName: Keg + "/bin/" + SystemName, ImageName: Keg + "/bin/" + ImageName}}

// Environment is the fixed environment for QEMU tools started from Go, the same one the native watchdog gives the VM, so DYLD_* cannot redirect loading.
func Environment() []string { return []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"} }

func HostOS() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sw_vers")
	cmd.Env = Environment()
	body, err := cmd.Output()
	if err != nil || len(body) == 0 {
		return "", errors.New("QEMU_RUNTIME_HOST_UNKNOWN")
	}
	return string(body), nil
}

// SystemVersion is HostOS for list and detail display: it rebuilds sw_vers' three lines from SystemVersion.plist only for the
// recognized flat schema and runs sw_vers for anything else.
func SystemVersion() (string, error) {
	const dir = "/System/Library/CoreServices/"
	if host, ok := systemVersion(dir+"ServerVersion.plist", dir+"SystemVersion.plist", "/System/Cryptexes/OS"+dir+"SystemVersion.plist"); ok {
		return host, nil
	}
	return HostOS()
}

// systemVersion refuses a server plist, a differing OS cryptex copy, ProductVersionExtra, ReleaseType and every key, type or
// structure not listed here, because sw_vers' output for those is not established.
func systemVersion(server, system, cryptex string) (string, bool) {
	if _, err := os.Lstat(server); !errors.Is(err, os.ErrNotExist) {
		return "", false
	}
	body, err := readPlist(system)
	if err != nil {
		return "", false
	}
	if other, err := readPlist(cryptex); err == nil && !bytes.Equal(other, body) || err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", false
	}
	values, ok := plistStrings(body)
	name, version, build := values["ProductName"], values["ProductVersion"], values["ProductBuildVersion"]
	if visible, found := values["ProductUserVisibleVersion"]; !ok || found && visible != version || !plainVersion(name) || !plainVersion(version) || !plainVersion(build) {
		return "", false
	}
	return "ProductName:\t\t" + name + "\nProductVersion:\t\t" + version + "\nBuildVersion:\t\t" + build + "\n", true
}

func readPlist(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("plist is not a regular file")
	}
	body, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err == nil && len(body) > 64<<10 {
		err = errors.New("plist too large")
	}
	return body, err
}

var plistKeys = map[string]bool{"BuildID": true, "ProductBuildVersion": true, "ProductCopyright": true, "ProductName": true,
	"ProductUserVisibleVersion": true, "ProductVersion": true, "iOSSupportVersion": true}

// plistStrings accepts only an XML plist whose root dict holds unique listed keys with string values.
func plistStrings(body []byte) (map[string]string, bool) {
	d := xml.NewDecoder(bytes.NewReader(body))
	var tokenErr error
	next := func() xml.Token {
		for {
			t, err := d.Token()
			if err != nil {
				tokenErr = err
				return nil
			}
			if c, ok := t.(xml.CharData); !ok || len(bytes.TrimSpace(c)) != 0 {
				return xml.CopyToken(t)
			}
		}
	}
	start := func(t xml.Token, name string, attrs ...xml.Attr) bool {
		s, ok := t.(xml.StartElement)
		return ok && s.Name == xml.Name{Local: name} && len(s.Attr) == len(attrs) && (len(attrs) == 0 || s.Attr[0] == attrs[0])
	}
	end := func(t xml.Token, name string) bool {
		e, ok := t.(xml.EndElement)
		return ok && e.Name == xml.Name{Local: name}
	}
	// Inside a key or string, whitespace is kept: one text token at most, then the end tag; split text or anything else is refused.
	raw := func() xml.Token {
		t, err := d.Token()
		if err != nil {
			tokenErr = err
		}
		return t
	}
	text := func(t xml.Token, name string) (string, bool) {
		if !start(t, name) {
			return "", false
		}
		value, t := "", raw()
		if c, ok := t.(xml.CharData); ok {
			value = string(c) // copied before the next token reuses the decoder's buffer
			t = raw()
		}
		return value, end(t, name)
	}
	if p, ok := next().(xml.ProcInst); !ok || p.Target != "xml" {
		return nil, false
	}
	if dir, ok := next().(xml.Directive); !ok || !bytes.HasPrefix(dir, []byte("DOCTYPE plist ")) {
		return nil, false
	}
	if !start(next(), "plist", xml.Attr{Name: xml.Name{Local: "version"}, Value: "1.0"}) || !start(next(), "dict") {
		return nil, false
	}
	values := map[string]string{}
	for t := next(); !end(t, "dict"); t = next() {
		key, ok := text(t, "key")
		value, found := text(next(), "string")
		if _, duplicate := values[key]; !ok || !found || !plistKeys[key] || duplicate {
			return nil, false
		}
		values[key] = value
	}
	return values, end(next(), "plist") && next() == nil && tokenErr == io.EOF
}

// plainVersion keeps the fast path to values sw_vers prints unchanged: letters, digits and dots.
func plainVersion(s string) bool {
	return s != "" && strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.") == ""
}

// Capture records the closure of the fixed keg from the current bytes; only build receipt construction calls it.
func Capture(ctx context.Context) (Manifest, error) {
	host, err := HostOS()
	if err != nil {
		return Manifest{}, err
	}
	for name, field := range map[string]int{SystemName: 3, ImageName: 2} {
		cmd := exec.CommandContext(ctx, fixed.executables[name], "--version")
		cmd.Env = Environment()
		body, err := cmd.Output()
		parts := strings.Fields(strings.SplitN(string(body), "\n", 2)[0])
		if err != nil || len(parts) <= field || parts[field] != Version {
			return Manifest{}, errors.New("QEMU_RUNTIME_VERSION_INVALID")
		}
	}
	return fixed.capture(host)
}

// Verify re-derives the closure from the current files and requires it to equal the frozen record; it returns the record digest.
func Verify(m Manifest) (string, error) {
	host, err := HostOS()
	if err != nil {
		return "", err
	}
	return fixed.verify(m, host)
}

// Observe records the host OS, each closure file's canonical path and identity and each install name's resolution without
// reading content; any change after a successful Verify makes the next caller run Verify again.
func Observe(m Manifest, host string) (string, error) {
	if m.HostOS != host {
		return "", errors.New("QEMU_RUNTIME_HOST_CHANGED")
	}
	files := m.Files()
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, path := range paths {
		var st unix.Stat_t
		if actual, err := filepath.EvalSymlinks(path); err != nil || actual != path || unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
			return "", errors.New("QEMU_RUNTIME_FILE_CHANGED")
		}
		identity, _ := json.Marshal([]any{path, st.Dev, st.Ino, st.Nlink, st.Mode, st.Uid, st.Gid, st.Size, st.Mtim, st.Ctim})
		h.Write(append(identity, '\n'))
	}
	for _, edge := range m.Edges {
		if resolved, err := filepath.EvalSymlinks(edge.InstallName); err != nil || resolved != edge.Resolved {
			return "", errors.New("QEMU_RUNTIME_RESOLUTION_CHANGED")
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Decode reads a frozen record strictly from a receipt value.
func Decode(value any) (Manifest, error) {
	var m Manifest
	var body []byte
	switch v := value.(type) {
	case json.RawMessage:
		body = v
	case []byte:
		body = v
	case nil:
		return m, errors.New("QEMU_RUNTIME_RECORD_MISSING")
	default:
		var err error
		if body, err = json.Marshal(v); err != nil {
			return m, errors.New("QEMU_RUNTIME_RECORD_INVALID")
		}
	}
	if len(body) == 0 || string(body) == "null" {
		return m, errors.New("QEMU_RUNTIME_RECORD_MISSING")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&m) != nil || decoder.Decode(new(any)) != io.EOF {
		return Manifest{}, errors.New("QEMU_RUNTIME_RECORD_INVALID")
	}
	return m, nil
}

func Digest(m Manifest) string {
	body, _ := json.Marshal(m)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func (s scope) capture(host string) (Manifest, error) {
	m := Manifest{Schema: 1, Kind: Kind, Keg: s.keg, Version: Version, HostOS: host, Executables: map[string]File{}, Libraries: map[string]string{}, Edges: []Edge{}, SystemEdges: []Edge{}, SystemPolicy: SystemPolicy, DynamicLoadPolicy: DynamicLoadPolicy}
	names := map[string]string{}
	queue := []string{}
	for name, path := range s.executables {
		names[path] = name
		queue = append(queue, path)
	}
	sort.Strings(queue)
	seen := map[string]bool{}
	for _, path := range queue {
		seen[path] = true
	}
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		kind := macho.TypeDylib
		if names[path] != "" {
			kind = macho.TypeExec
		}
		digest, loads, err := s.read(path, kind)
		if err != nil {
			return Manifest{}, err
		}
		if kind == macho.TypeExec {
			m.Executables[names[path]] = File{path, digest}
		} else {
			m.Libraries[path] = digest
		}
		for _, load := range loads {
			if s.systemName(load.name) {
				m.SystemEdges = append(m.SystemEdges, Edge{From: path, Command: load.command, InstallName: load.name})
				continue
			}
			resolved, err := s.resolve(load.name)
			if err != nil {
				return Manifest{}, err
			}
			m.Edges = append(m.Edges, Edge{From: path, Command: load.command, InstallName: load.name, Resolved: resolved})
			if !seen[resolved] {
				seen[resolved] = true
				queue = append(queue, resolved)
			}
			if len(seen) > closureLimit {
				return Manifest{}, errors.New("QEMU_RUNTIME_CLOSURE_LIMIT")
			}
		}
	}
	for _, edges := range [][]Edge{m.Edges, m.SystemEdges} {
		sort.Slice(edges, func(i, j int) bool {
			a, b := edges[i], edges[j]
			return a.From+"\x00"+a.Command+"\x00"+a.InstallName < b.From+"\x00"+b.Command+"\x00"+b.InstallName
		})
	}
	return m, nil
}

func (s scope) verify(m Manifest, host string) (string, error) {
	if m.Schema != 1 || m.Kind != Kind || m.Keg != s.keg || m.Version != Version || m.SystemPolicy != SystemPolicy || m.DynamicLoadPolicy != DynamicLoadPolicy || len(m.Executables) != len(s.executables) || len(m.Libraries) == 0 || len(m.Libraries) > closureLimit {
		return "", errors.New("QEMU_RUNTIME_RECORD_INVALID")
	}
	for name, path := range s.executables {
		if m.Executables[name].Path != path {
			return "", errors.New("QEMU_RUNTIME_RECORD_INVALID")
		}
	}
	if m.HostOS != host {
		return "", errors.New("QEMU_RUNTIME_HOST_CHANGED")
	}
	current, err := s.capture(host)
	if err != nil {
		return "", err
	}
	for name, file := range m.Executables {
		if current.Executables[name] != file {
			return "", errors.New("QEMU_RUNTIME_FILE_CHANGED")
		}
	}
	for path, digest := range m.Libraries {
		actual, ok := current.Libraries[path]
		if !ok {
			return "", errors.New("QEMU_RUNTIME_RESOLUTION_CHANGED")
		}
		if actual != digest {
			return "", errors.New("QEMU_RUNTIME_FILE_CHANGED")
		}
	}
	if len(current.Libraries) != len(m.Libraries) || !reflect.DeepEqual(current.Edges, m.Edges) || !reflect.DeepEqual(current.SystemEdges, m.SystemEdges) {
		return "", errors.New("QEMU_RUNTIME_RESOLUTION_CHANGED")
	}
	return Digest(m), nil
}

func (s scope) systemName(name string) bool {
	for _, prefix := range s.system {
		if strings.HasPrefix(name, prefix) && filepath.Clean(name) == name {
			return true
		}
	}
	return false
}

// resolve follows the symlinks of an absolute install name to a regular, non-writable-by-others file inside the Cellar.
func (s scope) resolve(name string) (string, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return "", errors.New("QEMU_RUNTIME_UNRESOLVABLE")
	}
	resolved, err := filepath.EvalSymlinks(name)
	if err != nil || !strings.HasPrefix(resolved, s.cellar) || filepath.Clean(resolved) != resolved {
		return "", errors.New("QEMU_RUNTIME_UNRESOLVABLE")
	}
	return resolved, nil
}

type load struct{ command, name string }

var dylibCommands = map[macho.LoadCmd]string{0xc: "LC_LOAD_DYLIB", 0x80000018: "LC_LOAD_WEAK_DYLIB", 0x8000001f: "LC_REEXPORT_DYLIB", 0x80000023: "LC_LOAD_UPWARD_DYLIB", 0x20: "LC_LAZY_LOAD_DYLIB"}

// LC_DYLD_ENVIRONMENT can set DYLD_* search paths from inside the binary, so it is refused instead of half-modelled.
// LC_RPATH only affects @rpath names, and every @-relative install name is already refused.
var refusedCommands = map[macho.LoadCmd]bool{0x27: true}

func (s scope) read(path string, want macho.Type) (string, []load, error) {
	if actual, err := filepath.EvalSymlinks(path); err != nil || actual != path {
		return "", nil, errors.New("QEMU_RUNTIME_FILE_CHANGED")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", nil, errors.New("QEMU_RUNTIME_FILE_CHANGED")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0022 != 0 || before.Size <= 0 || before.Size > fileLimit {
		return "", nil, errors.New("QEMU_RUNTIME_FILE_CHANGED")
	}
	digest, loads, err := readMachO(file, before.Size, want)
	if err != nil {
		return "", nil, err
	}
	if unix.Fstat(fd, &after) != nil || after.Size != before.Size || after.Mtim != before.Mtim || after.Ctim != before.Ctim {
		return "", nil, errors.New("QEMU_RUNTIME_FILE_CHANGED")
	}
	return digest, loads, nil
}

// machoCommandsLimit bounds the load-command bytes held in memory; the fixed QEMU closure is far below it.
const machoCommandsLimit = 1 << 20

// readMachO hashes every byte in one pass and parses that pass's header and load commands, so edges match the digest.
// Unused symbol tables and relocations are not parsed; frozen digests still pin their bytes.
func readMachO(r io.Reader, size int64, want macho.Type) (string, []load, error) {
	unsupported := errors.New("QEMU_RUNTIME_MACHO_UNSUPPORTED")
	if size < 32 {
		return "", nil, unsupported
	}
	h := sha256.New()
	head := make([]byte, 32)
	if _, err := io.ReadFull(r, head); err != nil {
		return "", nil, errors.New("QEMU_RUNTIME_FILE_CHANGED")
	}
	h.Write(head)
	le := binary.LittleEndian
	ncmds, sizeofcmds := le.Uint32(head[16:20]), le.Uint32(head[20:24])
	if le.Uint32(head[0:4]) != macho.Magic64 || macho.Cpu(le.Uint32(head[4:8])) != macho.CpuArm64 || macho.Type(le.Uint32(head[12:16])) != want ||
		sizeofcmds > machoCommandsLimit || int64(sizeofcmds) > size-32 {
		return "", nil, unsupported
	}
	cmds := make([]byte, sizeofcmds)
	if _, err := io.ReadFull(r, cmds); err != nil {
		return "", nil, errors.New("QEMU_RUNTIME_FILE_CHANGED")
	}
	h.Write(cmds)
	if _, err := io.CopyN(h, r, size-32-int64(sizeofcmds)); err != nil {
		return "", nil, errors.New("QEMU_RUNTIME_FILE_CHANGED")
	}
	loads := []load{}
	for i := uint32(0); i < ncmds; i++ {
		if len(cmds) < 8 || le.Uint32(cmds[4:8]) < 8 || le.Uint32(cmds[4:8]) > uint32(len(cmds)) {
			return "", nil, unsupported
		}
		cmd, raw := macho.LoadCmd(le.Uint32(cmds[0:4])), cmds[:le.Uint32(cmds[4:8])]
		cmds = cmds[len(raw):]
		// The cheap structure checks debug/macho.NewFile applied to these commands are kept.
		switch {
		case refusedCommands[cmd],
			cmd == macho.LoadCmdRpath && (len(raw) < 12 || le.Uint32(raw[8:12]) >= uint32(len(raw))),
			cmd == macho.LoadCmdSymtab && len(raw) < 24,
			cmd == macho.LoadCmdDysymtab && len(raw) < 80,
			cmd == macho.LoadCmdSegment && (len(raw) < 56 || uint64(len(raw)) < 56+68*uint64(le.Uint32(raw[48:52]))),
			cmd == macho.LoadCmdSegment64 && (len(raw) < 72 || uint64(len(raw)) < 72+80*uint64(le.Uint32(raw[64:68]))):
			return "", nil, unsupported
		}
		name, ok := dylibCommands[cmd]
		if !ok {
			continue
		}
		if len(raw) < 24 {
			return "", nil, unsupported
		}
		offset := le.Uint32(raw[8:12])
		if offset < 24 || int(offset) >= len(raw) {
			return "", nil, unsupported
		}
		installName, _, _ := strings.Cut(string(raw[offset:]), "\x00")
		if installName == "" || strings.HasPrefix(installName, "@") || !filepath.IsAbs(installName) {
			return "", nil, errors.New("QEMU_RUNTIME_UNRESOLVABLE")
		}
		loads = append(loads, load{name, installName})
	}
	return hex.EncodeToString(h.Sum(nil)), loads, nil
}
