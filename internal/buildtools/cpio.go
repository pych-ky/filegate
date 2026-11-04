package buildtools

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func cpioEntry(writer io.Writer, name string, mode uint32, source io.Reader, size int64, inode int) error {
	encoded := append([]byte(name), 0)
	fields := []uint64{uint64(inode), uint64(mode), 0, 0, 1, 0, uint64(size), 0, 0, 0, 0, uint64(len(encoded)), 0}
	if _, err := io.WriteString(writer, "070701"); err != nil {
		return err
	}
	for _, field := range fields {
		if _, err := fmt.Fprintf(writer, "%08x", field); err != nil {
			return err
		}
	}
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	if _, err := writer.Write(make([]byte, (4-(110+len(encoded))%4)%4)); err != nil {
		return err
	}
	if source != nil {
		if _, err := io.CopyN(writer, source, size); err != nil {
			return err
		}
	}
	_, err := writer.Write(make([]byte, (4-size%4)%4))
	return err
}

func RootCPIO(root, output string) error {
	names := []string{root}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root {
			names = append(names, path)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(names)
	file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	archive := gzip.NewWriter(file)
	defer archive.Close()
	archive.Header.ModTime = archive.Header.ModTime.UTC()
	for i, path := range names {
		info, err := os.Lstat(path)
		if err != nil {
			archive.Close()
			file.Close()
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			archive.Close()
			file.Close()
			return err
		}
		name = filepath.ToSlash(name)
		mode := permissionBits(info.Mode())
		size := int64(0)
		var source io.Reader
		var opened *os.File
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			mode |= 0120000
			target, e := os.Readlink(path)
			if e != nil {
				return e
			}
			source = strings.NewReader(target)
			size = int64(len(target))
		case info.IsDir():
			mode |= 0040000
		case info.Mode().IsRegular():
			mode |= 0100000
			opened, err = os.Open(path)
			if err != nil {
				return err
			}
			source = opened
			size = info.Size()
		default:
			archive.Close()
			file.Close()
			return fmt.Errorf("unsupported initramfs inode: %s", name)
		}
		err = cpioEntry(archive, name, mode, source, size, i+1)
		if opened != nil {
			opened.Close()
		}
		if err != nil {
			archive.Close()
			file.Close()
			return err
		}
	}
	if err = cpioEntry(archive, "TRAILER!!!", 0, nil, 0, len(names)+1); err == nil {
		err = archive.Close()
	} else {
		archive.Close()
	}
	if err == nil {
		err = file.Sync()
	}
	closed := file.Close()
	if err != nil {
		return err
	}
	return closed
}

func InspectCPIO(path string) (map[string]any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	archive, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	reader := bufio.NewReader(archive)
	count := 0
	found := map[string]bool{}
	for {
		header := make([]byte, 110)
		if _, err = io.ReadFull(reader, header); err != nil || string(header[:6]) != "070701" {
			return nil, errors.New("invalid newc header")
		}
		fields := make([]uint64, 13)
		for i := range fields {
			fields[i], err = strconv.ParseUint(string(header[6+i*8:14+i*8]), 16, 64)
			if err != nil {
				return nil, err
			}
		}
		mode, uid, gid, links, size, nameSize := fields[1], fields[2], fields[3], fields[4], fields[6], fields[11]
		if nameSize < 1 || nameSize > 4096 || size > 128<<20 {
			return nil, errors.New("trusted archive bounds mismatch")
		}
		name := make([]byte, int(nameSize))
		if _, err = io.ReadFull(reader, name); err != nil || name[len(name)-1] != 0 {
			return nil, errors.New("invalid newc name")
		}
		if _, err = io.CopyN(io.Discard, reader, int64((4-(110+nameSize)%4)%4)); err != nil {
			return nil, err
		}
		value := string(name[:len(name)-1])
		if value == "TRAILER!!!" {
			if size != 0 {
				return nil, errors.New("nonempty archive trailer")
			}
			if _, err = reader.ReadByte(); err != io.EOF {
				return nil, errors.New("unexpected archive trailer data")
			}
			break
		}
		if pythonPath(value) {
			return nil, errors.New("Python runtime artifact in initramfs")
		}
		kind := mode & 0170000
		if uid != 0 || gid != 0 || links != 1 || (kind != 0100000 && kind != 0040000 && kind != 0120000) {
			return nil, errors.New("archive owner or inode type mismatch")
		}
		if _, err = io.CopyN(io.Discard, reader, int64(size)); err != nil {
			return nil, err
		}
		if _, err = io.CopyN(io.Discard, reader, int64((4-size%4)%4)); err != nil {
			return nil, err
		}
		count++
		if count > 10000 {
			return nil, errors.New("archive entry count exceeded")
		}
		found[value] = true
	}
	for _, name := range []string{"init", "usr/sbin/mke2fs", "usr/lib/modules/6.18.58-0-virt/kernel/fs/ext4/ext4.ko", "usr/lib/modules/6.18.58-0-virt/kernel/fs/overlayfs/overlay.ko"} {
		if !found[name] {
			return nil, fmt.Errorf("required boot entry missing: %s", name)
		}
	}
	return map[string]any{"entries": count, "all_uid_gid_zero": true, "all_links_one": true, "required_boot_files_present": true, "gzip_CRC_read_to_end": true, "python_runtime_absent": true}, nil
}
