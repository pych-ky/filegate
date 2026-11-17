package buildtools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// guestReplaceable is the fixed set of image paths build-guest may replace; every other inode must stay identical.
var guestReplaceable = map[string]string{"/filegate-fixtures": "filegate-fixtures"}

// imageDigest omits numeric inode IDs, which differ between rebuilt images; Aliases names the paths sharing the inode instead.
type imageDigest struct {
	Path    string `json:"path"`
	Mode    uint32 `json:"mode"`
	UID     string `json:"uid"`
	GID     string `json:"gid"`
	Size    string `json:"size"`
	Links   string `json:"links"`
	Aliases string `json:"aliases"`
	Content string `json:"content"`
}

// inodeLinks reads every inode's link count with one debugfs stat batch and fails unless each block names the requested inode with the inventory's mode and owner.
func inodeLinks(ctx context.Context, debugfs, image, staging string, records []imageRecord) (map[string]string, error) {
	byInode := map[string]imageRecord{}
	inodes := []string{}
	for _, record := range records {
		if _, ok := byInode[record.Inode]; !ok {
			inodes = append(inodes, record.Inode)
		}
		byInode[record.Inode] = record
	}
	commands := make([]string, len(inodes))
	for i, inode := range inodes {
		commands[i] = "stat <" + inode + ">"
	}
	batch := filepath.Join(staging, "stat-"+filepath.Base(image)+".txt")
	if err := os.WriteFile(batch, []byte(strings.Join(commands, "\n")+"\n"), 0600); err != nil {
		return nil, err
	}
	out, _, err := command(ctx, "", nil, debugfs, "-f", batch, image)
	if err != nil {
		return nil, err
	}
	return parseStatLinks(string(out), inodes, byInode)
}

func parseStatLinks(out string, inodes []string, byInode map[string]imageRecord) (map[string]string, error) {
	blocks := strings.Split(out, "debugfs: stat <")
	if len(blocks) != len(inodes)+1 {
		return nil, errors.New("image stat output incomplete")
	}
	links := map[string]string{}
	for i, block := range blocks[1:] {
		inode := inodes[i]
		record := byInode[inode]
		number, mode, uid, gid, count := "", "", "", "", ""
		for _, line := range strings.Split(block, "\n") {
			fields := strings.Fields(line)
			switch {
			case len(fields) >= 6 && fields[0] == "Inode:" && fields[2] == "Type:" && fields[4] == "Mode:":
				number, mode = fields[1], fields[5]
			case len(fields) >= 4 && fields[0] == "User:" && fields[2] == "Group:":
				uid, gid = fields[1], fields[3]
			case len(fields) >= 2 && fields[0] == "Links:":
				count = fields[1]
			}
		}
		permissions, err := strconv.ParseUint(mode, 8, 32)
		if _, e := strconv.ParseUint(count, 10, 32); e != nil || err != nil || !strings.HasPrefix(block, inode+">") || number != inode || uid != record.UID || gid != record.GID || uint32(permissions) != record.Mode&07777 {
			return nil, fmt.Errorf("image stat record invalid: %s", inode)
		}
		links[inode] = count
	}
	return links, nil
}

// restoreDirectories gives owner access back to every directory of a tree this process extracted, top-down, without
// following symbolic links or changing files, so hardlinked or linked targets keep their modes.
func restoreDirectories(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return err
		}
		return unix.Fchmodat(unix.AT_FDCWD, path, 0700, unix.AT_SYMLINK_NOFOLLOW)
	})
}

// imageDigests records path, type, mode, owner, size, link count, hardlink aliases and content (file SHA-256 or symlink target) of every entry and of the root.
func imageDigests(ctx context.Context, debugfs, image, staging, root string) (digests []imageDigest, err error) {
	records, err := imageRecords(ctx, debugfs, image)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 || records[0].Path != "/" {
		return nil, errors.New("image root record missing")
	}
	links, err := inodeLinks(ctx, debugfs, image, staging, records)
	if err != nil {
		return nil, err
	}
	aliases := map[string][]string{}
	for _, record := range records {
		aliases[record.Inode] = append(aliases[record.Inode], record.Path)
	}
	if err = os.Mkdir(root, 0700); err != nil {
		return nil, err
	}
	// rdump keeps the image's read-only directory modes; the new tree must stay removable however this returns.
	defer func() {
		if restoreErr := restoreDirectories(root); restoreErr != nil {
			digests, err = nil, errors.Join(err, restoreErr)
		}
	}()
	quoted, err := quoteDebugfs(root)
	if err != nil {
		return nil, err
	}
	_, diagnostic, err := command(ctx, "", nil, debugfs, "-R", "rdump / "+quoted, image)
	if err != nil {
		return nil, err
	}
	// Unprivileged rdump cannot chown; any other diagnostic means the extracted tree is incomplete.
	for _, line := range strings.Split(strings.TrimSpace(string(diagnostic)), "\n") {
		if line != "" && !strings.HasPrefix(line, "debugfs ") && !strings.Contains(line, "while changing ownership") {
			return nil, fmt.Errorf("image extraction diagnostic: %s", line)
		}
	}
	digests = make([]imageDigest, len(records))
	for i, record := range records {
		local := filepath.Join(root, filepath.FromSlash(record.Path))
		names := aliases[record.Inode]
		sort.Strings(names)
		digest := imageDigest{Path: record.Path, Mode: record.Mode, UID: record.UID, GID: record.GID, Size: record.Size, Links: links[record.Inode], Aliases: strings.Join(names, "\n")}
		switch record.Mode & 0170000 {
		case 0040000:
		case 0100000:
			body, err := os.ReadFile(local)
			if err != nil || fmt.Sprint(len(body)) != record.Size {
				return nil, fmt.Errorf("extracted file differs from its inode: %s", record.Path)
			}
			digest.Content = digestHex(body)
		case 0120000:
			if digest.Content, err = os.Readlink(local); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported image inode type: %s", record.Path)
		}
		digests[i] = digest
	}
	return digests, nil
}

// compareImages requires the root and every entry outside replaced to be identical, including link counts and hardlink aliases; replaced paths must keep type, mode and owner and alias nothing.
func compareImages(ctx context.Context, debugfs, parent, derived, staging string, replaced map[string]bool) (map[string]any, error) {
	before, err := imageDigests(ctx, debugfs, parent, staging, filepath.Join(staging, "parent-root"))
	if err != nil {
		return nil, err
	}
	after, err := imageDigests(ctx, debugfs, derived, staging, filepath.Join(staging, "derived-root"))
	if err != nil {
		return nil, err
	}
	if len(before) != len(after) {
		return nil, errors.New("derived image inode set differs")
	}
	changes := map[string]any{}
	kinds := map[string]int{}
	for i := range before {
		a, b := before[i], after[i]
		if a.Path != b.Path {
			return nil, fmt.Errorf("derived image inode set differs at %s", a.Path)
		}
		if replaced[a.Path] {
			if a.Mode != b.Mode || a.UID != b.UID || a.GID != b.GID {
				return nil, fmt.Errorf("replaced file metadata changed: %s", a.Path)
			}
			if a.Links != "1" || b.Links != "1" || a.Aliases != a.Path || b.Aliases != b.Path {
				return nil, fmt.Errorf("replaced path has hardlink aliases: %s", a.Path)
			}
			changes[a.Path] = map[string]any{"baseline_sha256": a.Content, "sha256": b.Content, "baseline_size": a.Size, "size": b.Size}
		} else if a != b {
			return nil, fmt.Errorf("non-replaced image inode changed: %s", a.Path)
		}
		kinds[fmt.Sprintf("%o", a.Mode&0170000)]++
	}
	for path := range replaced {
		if _, ok := changes[path]; !ok {
			return nil, fmt.Errorf("replaced path missing from image: %s", path)
		}
	}
	encodedBefore, _ := json.Marshal(before)
	encodedAfter, _ := json.Marshal(after)
	return map[string]any{"entries_including_root": len(before), "entries_by_type": kinds, "non_replaced_identical": len(before) - len(changes), "replaced": changes,
		"compared_fields":      []string{"path", "type", "mode", "uid", "gid", "size", "link_count", "hardlink_alias_paths", "content_sha256_or_link_target"},
		"parent_digest_sha256": digestHex(encodedBefore), "derived_digest_sha256": digestHex(encodedAfter)}, nil
}

func digestHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
