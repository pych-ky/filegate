package updatebridge

import (
	"strings"
)

func workspace(value any) (object, error) {
	m, ok := value.(object)
	if !ok || m["event"] != "workspace" || !integer(m["free_bytes"], 0, 1<<32) || !integer(m["free_inodes"], 0, 1<<20) || m["reason"] != nil && !oneOf(m["reason"], "", "WORKSPACE_LIMIT", "WORKSPACE_IO_ERROR", "RESOURCE_MONITOR_FAILED", "WORKSPACE_CONFIGURATION_ERROR") {
		return nil, errInvalid
	}
	reason := m["reason"]
	if reason == "" {
		reason = nil
	}
	return object{"event": "workspace", "free_bytes": m["free_bytes"], "free_inodes": m["free_inodes"], "reason": reason}, nil
}

func mounts(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	expected := map[string]string{"/": "overlay", "/.base": "ext4", "/.definitions": "ext4", "/.work": "ext4", "/job": "ext4", "/dev": "devtmpfs", "/proc": "proc", "/sys": "sysfs", "/dev/shm": "tmpfs"}
	found := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			return false
		}
		front, back := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(front) < 6 || len(back) < 3 {
			return false
		}
		path := front[4]
		if expected[path] != back[0] || found[path] {
			return false
		}
		if (path == "/.base" || path == "/.definitions") && !contains(strings.Split(front[5], ","), "ro") {
			return false
		}
		if (path == "/.work" || path == "/job") && back[1] != "/dev/vdc" {
			return false
		}
		if path == "/dev/shm" && (!contains(strings.Split(back[2], ","), "size=65536k") || !contains(strings.Split(back[2], ","), "nr_inodes=4096")) {
			return false
		}
		found[path] = true
	}
	return len(found) == len(expected)
}

func contains(values []string, item string) bool {
	for _, v := range values {
		if v == item {
			return true
		}
	}
	return false
}

func preflight(ready object) bool {
	blocks, ok := ready["blocks"].(object)
	if !ok {
		return false
	}
	vda, ok := blocks["vda"].(object)
	if !ok {
		return false
	}
	vdb, ok := blocks["vdb"].(object)
	if !ok {
		return false
	}
	return ready["event"] == "ready" && vda["read_only"] == "1" && vdb["read_only"] == "1" && same(blocks["vdc"], object{"sectors": "8388608", "read_only": "0"}) && same(ready["net_devices"], []string{"/sys/class/net/eth0", "/sys/class/net/lo"}) && ready["loopback_up"] == true && mounts(ready["mountinfo"])
}
