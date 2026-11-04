package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
)

const updateProfileMarker = "filegate-official-update-v1\n"

func updateImage() bool {
	path := "/etc/filegate-update-profile"
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0444 || info.Size() != int64(len(updateProfileMarker)) {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 {
		return false
	}
	body, err := os.ReadFile(path)
	return err == nil && string(body) == updateProfileMarker
}

func updateNetworkDevices(networks []string) bool {
	return updateImage() && len(networks) == 2 && networks[0] == "/sys/class/net/eth0" && networks[1] == "/sys/class/net/lo"
}

func validUpdateStart(start startRequest) bool {
	empty := sha256.Sum256(nil)
	return updateImage() && start.Policy == "filegate-official-update-v1" && start.Size == 0 && len(start.Metadata) == 0 &&
		start.SHA256 == hex.EncodeToString(empty[:]) && start.JobID == "update_"+start.AttemptID && regexp.MustCompile(`^update_[0-9a-f]{32}$`).MatchString(start.AttemptID)
}

func runProductUpdate(send func(any), reader *bufio.Reader) {
	fail := func(reason string) { send(map[string]any{"event": "update_error", "reason": reason}) }
	if !updateImage() {
		fail("UPDATE_CONTROL_INVALID")
		return
	}
	packages, _ := filepath.Glob("/.packages/*.apk")
	if len(packages) == 0 {
		fail("PACKAGES_MISSING")
		return
	}
	install := exec.Command("/sbin/apk", append([]string{"add", "--no-network"}, packages...)...)
	install.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "TMPDIR=/job/adapter-tmp"}
	if install.Run() != nil || os.MkdirAll("/job/av-parent", 0755) != nil || os.Chown("/job/av-parent", 65534, 65534) != nil {
		fail("WORKSPACE_IO_ERROR")
		return
	}
	if os.WriteFile("/etc/hosts", []byte("127.0.0.1 localhost\n10.0.2.100 database.clamav.net\n"), 0644) != nil ||
		exec.Command("/bin/busybox", "ifconfig", "eth0", "10.0.2.15", "netmask", "255.255.255.0", "up").Run() != nil {
		fail("WORKSPACE_CONFIGURATION_ERROR")
		return
	}
	_, err := controlledAVWorker("--freshclam-official-worker", send, reader)
	if err != nil {
		fail("DEFINITION_UPDATE")
	}
}
