package updatebridge

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

func networkLock(request, expected string) (*os.File, string, object, error) {
	value, body, err := readControl(request, 16384)
	r, ok := value.(object)
	if err != nil || !ok || !validDigest(expected) || digest(body) != expected || r["profile"] != updateProfile || r["fixture_only"] != false {
		return nil, "", nil, errInvalid
	}
	out := filepath.Join(filepath.Dir(request), "output")
	intent, _, err := readControl(filepath.Join(out, "network-intent.json"), 4096)
	if err != nil {
		return nil, "", nil, err
	}
	fd, err := unix.Open(filepath.Join(out, "network.lock"), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", nil, err
	}
	f := os.NewFile(uintptr(fd), "network.lock")
	s, err := fileStat(f)
	if err != nil || s.Mode&unix.S_IFMT != unix.S_IFREG || s.Uid != uint32(os.Getuid()) || uint32(s.Mode)&07777 != 0600 || s.Size != 0 || !same(intent, object{"schema": 1, "update_id": r["attempt_id"], "request_sha256": expected, "device": s.Dev, "inode": s.Ino}) {
		f.Close()
		return nil, "", nil, errInvalid
	}
	return f, out, r, nil
}

func publicIPv4(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip.To4())
	if !ok || !a.IsGlobalUnicast() {
		return false
	}
	for _, block := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		if netip.MustParsePrefix(block).Contains(a) {
			return false
		}
	}
	return true
}

// Forward holds the shared lock until its fixed-origin connection has closed.
func Forward(request, expected string) error {
	lock, out, _, err := networkLock(request, expected)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		return err
	}
	closed := func() bool { return !absent(filepath.Join(out, "network-closed.json")) }
	if closed() {
		return errInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip4", "database.clamav.net")
	if err != nil {
		return err
	}
	unique := map[string]bool{}
	for _, ip := range addresses {
		if publicIPv4(ip) {
			unique[ip.String()] = true
		}
	}
	ordered := []string{}
	for ip := range unique {
		ordered = append(ordered, ip)
	}
	sort.Strings(ordered)
	if len(ordered) == 0 || closed() {
		return errInvalid
	}
	connection, err := net.DialTimeout("tcp4", net.JoinHostPort(ordered[0], "443"), 10*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	file, err := connection.(*net.TCPConn).File()
	if err != nil {
		return err
	}
	defer file.Close()
	fd := int(file.Fd())
	for _, descriptor := range []int{0, 1, fd} {
		if err = unix.SetNonblock(descriptor, true); err != nil {
			return err
		}
	}
	return relayNetwork(fd, closed)
}

func relayNetwork(fd int, closed func() bool) error {
	toRemote, toGuest := []byte{}, []byte{}
	guestOpen, remoteOpen, shut := true, true, false
	until := time.Now().Add(600 * time.Second)
	read := func(descriptor int, buffer *[]byte, open *bool) error {
		chunk := make([]byte, 65536-len(*buffer))
		n, err := unix.Read(descriptor, chunk)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return nil
		}
		if err != nil {
			return err
		}
		if n == 0 {
			*open = false
		} else {
			*buffer = append(*buffer, chunk[:n]...)
		}
		return nil
	}
	write := func(descriptor int, buffer *[]byte) error {
		n, err := unix.Write(descriptor, *buffer)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return nil
		}
		if err != nil {
			return err
		}
		*buffer = (*buffer)[n:]
		return nil
	}
	for time.Now().Before(until) {
		if closed() {
			return nil
		}
		if !remoteOpen && len(toGuest) == 0 {
			return nil
		}
		poll := []unix.PollFd{{Fd: 0}, {Fd: 1}, {Fd: int32(fd)}}
		if guestOpen && len(toRemote) < 65536 {
			poll[0].Events = unix.POLLIN
		}
		if len(toGuest) > 0 {
			poll[1].Events = unix.POLLOUT
		}
		if remoteOpen && len(toGuest) < 65536 {
			poll[2].Events |= unix.POLLIN
		}
		if len(toRemote) > 0 {
			poll[2].Events |= unix.POLLOUT
		}
		for i := range poll {
			if poll[i].Events == 0 {
				poll[i].Fd = -1
			}
		}
		if _, err := unix.Poll(poll, 200); err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		for _, p := range poll {
			if p.Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
				return errInvalid
			}
		}
		if poll[1].Revents&unix.POLLHUP != 0 {
			return errInvalid
		}
		if guestOpen && len(toRemote) < 65536 && poll[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
			if err := read(0, &toRemote, &guestOpen); err != nil {
				return err
			}
		}
		if remoteOpen && len(toGuest) < 65536 && poll[2].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
			if err := read(fd, &toGuest, &remoteOpen); err != nil {
				return err
			}
		}
		if len(toRemote) > 0 && poll[2].Revents&unix.POLLOUT != 0 {
			if err := write(fd, &toRemote); err != nil {
				return err
			}
		}
		if len(toGuest) > 0 && poll[1].Revents&unix.POLLOUT != 0 {
			if err := write(1, &toGuest); err != nil {
				return err
			}
		}
		if !guestOpen && len(toRemote) == 0 && !shut {
			if err := unix.Shutdown(fd, unix.SHUT_WR); err != nil {
				return err
			}
			shut = true
		}
	}
	return errInvalid
}
