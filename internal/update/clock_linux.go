package update

import (
	"golang.org/x/sys/unix"
	"os"
	"strings"
	"time"
)

func ReadClock() (Clock, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	var ts unix.Timespec
	if err != nil || unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) != nil || ts.Sec < 0 || ts.Nsec < 0 {
		return Clock{}, ClockUncertain
	}
	c := Clock{Boot: strings.TrimSpace(string(boot)), UTC: time.Now().Unix(), ContinuousNS: uint64(ts.Sec)*1e9 + uint64(ts.Nsec)}
	if !c.Valid() {
		return Clock{}, ClockUncertain
	}
	return c, nil
}
