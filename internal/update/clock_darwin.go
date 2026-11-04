package update

/*
#include <mach/mach_time.h>
#include <stdint.h>
static int filegate_continuous_ns(uint64_t *out) {
    mach_timebase_info_data_t tb;
    if (mach_timebase_info(&tb) != KERN_SUCCESS || !tb.numer || !tb.denom) return -1;
    __uint128_t value = (__uint128_t)mach_continuous_time() * tb.numer / tb.denom;
    if (value > UINT64_MAX) return -1;
    *out = (uint64_t)value;
    return 0;
}
*/
import "C"

import (
	"golang.org/x/sys/unix"
	"strings"
	"time"
)

func ReadClock() (Clock, error) {
	boot, err := unix.Sysctl("kern.bootsessionuuid")
	var ticks C.uint64_t
	if err != nil || C.filegate_continuous_ns(&ticks) != 0 {
		return Clock{}, ClockUncertain
	}
	c := Clock{Boot: strings.ToLower(boot), UTC: time.Now().Unix(), ContinuousNS: uint64(ticks)}
	if !c.Valid() {
		return Clock{}, ClockUncertain
	}
	return c, nil
}
