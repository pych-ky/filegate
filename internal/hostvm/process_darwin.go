//go:build darwin

package hostvm

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <errno.h>
#include <stdint.h>
static int filegate_usage(int pid, uint64_t *values) {
 struct rusage_info_v4 r;
 errno=0;
 if(proc_pid_rusage(pid,RUSAGE_INFO_V4,(rusage_info_t *)&r)!=0) return errno ? errno : EIO;
 values[0]=r.ri_proc_start_abstime; values[1]=r.ri_proc_exit_abstime;
 values[2]=r.ri_resident_size; values[3]=r.ri_phys_footprint;
 return 0;
}
static int filegate_group(int pid, uint32_t *group, uint32_t *uid) {
 struct proc_bsdshortinfo info;
 errno=0;
 if(proc_pidinfo(pid,PROC_PIDT_SHORTBSDINFO,0,&info,sizeof(info))!=sizeof(info)) return errno ? errno : EIO;
 if(info.pbsi_pid!=(uint32_t)pid) return EIO;
 *group=info.pbsi_pgid; *uid=info.pbsi_uid; return 0;
}
static int filegate_group_count(int group,int *count) {
 int pids[64];errno=0;int n=proc_listpgrppids(group,pids,sizeof(pids));
 if(n<0 || errno) return errno ? errno : EIO;
 *count=n;return 0;
}
*/
import "C"
import (
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func BootUUID() (string, error) {
	v, e := unix.Sysctl("kern.bootsessionuuid")
	v = strings.TrimSpace(strings.ToLower(v))
	if e != nil || !bootPattern.MatchString(v) {
		return "", Error("CONTROL_BOOT_UNAVAILABLE")
	}
	return v, nil
}
func NativeIdentity(pid int) (Object, error) {
	var b, a [4]C.uint64_t
	e := C.filegate_usage(C.int(pid), &b[0])
	if e == C.ESRCH {
		return nil, nil
	}
	if e != 0 {
		return nil, syscall.Errno(e)
	}
	var group, uid C.uint32_t
	e = C.filegate_group(C.int(pid), &group, &uid)
	if e == C.ESRCH {
		return nil, nil
	}
	if e != 0 {
		return nil, syscall.Errno(e)
	}
	e = C.filegate_usage(C.int(pid), &a[0])
	if e == C.ESRCH {
		return nil, nil
	}
	if e != 0 {
		return nil, syscall.Errno(e)
	}
	if a[0] == 0 || a[0] != b[0] {
		return nil, Error("CONTROL_IDENTITY_CHANGED")
	}
	return Object{"pid": pid, "start_abstime": uint64(a[0]), "exit_abstime": uint64(a[1]), "resident_bytes": uint64(a[2]), "footprint_bytes": uint64(a[3]), "process_group": uint64(group), "uid": uint64(uid)}, nil
}
func GroupEmpty(group int) (bool, error) {
	if group <= 1 {
		return false, Error("CONTROL_GROUP_INVALID")
	}
	var count C.int
	e := C.filegate_group_count(C.int(group), &count)
	if e != 0 {
		return false, syscall.Errno(e)
	}
	return count == 0, nil
}
func signalOwned(identity Object, signal syscall.Signal) error {
	back := IdentityReadback(identity)
	if back["same_identity_live"] != true {
		return Error("CONTROL_IDENTITY_NOT_LIVE")
	}
	actual := Map(back, "actual")
	if Int(actual, "uid") != int64(os.Getuid()) {
		return Error("CONTROL_OWNER_CHANGED")
	}
	return syscall.Kill(int(Int(identity, "pid")), signal)
}
