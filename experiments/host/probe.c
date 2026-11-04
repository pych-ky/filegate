#include <dispatch/dispatch.h>
#include <errno.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>

static atomic_ulong pressure_events;
static dispatch_source_t pressure_source;

static void pressure_event(void *context) {
    (void)context;
    atomic_fetch_or(&pressure_events, dispatch_source_get_data(pressure_source));
}

static int sample(pid_t pid, struct rusage_info_v4 *usage) {
    memset(usage, 0, sizeof(*usage));
    return proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)usage);
}

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "probe") != 0) {
        fprintf(stderr, "usage: host-probe probe\n");
        return 2;
    }
    int ready[2];
    if (pipe(ready) != 0) return 2;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        close(ready[0]);
        size_t size = 16 * 1024 * 1024;
        void *memory = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (memory == MAP_FAILED) _exit(2);
        memset(memory, 0x46, size);
        if (write(ready[1], "R", 1) != 1) _exit(2);
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 2;
    }
    close(ready[0]);
    struct rusage_info_v4 self_usage, child_usage, second_usage;
    errno = 0;
    int self_result = sample(getpid(), &self_usage);
    int self_errno = errno;
    errno = 0;
    int child_result = sample(child, &child_usage);
    int child_errno = errno;
    errno = 0;
    int second_result = sample(child, &second_usage);
    int second_errno = errno;
    struct statvfs disk;
    errno = 0;
    int disk_result = statvfs(".", &disk);
    int disk_errno = errno;
    mach_timebase_info_data_t timebase;
    kern_return_t clock_result = mach_timebase_info(&timebase);
    uint64_t first_time = mach_continuous_time();
    usleep(20000);
    uint64_t second_time = mach_continuous_time();
    dispatch_queue_t queue = dispatch_queue_create("filegate.stage0.pressure", DISPATCH_QUEUE_SERIAL);
    pressure_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MEMORYPRESSURE, 0,
        DISPATCH_MEMORYPRESSURE_NORMAL | DISPATCH_MEMORYPRESSURE_WARN | DISPATCH_MEMORYPRESSURE_CRITICAL, queue);
    if (pressure_source != NULL) {
        dispatch_source_set_event_handler_f(pressure_source, pressure_event);
        dispatch_resume(pressure_source);
    }
    usleep(20000);
    int pressure_subscribed = pressure_source != NULL;
    if (pressure_source != NULL) dispatch_source_cancel(pressure_source);
    kill(child, SIGTERM);
    int child_status;
    int reaped = waitpid(child, &child_status, 0) == child;
    int identity_valid = child_result == 0 && second_result == 0 &&
        child_usage.ri_proc_start_abstime != 0 &&
        child_usage.ri_proc_start_abstime == second_usage.ri_proc_start_abstime;
    int available = self_result == 0 && child_result == 0 && identity_valid &&
        disk_result == 0 && clock_result == KERN_SUCCESS && second_time > first_time &&
        pressure_subscribed && reaped;
    printf("{\"schema_version\":1,\"mode\":\"native_availability_probe\",\"api_flavor\":\"RUSAGE_INFO_V4\","
        "\"self_rusage_result\":%d,\"self_errno\":%d,\"child_rusage_result\":%d,\"child_errno\":%d,"
        "\"repeat_result\":%d,\"repeat_errno\":%d,\"child_pid\":%d,\"child_start_abstime\":%llu,"
        "\"identity_stable\":%s,\"child_footprint_bytes\":%llu,\"child_resident_bytes\":%llu,"
        "\"statvfs_result\":%d,\"statvfs_errno\":%d,\"disk_available_bytes\":%llu,"
        "\"clock_result\":%d,\"continuous_clock_advanced\":%s,\"timebase_numer\":%u,\"timebase_denom\":%u,"
        "\"pressure_source_created_and_resumed\":%s,\"pressure_events_observed\":%lu,"
        "\"child_term_reaped\":%s,\"monitoring_available\":%s,"
        "\"qemu_started\":false,\"real_memory_pressure_not_induced\":true}\n",
        self_result,self_errno,child_result,child_errno,second_result,second_errno,child,
        (unsigned long long)child_usage.ri_proc_start_abstime,identity_valid?"true":"false",
        (unsigned long long)child_usage.ri_phys_footprint,(unsigned long long)child_usage.ri_resident_size,
        disk_result,disk_errno,disk_result==0?(unsigned long long)disk.f_bavail*disk.f_frsize:0,
        clock_result,second_time>first_time?"true":"false",timebase.numer,timebase.denom,
        pressure_subscribed?"true":"false",atomic_load(&pressure_events),reaped?"true":"false",available?"true":"false");
    return available ? 0 : 1;
}
