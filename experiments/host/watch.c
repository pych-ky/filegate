#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
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

#define MAX_PROCESSES 64
#define MEMORY_LIMIT (6ULL * 1024 * 1024 * 1024)

struct identity { pid_t pid; uint64_t start; int exited; };
static struct identity processes[MAX_PROCESSES];
static size_t process_count;
static mach_timebase_info_data_t timebase;
static atomic_ulong pressure_state;
static dispatch_source_t pressure_source;

static uint64_t now_ns(void) {
    return (uint64_t)((__uint128_t)mach_continuous_time() * timebase.numer / timebase.denom);
}

static void pressure_event(void *context) {
    (void)context;
    atomic_store(&pressure_state, dispatch_source_get_data(pressure_source));
}

static int usage(pid_t pid, struct rusage_info_v4 *result) {
    memset(result, 0, sizeof(*result));
    return proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)result);
}

static int add_process(pid_t pid) {
    for (size_t i = 0; i < process_count; i++) if (processes[i].pid == pid) return 0;
    if (process_count == MAX_PROCESSES) return -1;
    struct rusage_info_v4 result;
    if (usage(pid, &result) != 0 || result.ri_proc_start_abstime == 0) return -1;
    processes[process_count++] = (struct identity){pid, result.ri_proc_start_abstime, 0};
    return 0;
}

static int measure(uint64_t *footprint, uint64_t *resident, int force_failure) {
    *footprint = 0;
    *resident = 0;
    if (force_failure) { errno = EIO; return -1; }
    for (size_t i = 0; i < process_count; i++) {
        if (processes[i].exited) continue;
        struct rusage_info_v4 result;
        if (usage(processes[i].pid, &result) != 0) {
            if (errno == ESRCH) { processes[i].exited = 1; continue; }
            return -1;
        }
        if (result.ri_proc_start_abstime != processes[i].start) return -1;
        if (result.ri_proc_exit_abstime != 0) { processes[i].exited = 1; continue; }
        *footprint += result.ri_phys_footprint;
        *resident += result.ri_resident_size;
        pid_t children[MAX_PROCESSES] = {0};
        errno = 0;
        int count = proc_listchildpids(processes[i].pid, children, sizeof(children));
        if (count < 0 || errno != 0 || count >= MAX_PROCESSES) return -1;
        for (int c = 0; c < count; c++) if (children[c] > 0 && add_process(children[c]) != 0) return -1;
    }
    return 0;
}

static int signal_verified(struct identity *process, int signal_number) {
    if (process->exited) return 0;
    struct rusage_info_v4 result;
    if (usage(process->pid, &result) != 0) {
        if (errno == ESRCH) { process->exited = 1; return 0; }
        return -1;
    }
    if (result.ri_proc_start_abstime != process->start) return -1;
    if (result.ri_proc_exit_abstime != 0) { process->exited = 1; return 0; }
    return kill(process->pid, signal_number);
}

static int fixture_child(const char *mode) {
    if (strcmp(mode, "ignore-term") == 0) signal(SIGTERM, SIG_IGN);
    if (strcmp(mode, "normal") == 0) { usleep(1200000); return 0; }
    if (strcmp(mode, "descendant") == 0) {
        pid_t nested = fork();
        if (nested < 0) return 2;
    }
    size_t bytes = 16 * 1024 * 1024;
    void *memory = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (memory == MAP_FAILED) return 2;
    memset(memory, 0x46, bytes);
    for (;;) pause();
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "fixture-child") == 0) return fixture_child(argv[2]);
    if (argc < 8 || strcmp(argv[1], "run") != 0) {
        fprintf(stderr, "usage: host-watch run SECONDS DISK_PATH REQUIRED_FREE_BYTES INJECTION DEADLINE_REASON COMMAND [ARGS...]\n");
        return 2;
    }
    char *end;
    double duration = strtod(argv[2], &end);
    if (*end || duration <= 0 || duration > 600) return 2;
    uint64_t required_free = strtoull(argv[4], &end, 10);
    if (*end) return 2;
    const char *injection = argv[5];
    const char *deadline_reason = argv[6];
    if (strcmp(deadline_reason,"UPDATE_TIMEOUT") != 0 && strcmp(deadline_reason,"SCAN_TIMEOUT") != 0) return 2;
    int injected = strcmp(injection, "none") != 0;
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    struct rusage_info_v4 self;
    struct statvfs disk;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.denom == 0 ||
        usage(getpid(), &self) != 0 || statvfs(argv[3], &disk) != 0) {
        puts("{\"event\":\"START_REFUSED\",\"reason\":\"RESOURCE_MONITOR_FAILED\",\"child_started\":false}");
        return 1;
    }
    dispatch_queue_t queue = dispatch_queue_create("filegate.stage0.watch", DISPATCH_QUEUE_SERIAL);
    pressure_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MEMORYPRESSURE, 0,
        DISPATCH_MEMORYPRESSURE_NORMAL | DISPATCH_MEMORYPRESSURE_WARN | DISPATCH_MEMORYPRESSURE_CRITICAL, queue);
    if (pressure_source == NULL) {
        puts("{\"event\":\"START_REFUSED\",\"reason\":\"RESOURCE_MONITOR_FAILED\",\"child_started\":false}");
        return 1;
    }
    dispatch_source_set_event_handler_f(pressure_source, pressure_event);
    dispatch_resume(pressure_source);
    uint64_t start = now_ns(), deadline = start + (uint64_t)(duration * 1e9);
    if ((uint64_t)disk.f_bavail * disk.f_frsize < required_free) {
        puts("{\"event\":\"START_REFUSED\",\"reason\":\"DISK_PRESSURE\",\"child_started\":false}");
        return 1;
    }
    int gate[2];
    if (pipe(gate) != 0) return 2;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        close(gate[1]);
        char allow;
        if (read(gate[0], &allow, 1) != 1 || allow != 'R') _exit(2);
        close(gate[0]);
        execv(argv[7], &argv[7]);
        _exit(127);
    }
    close(gate[0]);
    if (add_process(child) != 0) {
        close(gate[1]);
        waitpid(child, NULL, 0);
        puts("{\"event\":\"START_REFUSED\",\"reason\":\"RESOURCE_MONITOR_FAILED\",\"child_started\":false}");
        return 1;
    }
    printf("{\"event\":\"MONITOR_READY\",\"child_pid\":%d,\"child_start_abstime\":%llu,\"continuous_start_ns\":%llu,\"continuous_deadline_ns\":%llu,\"injection\":%s}\n",
        child, (unsigned long long)processes[0].start, (unsigned long long)start, (unsigned long long)deadline, injected?"true":"false");
    if (write(gate[1], "R", 1) != 1) { close(gate[1]); waitpid(child, NULL, 0); return 1; }
    close(gate[1]);
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (flags >= 0) fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    uint64_t heartbeat = start, next_sample = start, warning_since = 0, stop_at = 0;
    int stdin_closed = 0, sent_kill = 0, child_status = 0, child_reaped = 0;
    const char *reason = NULL;
    int identity_refusal_tested = 0;
    for (;;) {
        uint64_t current = now_ns();
        char buffer[256];
        ssize_t received = read(STDIN_FILENO, buffer, sizeof(buffer));
        if (received == 0) stdin_closed = 1;
        if (received > 0) for (ssize_t i = 0; i < received; i++) if (buffer[i] == 'H') heartbeat = current;
        if (!child_reaped && waitpid(child, &child_status, WNOHANG) == child) {
            child_reaped = 1;
            processes[0].exited = 1;
        }
        if (current >= next_sample || stop_at) {
            next_sample = current + 1000000000ULL;
            uint64_t footprint = 0, resident = 0;
            int force = strcmp(injection,"monitor-failure")==0 && current-start>=1000000000ULL;
            int measured = measure(&footprint, &resident, force);
            if (measured != 0) measured = measure(&footprint, &resident, force);
            int disk_ok = statvfs(strcmp(injection,"disk-failure")==0 && current-start>=1000000000ULL?"/nonexistent-filegate-stage0-volume":argv[3], &disk)==0;
            uint64_t free_bytes = disk_ok?(uint64_t)disk.f_bavail*disk.f_frsize:0;
            uint64_t observed = footprint > resident ? footprint : resident;
            unsigned long pressure = atomic_load(&pressure_state);
            if (current-start>=1000000000ULL && strcmp(injection,"pressure-warning")==0) pressure=DISPATCH_MEMORYPRESSURE_WARN;
            if (current-start>=1000000000ULL && strcmp(injection,"pressure-critical")==0) pressure=DISPATCH_MEMORYPRESSURE_CRITICAL;
            if (current-start>=1000000000ULL && strcmp(injection,"memory-limit")==0) observed=MEMORY_LIMIT+1;
            if (strcmp(injection,"identity-refusal")==0 && !identity_refusal_tested) {
                struct identity wrong=processes[0]; wrong.start++;
                int refused=signal_verified(&wrong,SIGTERM)!=0;
                printf("{\"event\":\"IDENTITY_REFUSAL_FIXTURE\",\"wrong_identity_signal_refused\":%s}\n",refused?"true":"false");
                identity_refusal_tested=1;
                if (!refused) reason="IDENTITY_CHECK_FAILED";
            }
            if (!stop_at) printf("{\"event\":\"SAMPLE\",\"elapsed_ns\":%llu,\"footprint_bytes\":%llu,\"resident_bytes\":%llu,\"observed_memory_bytes\":%llu,\"processes\":%zu,\"free_bytes\":%llu,\"measurement_ok\":%s,\"disk_ok\":%s,\"pressure\":%lu}\n",
                (unsigned long long)(current-start),(unsigned long long)footprint,(unsigned long long)resident,(unsigned long long)observed,process_count,(unsigned long long)free_bytes,measured==0?"true":"false",disk_ok?"true":"false",pressure);
            if (!reason) {
                if (measured!=0 || !disk_ok) reason="RESOURCE_MONITOR_FAILED";
                else if (observed>MEMORY_LIMIT) reason="HOST_RESOURCE_PRESSURE";
                else if (free_bytes<required_free) reason="DISK_PRESSURE";
                else if (pressure&DISPATCH_MEMORYPRESSURE_CRITICAL) reason="HOST_RESOURCE_PRESSURE";
                else if (pressure&DISPATCH_MEMORYPRESSURE_WARN) {
                    if (!warning_since) warning_since=current;
                    if (current-warning_since>=3000000000ULL) reason="HOST_RESOURCE_PRESSURE";
                } else warning_since=0;
            }
            if (reason && !stop_at) {
                stop_at=current;
                sent_kill=(pressure&DISPATCH_MEMORYPRESSURE_CRITICAL)!=0;
                printf("{\"event\":\"STOP_BEGIN\",\"reason\":\"%s\",\"elapsed_ns\":%llu,\"first_signal\":%d}\n",reason,(unsigned long long)(current-start),sent_kill?SIGKILL:SIGTERM);
                for (size_t i=process_count;i>0;i--) signal_verified(&processes[i-1],sent_kill?SIGKILL:SIGTERM);
            }
        }
        if (!reason && (stdin_closed || current-heartbeat>=5000000000ULL)) reason="INTERRUPTED";
        if (!reason && current>=deadline) reason=deadline_reason;
        if (reason && !stop_at) next_sample=0;
        if (stop_at && !sent_kill && current-stop_at>=2000000000ULL) {
            for (size_t i=process_count;i>0;i--) signal_verified(&processes[i-1],SIGKILL);
            sent_kill=1;
            printf("{\"event\":\"SIGKILL_SENT\",\"stop_elapsed_ns\":%llu}\n",(unsigned long long)(current-stop_at));
        }
        int live=0;
        for (size_t i=0;i<process_count;i++) if (!processes[i].exited) live++;
        if (child_reaped && live==0) {
            printf("{\"event\":\"FINISHED\",\"reason\":\"%s\",\"child_exit_status\":%d,\"child_term_signal\":%d,\"processes\":%zu,\"all_exited\":true,\"stop_elapsed_ns\":%llu,\"sigkill_sent\":%s}\n",
                reason?reason:"NORMAL_EXIT",WIFEXITED(child_status)?WEXITSTATUS(child_status):-1,WIFSIGNALED(child_status)?WTERMSIG(child_status):0,process_count,(unsigned long long)(stop_at?current-stop_at:0),sent_kill?"true":"false");
            dispatch_source_cancel(pressure_source);
            return reason?1:0;
        }
        if (stop_at && current-stop_at>=10000000000ULL) {
            puts("{\"event\":\"FINISHED\",\"reason\":\"VM_STOP_FAILED\",\"all_exited\":false,\"next_vm_allowed\":false}");
            return 1;
        }
        usleep(10000);
    }
}
