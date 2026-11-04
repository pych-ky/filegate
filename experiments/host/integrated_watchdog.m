#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach_time.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

enum { MAX_PROCESSES=64, LINE_LIMIT=65536, EVENT_BUDGET=4*1024*1024, HOST_MANAGED_BUDGET=64*1024*1024 };
static mach_timebase_info_data_t timebase;
static atomic_ulong pressure;
static atomic_ullong warning_since;
static atomic_ullong normal_since;
static volatile sig_atomic_t interrupted;
static dispatch_source_t pressure_source;
static int log_fd=-1;
static size_t log_bytes;
static int broker_fd=-1;
static int helper_input=-1;
static NSString *reason;
static uint64_t stop_at;
static BOOL kill_sent;
static NSMutableArray<NSMutableDictionary *> *tracked;
static NSMutableData *pending_log;
static BOOL children_released;
static int guardian_lifeline=-1;
static BOOL guardian_stop_notified;
static NSDictionary *last_memory_sample;
static NSDictionary *stop_resource_evidence;
static BOOL fixture_measurement_failure;

typedef struct { uint64_t start_abstime; int32_t pid; uint32_t kind; } GuardianCommand;

static uint64_t clock_ns(void) { return (uint64_t)((__uint128_t)mach_continuous_time()*timebase.numer/timebase.denom); }
static void on_signal(int value) { (void)value; interrupted=1; }
static BOOL number(id value) { return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value)!=CFBooleanGetTypeID(); }
static BOOL integer(id value) { return number(value) && [value doubleValue]>=0 && [value doubleValue]==[value unsignedLongLongValue]; }
static NSDictionary *native_platform(void) { return @{@"os":NSProcessInfo.processInfo.operatingSystemVersionString,@"architecture":@"arm64",@"uid":@(geteuid())}; }

static BOOL owner_path(NSString *path, mode_t permissions, BOOL directory) {
    struct stat st;
    return lstat(path.fileSystemRepresentation,&st)==0 && st.st_uid==geteuid() &&
        (st.st_mode&0777)==permissions && (directory?S_ISDIR(st.st_mode):S_ISREG(st.st_mode));
}

static NSData *json_data(id object) { return [NSJSONSerialization dataWithJSONObject:object options:0 error:NULL]; }
static NSDictionary *json_line(NSData *data) {
    if (!data || data.length>LINE_LIMIT) return nil;
    id object=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    return [object isKindOfClass:NSDictionary.class]?object:nil;
}
static NSDictionary *bounded_json_file(NSString *path) {
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return nil;
    NSMutableData *data=[NSMutableData data]; uint8_t buffer[4096]; ssize_t count;
    while ((count=read(fd,buffer,sizeof(buffer)))>0) {
        [data appendBytes:buffer length:(NSUInteger)count];
        if (data.length>LINE_LIMIT) { close(fd); return nil; }
    }
    close(fd); return count<0?nil:json_line(data);
}

static void emit(NSDictionary *event, BOOL terminal) {
    NSData *data=json_data(event);
    if (!data || data.length>LINE_LIMIT || log_bytes+data.length+1>EVENT_BUDGET-(terminal?0:65536)) {
        if (!reason) reason=@"DISK_PRESSURE";
        return;
    }
    NSMutableData *line=[data mutableCopy];
    [line appendBytes:"\n" length:1];
    [pending_log appendData:line]; log_bytes+=line.length;
    if (!children_released) {
        ssize_t written=write(log_fd,pending_log.bytes,pending_log.length);
        BOOL synced=written==(ssize_t)pending_log.length;
        if (synced && [event[@"event"] isEqualToString:@"FINISHED"]) synced=fsync(log_fd)==0;
        if (!synced) {
            reason=@"DISK_PRESSURE";
            if ([event[@"event"] isEqualToString:@"FINISHED"]) {
                NSMutableDictionary *failed=[event mutableCopy]; failed[@"reason"]=reason;
                data=json_data(failed); line=[data mutableCopy]; [line appendBytes:"\n" length:1];
            }
        }
        [pending_log setLength:0];
    }
    if (broker_fd>=0 && send(broker_fd,line.bytes,line.length,MSG_DONTWAIT|MSG_NOSIGNAL)!=(ssize_t)line.length && !reason) reason=@"INTERRUPTED";
}

static NSString *digest(NSString *path) {
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return nil;
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    uint8_t buffer[65536], output[CC_SHA256_DIGEST_LENGTH];
    ssize_t count;
    while ((count=read(fd,buffer,sizeof(buffer)))>0) CC_SHA256_Update(&context,buffer,(CC_LONG)count);
    close(fd);
    if (count<0) return nil;
    CC_SHA256_Final(output,&context);
    NSMutableString *result=[NSMutableString string];
    for (size_t i=0;i<sizeof(output);i++) [result appendFormat:@"%02x",output[i]];
    return result;
}

static BOOL usage(pid_t pid, struct rusage_info_v4 *result) {
    memset(result,0,sizeof(*result));
    return proc_pid_rusage(pid,RUSAGE_INFO_V4,(rusage_info_t *)result)==0;
}

static BOOL add_process(pid_t pid, NSString *role) {
    struct rusage_info_v4 sample;
    if (!usage(pid,&sample) || !sample.ri_proc_start_abstime || getpgid(pid)!=getpgrp()) return NO;
    for (NSDictionary *known in tracked) if ([known[@"pid"] intValue]==pid) return [known[@"start_abstime"] unsignedLongLongValue]==sample.ri_proc_start_abstime;
    if (tracked.count>=MAX_PROCESSES) return NO;
    [tracked addObject:[@{@"pid":@(pid),@"start_abstime":@(sample.ri_proc_start_abstime),@"role":role,@"exited":@NO} mutableCopy]];
    return YES;
}

static BOOL measure(uint64_t *footprint, uint64_t *resident) {
    *footprint=0; *resident=0;
    if (fixture_measurement_failure) return NO;
    for (NSUInteger i=0;i<tracked.count;i++) {
        NSMutableDictionary *item=tracked[i];
        if ([item[@"exited"] boolValue]) continue;
        struct rusage_info_v4 sample;
        pid_t pid=[item[@"pid"] intValue];
        if (!usage(pid,&sample)) {
            if (errno==ESRCH) { item[@"exited"]=@YES; continue; }
            return NO;
        }
        if (sample.ri_proc_start_abstime!=[item[@"start_abstime"] unsignedLongLongValue]) return NO;
        if (sample.ri_proc_exit_abstime) { item[@"exited"]=@YES; continue; }
        if (getpgid(pid)!=getpgrp()) return NO;
        if (UINT64_MAX-*footprint<sample.ri_phys_footprint || UINT64_MAX-*resident<sample.ri_resident_size) return NO;
        *footprint+=sample.ri_phys_footprint; *resident+=sample.ri_resident_size;
        pid_t children[MAX_PROCESSES];
        errno=0;
        int count=proc_listchildpids(pid,children,sizeof(children));
        if (count<0 || errno || count>=MAX_PROCESSES) return NO;
        for (int n=0;n<count;n++) if (children[n]>0 && !add_process(children[n],@"descendant")) return NO;
    }
    return YES;
}

static BOOL signal_one(NSMutableDictionary *item, int value) {
    if ([item[@"exited"] boolValue]) return YES;
    pid_t pid=[item[@"pid"] intValue];
    struct rusage_info_v4 sample;
    if (!usage(pid,&sample)) {
        if (errno==ESRCH) { item[@"exited"]=@YES; return YES; }
        return NO;
    }
    if (sample.ri_proc_start_abstime!=[item[@"start_abstime"] unsignedLongLongValue]) return NO;
    if (sample.ri_proc_exit_abstime) { item[@"exited"]=@YES; return YES; }
    return kill(pid,value)==0 || errno==ESRCH;
}

static BOOL guardian_command(uint32_t kind, pid_t pid, uint64_t start) {
    GuardianCommand command={.start_abstime=start,.pid=pid,.kind=kind};
    if (guardian_lifeline<0) return NO;
    ssize_t written;
    do { written=write(guardian_lifeline,&command,sizeof(command)); } while (written<0 && errno==EINTR);
    return written==sizeof(command);
}

static void begin_stop(uint64_t now, BOOL critical) {
    if (!reason || stop_at) return;
    stop_at=now; kill_sent=critical;
    if (guardian_lifeline>=0 && !guardian_stop_notified) {
        guardian_stop_notified=guardian_command(2,0,0);
        if (!guardian_stop_notified) reason=@"RESOURCE_MONITOR_FAILED";
    }
    if (helper_input>=0) { close(helper_input); helper_input=-1; }
    for (NSMutableDictionary *item in [tracked reverseObjectEnumerator]) if (![item[@"role"] isEqual:@"guardian"]) signal_one(item,critical?SIGKILL:SIGTERM);
    emit(@{@"event":@"STOP_BEGIN",@"reason":reason,@"continuous_ns":@(now),@"first_signal":@(critical?SIGKILL:SIGTERM),@"resource_evidence":stop_resource_evidence?:NSNull.null},YES);
}

static pid_t spawn_suspended(NSArray<NSString *> *arguments, int input, int output) {
    char **argv=calloc(arguments.count+1,sizeof(char *));
    for (NSUInteger i=0;i<arguments.count;i++) argv[i]=strdup(arguments[i].UTF8String);
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions,input,STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions,output,STDOUT_FILENO);
    int null_fd=open("/dev/null",O_RDWR|O_CLOEXEC);
    posix_spawn_file_actions_adddup2(&actions,null_fd,STDERR_FILENO);
    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes,POSIX_SPAWN_START_SUSPENDED|POSIX_SPAWN_CLOEXEC_DEFAULT);
    char *env[]={"PATH=/usr/bin:/bin","LANG=C","LC_ALL=C",NULL};
    pid_t pid=0;
    int result=posix_spawn(&pid,argv[0],&actions,&attributes,argv,env);
    close(null_fd);
    posix_spawnattr_destroy(&attributes); posix_spawn_file_actions_destroy(&actions);
    for (NSUInteger i=0;i<arguments.count;i++) free(argv[i]); free(argv);
    return result==0?pid:-1;
}

static BOOL read_lines(int fd, NSMutableData *pending, NSMutableArray<NSDictionary *> *messages, size_t *total, BOOL *closed) {
    uint8_t buffer[4096];
    ssize_t count;
    while ((count=read(fd,buffer,sizeof(buffer)))>0) {
        *total+=(size_t)count;
        if (*total>1024*1024) return NO;
        [pending appendBytes:buffer length:(NSUInteger)count];
        for (;;) {
            const uint8_t *bytes=pending.bytes;
            const uint8_t *newline=memchr(bytes,'\n',pending.length);
            if (!newline) break;
            NSUInteger length=(NSUInteger)(newline-bytes);
            NSDictionary *message=json_line([pending subdataWithRange:NSMakeRange(0,length)]);
            if (!message) return NO;
            [messages addObject:message];
            [pending replaceBytesInRange:NSMakeRange(0,length+1) withBytes:NULL length:0];
        }
        if (pending.length>LINE_LIMIT) return NO;
    }
    if (count==0) *closed=YES;
    return count>=0 || errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR;
}

static int guardian_identity(pid_t pid, uint64_t start, pid_t group) {
    struct rusage_info_v4 sample;
    if (!usage(pid,&sample)) return errno==ESRCH?0:-1;
    if (sample.ri_proc_start_abstime!=start || sample.ri_proc_exit_abstime) return 0;
    struct proc_bsdshortinfo info;
    errno=0;
    if (proc_pidinfo(pid,PROC_PIDT_SHORTBSDINFO,0,&info,sizeof(info))!=sizeof(info)) return errno==ESRCH?0:-1;
    if (info.pbsi_pid!=(uint32_t)pid || info.pbsi_pgid!=(uint32_t)group || info.pbsi_uid!=geteuid()) return -1;
    return 1;
}

static BOOL guardian_add(NSMutableArray<NSMutableDictionary *> *targets, pid_t pid, uint64_t start, pid_t parent, pid_t group) {
    if (pid<=1 || pid==getpid() || pid==parent || !start) return NO;
    for (NSDictionary *target in targets) if ([target[@"pid"] intValue]==pid && [target[@"start_abstime"] unsignedLongLongValue]==start) return YES;
    if (targets.count>=MAX_PROCESSES || guardian_identity(pid,start,group)<0) return NO;
    [targets addObject:[@{@"pid":@(pid),@"start_abstime":@(start),@"process_group":@(group),@"uid":@(geteuid()),@"exited":@NO,@"term_sent":@NO,@"sigkill_sent":@NO} mutableCopy]];
    return YES;
}

static int guardian_send(pid_t pid, uint64_t start, pid_t group, int value) {
    int state=guardian_identity(pid,start,group);
    if (state!=1) return state;
    if (kill(pid,value)==0) return 1;
    return errno==ESRCH?0:-1;
}

static BOOL guardian_inventory(NSMutableArray<NSMutableDictionary *> *targets, pid_t parent, pid_t group) {
    pid_t pids[MAX_PROCESSES+2];
    errno=0;
    int count=proc_listpgrppids(group,pids,sizeof(pids));
    if (count<=0 || errno || count>=MAX_PROCESSES+2) return NO;
    BOOL self_found=NO;
    for (int i=0;i<count;i++) {
        if (pids[i]==getpid()) { self_found=YES; continue; }
        if (pids[i]==parent) continue;
        if (pids[i]<=1) continue;
        struct rusage_info_v4 sample;
        if (!usage(pids[i],&sample)) { if (errno==ESRCH) continue; return NO; }
        if (!guardian_add(targets,pids[i],sample.ri_proc_start_abstime,parent,group)) return NO;
    }
    return self_found;
}

static int guardian(int argc, char **argv) {
    if (argc!=6 || geteuid()==0 || getuid()!=geteuid()) return 2;
    signal(SIGTERM,SIG_IGN); signal(SIGINT,SIG_IGN); signal(SIGPIPE,SIG_IGN);
    umask(077);
    struct rlimit core={0,0}; if (setrlimit(RLIMIT_CORE,&core)!=0) return 2;
    char *end;
    errno=0; long parent_value=strtol(argv[2],&end,10);
    if (errno || *end || parent_value<=1 || parent_value>INT_MAX) return 2;
    pid_t parent=(pid_t)parent_value;
    errno=0; uint64_t parent_start=strtoull(argv[3],&end,10);
    if (errno || *end || !parent_start) return 2;
    errno=0; long group_value=strtol(argv[4],&end,10);
    if (errno || *end || group_value!=parent || getpgrp()!=parent) return 2;
    NSString *control=@(argv[5]);
    if (!owner_path(control,0700,YES)) return 2;
    int parent_state=guardian_identity(parent,parent_start,parent);
    if (parent_state<0 || (parent_state==1 && getppid()!=parent)) return 2;
    struct rusage_info_v4 self;
    if (!usage(getpid(),&self) || !guardian_inventory([NSMutableArray array],parent,parent)) return 2;
    int result_fd=open([[control stringByAppendingPathComponent:@"guardian-result.json"] fileSystemRepresentation],O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (result_fd<0) return 2;
    NSDictionary *ready=@{@"event":@"guardian_ready",@"pid":@(getpid()),@"start_abstime":@(self.ri_proc_start_abstime),@"process_group":@(parent)};
    NSMutableData *ready_line=[json_data(ready) mutableCopy]; [ready_line appendBytes:"\n" length:1];
    if (write(STDOUT_FILENO,ready_line.bytes,ready_line.length)!=(ssize_t)ready_line.length) { close(result_fd); return 2; }
    close(STDOUT_FILENO);
    NSMutableArray<NSMutableDictionary *> *targets=[NSMutableArray array];
    GuardianCommand command; size_t have=0;
    BOOL failed=NO, stop_intent=NO, eof=NO;
    for (;;) {
        ssize_t count=read(STDIN_FILENO,(uint8_t *)&command+have,sizeof(command)-have);
        if (count<0) { if (errno==EINTR) continue; failed=YES; break; }
        if (!count) { eof=YES; if (have) failed=YES; break; }
        have+=(size_t)count;
        if (have<sizeof(command)) continue;
        if (command.kind==1) { if (!guardian_add(targets,command.pid,command.start_abstime,parent,parent)) failed=YES; }
        else if (command.kind==2 && command.pid==0 && command.start_abstime==0) stop_intent=YES;
        else failed=YES;
        have=0;
    }
    close(STDIN_FILENO);
    parent_state=guardian_identity(parent,parent_start,parent);
    if (parent_state<0 || (parent_state==1 && !stop_intent)) failed=YES;
    uint64_t began=clock_ns(); BOOL term_sent=NO, sigkill_sent=NO, all_exited=NO;
    for (;;) { @autoreleasepool {
        uint64_t now=clock_ns();
        if (!guardian_inventory(targets,parent,parent)) failed=YES;
        all_exited=YES;
        for (NSMutableDictionary *target in targets) {
            pid_t pid=[target[@"pid"] intValue];
            uint64_t identity=[target[@"start_abstime"] unsignedLongLongValue];
            int state=guardian_identity(pid,identity,parent);
            if (state==0) { target[@"exited"]=@YES; continue; }
            all_exited=NO;
            if (state<0) { failed=YES; continue; }
            if (![target[@"term_sent"] boolValue]) {
                int sent=guardian_send(pid,identity,parent,SIGTERM);
                if (sent==1) { target[@"term_sent"]=@YES; term_sent=YES; }
                else if (sent==0) { target[@"exited"]=@YES; continue; }
                else failed=YES;
            }
            if (now-began>=2000000000ULL && ![target[@"sigkill_sent"] boolValue]) {
                int sent=guardian_send(pid,identity,parent,SIGKILL);
                if (sent==1) { target[@"sigkill_sent"]=@YES; sigkill_sent=YES; }
                else if (sent==0) target[@"exited"]=@YES;
                else failed=YES;
            }
        }
        if (all_exited || now-began>=9500000000ULL) break;
        usleep(10000);
    } }
    NSDictionary *result=@{@"schema":@1,@"parent_pid":@(parent),@"parent_start_abstime":@(parent_start),@"guardian_pid":@(getpid()),@"guardian_start_abstime":@(self.ri_proc_start_abstime),@"process_group":@(parent),@"parent_pipe_eof":@(eof),@"parent_same_identity_live_at_eof":parent_state<0?(id)NSNull.null:@((BOOL)(parent_state==1)),@"parent_stop_intent_seen":@(stop_intent),@"all_targets_exited":@((BOOL)(all_exited&&!failed)),@"term_sent":@(term_sent),@"sigkill_sent":@(sigkill_sent),@"targets":[targets copy],@"elapsed_ns":@(clock_ns()-began),@"monitor_failed":@(failed)};
    NSMutableData *data=[json_data(result) mutableCopy]; [data appendBytes:"\n" length:1];
    BOOL saved=data.length<=LINE_LIMIT && write(result_fd,data.bytes,data.length)==(ssize_t)data.length && fsync(result_fd)==0;
    if (close(result_fd)!=0) saved=NO;
    return all_exited&&!failed&&saved?0:1;
}

static void record_pressure(unsigned long value, uint64_t now) {
    if (value&DISPATCH_MEMORYPRESSURE_WARN) {
        uint64_t zero=0; atomic_compare_exchange_strong(&warning_since,&zero,now); atomic_store(&normal_since,0);
    } else if (value&DISPATCH_MEMORYPRESSURE_NORMAL) {
        atomic_store(&warning_since,0); uint64_t zero=0; atomic_compare_exchange_strong(&normal_since,&zero,now);
    } else atomic_store(&normal_since,0);
    atomic_store(&pressure,value);
}

static void pressure_event(void) {
    record_pressure(dispatch_source_get_data(pressure_source),clock_ns());
}

static int fixture(NSString *role, NSString *mode) {
    if ([role isEqualToString:@"fixture-vm"]) {
        if ([mode isEqualToString:@"early-exit"]) { usleep(500000); return 0; }
        signal(SIGTERM,SIG_IGN); for (;;) pause();
    }
    NSMutableDictionary *workspace=[@{@"event":@"workspace",@"free_bytes":@(128*1024*1024),@"free_inodes":@4096,@"reason":[NSNull null]} mutableCopy];
    if ([mode isEqualToString:@"low-space"]) workspace[@"free_bytes"]=@(64*1024*1024-1);
    if ([mode isEqualToString:@"low-inodes"]) workspace[@"free_inodes"]=@127;
    if ([mode isEqualToString:@"io-error"]) workspace[@"reason"]=@"WORKSPACE_IO_ERROR";
    if ([mode isEqualToString:@"monitor-error"]) workspace[@"reason"]=@"RESOURCE_MONITOR_FAILED";
    if ([mode isEqualToString:@"configuration-error"]) workspace[@"reason"]=@"WORKSPACE_CONFIGURATION_ERROR";
    if ([mode isEqualToString:@"unknown-reason"]) workspace[@"reason"]=@"UNKNOWN";
    if ([mode isEqualToString:@"invalid-type"]) workspace[@"free_bytes"]=@"134217728";
    void (^line)(NSDictionary *)=^(NSDictionary *value) { NSData *data=json_data(value); write(1,data.bytes,data.length); write(1,"\n",1); };
    line(workspace); line(@{@"event":@"validated_ready"});
    char ack[6]={0};
    if (read(0,ack,6)!=6 || memcmp(ack,"READY\n",6)!=0) return 2;
    if ([mode isEqualToString:@"heartbeat-stop"]) for (;;) pause();
    if ([mode isEqualToString:@"malformed"]) { write(1,"invalid\n",8); for (;;) pause(); }
    for (int i=0;i<3;i++) { sleep(1); line(workspace); }
    line(@{@"event":@"exchange_finished",@"outcome":@"verified",@"guest_final_event":@"result"});
    return 0;
}

int main(int argc, char **argv) { @autoreleasepool {
    if (mach_timebase_info(&timebase)!=KERN_SUCCESS || !timebase.denom) return 2;
    if (argc==2 && strcmp(argv[1],"clock")==0) { printf("%llu\n",(unsigned long long)clock_ns()); return 0; }
    if (argc==2 && strcmp(argv[1],"platform")==0) { NSData *data=json_data(native_platform()); write(1,data.bytes,data.length); write(1,"\n",1); return 0; }
    if (argc>=2 && strcmp(argv[1],"guardian")==0) return guardian(argc,argv);
    if (argc==4 && strcmp(argv[1],"fixture-child")==0) return fixture(@(argv[2]),@(argv[3]));
    if (argc!=2 || geteuid()==0 || getpid()!=getpgrp()) return 2;
    umask(077); signal(SIGPIPE,SIG_IGN); signal(SIGTERM,on_signal); signal(SIGINT,on_signal);
    struct rlimit core={0,0}; if (setrlimit(RLIMIT_CORE,&core)!=0) return 2;
    NSString *configuration=@(argv[1]);
    if (!owner_path(configuration,0600,NO)) return 2;
    NSDictionary *config=bounded_json_file(configuration);
    NSString *mode=config[@"mode"], *run=config[@"run_directory"], *control=config[@"control_directory"];
    BOOL is_fixture=[mode isEqualToString:@"fixture"];
    NSString *resource_fixture=config[@"fixture_resource_fault"];
    if (resource_fixture && (!is_fixture || ![@[@"memory-limit",@"pressure-warning",@"pressure-critical",@"measure-failure"] containsObject:resource_fixture])) return 2;
    if (![config[@"schema"] isEqual:@1] || (!is_fixture && ![mode isEqualToString:@"qemu"]) ||
        ![run isKindOfClass:NSString.class] || ![control isKindOfClass:NSString.class] || !owner_path(run,0700,YES) || !owner_path(control,0700,YES) ||
        !integer(config[@"continuous_start_ns"]) || !integer(config[@"continuous_deadline_ns"])) return 2;
    if ((!is_fixture || [config[@"require_launchagent"] boolValue]) && getpgrp()!=getpid()) return 2;
    uint64_t start=[config[@"continuous_start_ns"] unsignedLongLongValue], deadline=[config[@"continuous_deadline_ns"] unsignedLongLongValue];
    BOOL update=[config[@"owner_kind"] isEqualToString:@"update"];
    if (start>clock_ns() || deadline<=start || deadline-start>(update?600:300)*1000000000ULL) return 2;
    NSArray *vm=config[@"vm_argv"], *helper=config[@"helper_argv"];
    if (![vm isKindOfClass:NSArray.class] || !vm.count || ![helper isKindOfClass:NSArray.class] || !helper.count) return 2;
    unichar zero=0; NSString *nul=[NSString stringWithCharacters:&zero length:1];
    for (id value in [vm arrayByAddingObjectsFromArray:helper]) if (![value isKindOfClass:NSString.class] || [value length]>4096 || [value rangeOfString:nul].location!=NSNotFound) return 2;
    if (!is_fixture && ![digest(vm[0]) isEqual:config[@"qemu_sha256"]]) return 2;
    if (!is_fixture) {
        NSString *proof_path=config[@"launch_proof_path"];
        if (![proof_path isKindOfClass:NSString.class] || !owner_path(proof_path,0600,NO)) return 2;
        NSDictionary *proof=bounded_json_file(proof_path);
        if (![proof[@"kind"] isEqual:@"launchagent_death"] || ![proof[@"passed"] isEqual:@YES] ||
            ![proof[@"all_exited_without_child_signal"] isEqual:@YES] || ![proof[@"temporary_service_absent"] isEqual:@YES] ||
            ![proof[@"guardian_result_verified"] isEqual:@YES] || ![proof[@"cleanup_all_exited"] isEqual:@YES] ||
            ![proof[@"guardian_fixture_vm_sigkill_confirmed"] isEqual:@YES] ||
            ![proof[@"normal_completion_disabled"] isEqual:@YES] || ![proof[@"stop_events_observed"] isEqual:@NO] ||
            ![proof[@"native_platform"] isEqual:native_platform()] || ![proof[@"binary_sha256"] isEqual:digest(@(argv[0]))]) return 2;
        NSDictionary *pins=config[@"helper_pins"];
        if (![pins isKindOfClass:NSDictionary.class] || pins.count<2 || pins.count>8) return 2;
        for (id path in pins) if (![path isKindOfClass:NSString.class] || ![pins[path] isKindOfClass:NSString.class] || ![digest(path) isEqual:pins[path]]) return 2;
    }
    log_fd=open([[control stringByAppendingPathComponent:@"events.jsonl"] fileSystemRepresentation],O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (log_fd<0) return 2;
    tracked=[NSMutableArray array]; pending_log=[NSMutableData data];
    struct rusage_info_v4 self;
    struct statvfs disk;
    if (!usage(getpid(),&self) || statvfs(run.fileSystemRepresentation,&disk)!=0) reason=@"RESOURCE_MONITOR_FAILED";
    dispatch_queue_t queue=dispatch_queue_create("filegate.stage0.integrated-pressure",DISPATCH_QUEUE_SERIAL);
    pressure_source=dispatch_source_create(DISPATCH_SOURCE_TYPE_MEMORYPRESSURE,0,DISPATCH_MEMORYPRESSURE_NORMAL|DISPATCH_MEMORYPRESSURE_WARN|DISPATCH_MEMORYPRESSURE_CRITICAL,queue);
    if (!pressure_source) reason=@"RESOURCE_MONITOR_FAILED";
    else { atomic_store(&normal_since,clock_ns()); dispatch_source_set_event_handler(pressure_source,^{ pressure_event(); }); dispatch_resume(pressure_source); }
    int listener=socket(AF_UNIX,SOCK_STREAM,0);
    fcntl(listener,F_SETFD,FD_CLOEXEC);
    NSString *socket_path=[control stringByAppendingPathComponent:@"watch.sock"];
    struct sockaddr_un address={0}; address.sun_family=AF_UNIX;
    if (socket_path.length>=sizeof(address.sun_path)) reason=@"RESOURCE_MONITOR_FAILED";
    else strcpy(address.sun_path,socket_path.fileSystemRepresentation);
    if (listener<0 || bind(listener,(struct sockaddr *)&address,sizeof(address))!=0 || chmod(address.sun_path,0600)!=0 || listen(listener,1)!=0) reason=@"RESOURCE_MONITOR_FAILED";
    fcntl(listener,F_SETFL,O_NONBLOCK);
    emit(@{@"event":@"WATCHDOG_STARTED",@"pid":@(getpid()),@"start_abstime":@(self.ri_proc_start_abstime),@"process_group":@(getpgrp()),@"continuous_start_ns":@(start),@"continuous_deadline_ns":@(deadline),@"mode":mode},YES);
    uint64_t broker_heartbeat=clock_ns(), workspace_heartbeat=0, next_sample=0, vm_started_at=0;
    BOOL started=NO, ready=NO, exchange_done=NO, helper_closed=NO, broker_closed=NO, transfer_allowed=NO, resource_fixture_applied=NO;
    int output_pipe[2]={-1,-1}, input_pipe[2]={-1,-1};
    int null_fd=open("/dev/null",O_RDWR|O_CLOEXEC), helper_output=-1;
    pid_t guardian_pid=-1; uint64_t guardian_start=0;
    BOOL guardian_closed=NO, guardian_reaped=NO;
    int guardian_status=0;
    NSMutableData *broker_pending=[NSMutableData data], *helper_pending=[NSMutableData data];
    size_t broker_total=0, helper_total=0;
    for (;;) { @autoreleasepool {
        uint64_t now=clock_ns();
        if (broker_fd<0 && !reason) {
            int client=accept(listener,NULL,NULL);
            if (client>=0) {
                uid_t uid; gid_t gid;
                if (getpeereid(client,&uid,&gid)!=0 || uid!=geteuid()) { close(client); reason=@"INTERRUPTED"; }
                else { broker_fd=client; fcntl(client,F_SETFD,FD_CLOEXEC); fcntl(client,F_SETFL,O_NONBLOCK); broker_heartbeat=now; }
            }
        }
        if (interrupted && !reason) reason=@"INTERRUPTED";
        if (now>=deadline && (!reason || [reason isEqualToString:@"EXCHANGE_COMPLETE"])) reason=update?@"UPDATE_TIMEOUT":@"SCAN_TIMEOUT";
        if (ready && resource_fixture && !resource_fixture_applied) {
            if ([resource_fixture isEqual:@"pressure-warning"]) record_pressure(DISPATCH_MEMORYPRESSURE_WARN,now);
            if ([resource_fixture isEqual:@"pressure-critical"]) record_pressure(DISPATCH_MEMORYPRESSURE_CRITICAL,now);
            fixture_measurement_failure=[resource_fixture isEqual:@"measure-failure"];
            resource_fixture_applied=YES;
        }
        unsigned long memory_pressure=atomic_load(&pressure);
        uint64_t warning=atomic_load(&warning_since);
        if ((memory_pressure&DISPATCH_MEMORYPRESSURE_CRITICAL) && !reason) {
            reason=@"HOST_RESOURCE_PRESSURE";
            stop_resource_evidence=@{@"trigger":@"os_pressure_critical",@"pressure_flags":@(memory_pressure),@"continuous_ns":@(now),@"last_memory_sample":last_memory_sample?:NSNull.null};
        }
        if (warning && now>=warning && now-warning>=3000000000ULL && !reason) {
            reason=@"HOST_RESOURCE_PRESSURE";
            stop_resource_evidence=@{@"trigger":@"os_pressure_warning",@"pressure_flags":@(memory_pressure),@"warning_since_ns":@(warning),@"warning_elapsed_ns":@(now-warning),@"continuous_ns":@(now),@"last_memory_sample":last_memory_sample?:NSNull.null};
        }
        if ((broker_closed || now-broker_heartbeat>=5000000000ULL) && !reason) reason=@"INTERRUPTED";
        NSMutableArray *messages=[NSMutableArray array];
        if (broker_fd>=0 && !read_lines(broker_fd,broker_pending,messages,&broker_total,&broker_closed) && !reason) reason=@"RESOURCE_MONITOR_FAILED";
        for (NSDictionary *message in messages) {
            NSString *event=message[@"event"];
            if ([event isEqualToString:@"heartbeat"]) broker_heartbeat=now;
            else if ([event isEqualToString:@"cancel"]) { if (!reason) reason=@"INTERRUPTED"; }
            else if ([event isEqualToString:@"start"] && !started && !reason) {
                uint64_t normal=atomic_load(&normal_since);
                uint64_t required_normal=30000000000ULL;
                if (is_fixture && integer(config[@"fixture_normal_wait_ns"]) && [config[@"fixture_normal_wait_ns"] unsignedLongLongValue]<=required_normal) required_normal=[config[@"fixture_normal_wait_ns"] unsignedLongLongValue];
                if (!normal || now<normal || now-normal<required_normal) continue;
                if (!is_fixture) {
                    struct stat st;
                    NSString *raw=[run stringByAppendingPathComponent:@"work.raw"];
                    if (lstat(raw.fileSystemRepresentation,&st)!=0 || !S_ISREG(st.st_mode) || st.st_size!=4294967296LL || st.st_blocks*512<4294967296LL) { reason=@"WORKSPACE_CONFIGURATION_ERROR"; break; }
                }
                int life[2]={-1,-1}, status_pipe[2]={-1,-1};
                if (pipe(life)!=0 || pipe(status_pipe)!=0) { reason=@"RESOURCE_MONITOR_FAILED"; break; }
                for (int i=0;i<2;i++) { fcntl(life[i],F_SETFD,FD_CLOEXEC); fcntl(status_pipe[i],F_SETFD,FD_CLOEXEC); }
                guardian_lifeline=life[1]; fcntl(guardian_lifeline,F_SETFL,O_NONBLOCK);
                guardian_pid=spawn_suspended(@[@(argv[0]),@"guardian",[@(getpid()) stringValue],[@(self.ri_proc_start_abstime) stringValue],[@(getpgrp()) stringValue],control],life[0],status_pipe[1]);
                close(life[0]); close(status_pipe[1]);
                if (guardian_pid<0) { close(status_pipe[0]); reason=@"RESOURCE_MONITOR_FAILED"; break; }
                if (!add_process(guardian_pid,@"guardian")) { kill(guardian_pid,SIGKILL); waitpid(guardian_pid,NULL,0); close(status_pipe[0]); reason=@"RESOURCE_MONITOR_FAILED"; break; }
                NSMutableDictionary *guardian_item=tracked.lastObject;
                guardian_start=[guardian_item[@"start_abstime"] unsignedLongLongValue];
                if (!signal_one(guardian_item,SIGCONT)) { close(status_pipe[0]); reason=@"RESOURCE_MONITOR_FAILED"; break; }
                fcntl(status_pipe[0],F_SETFL,O_NONBLOCK);
                NSMutableData *guard_pending=[NSMutableData data]; NSMutableArray *guard_messages=[NSMutableArray array];
                size_t guard_bytes=0; BOOL guard_output_closed=NO, guard_ready=NO;
                uint64_t guard_deadline=clock_ns()+2000000000ULL;
                while (clock_ns()<guard_deadline && !guard_ready) {
                    struct pollfd descriptor={.fd=status_pipe[0],.events=POLLIN|POLLHUP};
                    int polled=poll(&descriptor,1,10);
                    if (polled<0 && errno!=EINTR) break;
                    if (!read_lines(status_pipe[0],guard_pending,guard_messages,&guard_bytes,&guard_output_closed)) break;
                    if (guard_messages.count==1) {
                        NSDictionary *message=guard_messages[0];
                        guard_ready=[message[@"event"] isEqual:@"guardian_ready"] && [message[@"pid"] isEqual:@(guardian_pid)] && [message[@"start_abstime"] isEqual:@(guardian_start)] && [message[@"process_group"] isEqual:@(getpgrp())];
                        break;
                    }
                    if (guard_output_closed) break;
                }
                close(status_pipe[0]);
                if (!guard_ready || guard_pending.length || guardian_identity(guardian_pid,guardian_start,getpgrp())!=1) { reason=@"RESOURCE_MONITOR_FAILED"; break; }
                emit(@{@"event":@"GUARDIAN_READY",@"pid":@(guardian_pid),@"start_abstime":@(guardian_start),@"process_group":@(getpgrp())},YES);
                if (pipe(output_pipe)!=0 || pipe(input_pipe)!=0) { reason=@"RESOURCE_MONITOR_FAILED"; break; }
                for (int i=0;i<2;i++) { fcntl(output_pipe[i],F_SETFD,FD_CLOEXEC); fcntl(input_pipe[i],F_SETFD,FD_CLOEXEC); }
                pid_t vm_pid=spawn_suspended(vm,null_fd,null_fd);
                if (vm_pid<0) { reason=@"VM_START_FAILED"; break; }
                if (!add_process(vm_pid,@"vm")) { kill(vm_pid,SIGKILL); waitpid(vm_pid,NULL,0); reason=@"VM_START_FAILED"; break; }
                pid_t helper_pid=spawn_suspended(helper,input_pipe[0],output_pipe[1]);
                if (helper_pid<0) { reason=@"VM_START_FAILED"; break; }
                if (!add_process(helper_pid,@"helper")) { kill(helper_pid,SIGKILL); waitpid(helper_pid,NULL,0); reason=@"VM_START_FAILED"; break; }
                for (NSDictionary *item in tracked) if (![item[@"role"] isEqual:@"guardian"] && !guardian_command(1,[item[@"pid"] intValue],[item[@"start_abstime"] unsignedLongLongValue])) reason=@"RESOURCE_MONITOR_FAILED";
                close(output_pipe[1]); close(input_pipe[0]); output_pipe[1]=-1; input_pipe[0]=-1;
                helper_output=output_pipe[0]; helper_input=input_pipe[1]; fcntl(helper_output,F_SETFL,O_NONBLOCK);
                uint64_t footprint,resident;
                if (!measure(&footprint,&resident) && !measure(&footprint,&resident)) { reason=@"RESOURCE_MONITOR_FAILED"; break; }
                last_memory_sample=@{@"footprint_bytes":@(footprint),@"resident_bytes":@(resident),@"observed_memory_bytes":@(MAX(footprint,resident)),@"process_count":@(tracked.count),@"continuous_ns":@(clock_ns())};
                emit(@{@"event":@"MONITOR_READY",@"processes":[tracked copy],@"continuous_ns":@(now)},YES);
                if (reason || clock_ns()>=deadline) { if (!reason) reason=update?@"UPDATE_TIMEOUT":@"SCAN_TIMEOUT"; break; }
                children_released=YES;
                for (NSMutableDictionary *item in tracked) if (![item[@"role"] isEqual:@"guardian"] && !signal_one(item,SIGCONT)) reason=@"RESOURCE_MONITOR_FAILED";
                started=YES; vm_started_at=clock_ns();
            } else if (![event isEqualToString:@"start"] && !reason) reason=@"RESOURCE_MONITOR_FAILED";
        }
        if (started && helper_output>=0 && !reason) {
            [messages removeAllObjects];
            if (!read_lines(helper_output,helper_pending,messages,&helper_total,&helper_closed)) reason=@"REPORT_VALIDATION_FAILED";
            for (NSDictionary *message in messages) {
                NSString *event=message[@"event"];
                if ([event isEqualToString:@"workspace"]) {
                    id failure=message[@"reason"];
                    if (!integer(message[@"free_bytes"]) || !integer(message[@"free_inodes"])) reason=@"RESOURCE_MONITOR_FAILED";
                    else if (failure && failure!=NSNull.null) {
                        if ([@[@"WORKSPACE_LIMIT",@"WORKSPACE_IO_ERROR",@"RESOURCE_MONITOR_FAILED",@"WORKSPACE_CONFIGURATION_ERROR"] containsObject:failure]) reason=failure;
                        else reason=@"REPORT_VALIDATION_FAILED";
                    } else if ([message[@"free_bytes"] unsignedLongLongValue]<64*1024*1024ULL || [message[@"free_inodes"] unsignedLongLongValue]<128) reason=@"WORKSPACE_LIMIT";
                    workspace_heartbeat=now;
                    emit(@{@"event":@"WORKSPACE",@"free_bytes":message[@"free_bytes"]?:@0,@"free_inodes":message[@"free_inodes"]?:@0,@"reason":reason?:NSNull.null},NO);
                } else if ([event isEqualToString:@"validated_ready"] && !ready && !reason) {
                    if (!workspace_heartbeat || now-workspace_heartbeat>=5000000000ULL || clock_ns()>=deadline) reason=@"RESOURCE_MONITOR_FAILED";
                    else {
                        ready=YES;
                        emit(@{@"event":@"TRANSFER_ALLOWED",@"continuous_ns":@(now)},YES);
                        if (!reason && write(helper_input,"READY\n",6)==6) transfer_allowed=YES;
                        else reason=@"RESOURCE_MONITOR_FAILED";
                    }
                } else if ([event isEqualToString:@"exchange_finished"] && transfer_allowed && !exchange_done) {
                    exchange_done=[message[@"outcome"] isEqualToString:@"verified"];
                    if (!reason) reason=clock_ns()>=deadline?(update?@"UPDATE_TIMEOUT":@"SCAN_TIMEOUT"):(exchange_done?@"EXCHANGE_COMPLETE":@"REPORT_VALIDATION_FAILED");
                } else if (!reason) reason=@"REPORT_VALIDATION_FAILED";
            }
        }
        if (started && !ready && now>=vm_started_at && now-vm_started_at>=60000000000ULL && !reason) reason=@"VM_START_FAILED";
        if (ready && !exchange_done && now-workspace_heartbeat>=5000000000ULL && !reason) reason=@"RESOURCE_MONITOR_FAILED";
        if (helper_closed && !exchange_done && !reason) reason=@"REPORT_VALIDATION_FAILED";
        if (now>=next_sample || reason) {
            next_sample=now+1000000000ULL;
            uint64_t footprint=0,resident=0;
            BOOL measured=measure(&footprint,&resident);
            if (!measured) measured=measure(&footprint,&resident);
            if (!measured && !reason) {
                reason=@"RESOURCE_MONITOR_FAILED";
                stop_resource_evidence=@{@"trigger":@"memory_measurement_failed",@"attempts":@2,@"continuous_ns":@(now),@"last_memory_sample":last_memory_sample?:NSNull.null};
            }
            uint64_t observed=MAX(footprint,resident);
            if (ready && [resource_fixture isEqual:@"memory-limit"]) { footprint=6*1024*1024*1024ULL+1; observed=MAX(footprint,resident); }
            if (measured) last_memory_sample=@{@"footprint_bytes":@(footprint),@"resident_bytes":@(resident),@"observed_memory_bytes":@(observed),@"process_count":@(tracked.count),@"continuous_ns":@(now)};
            if (!stop_at && measured && ( [stop_resource_evidence[@"trigger"] isEqual:@"os_pressure_warning"] || [stop_resource_evidence[@"trigger"] isEqual:@"os_pressure_critical"] )) {
                NSMutableDictionary *evidence=[stop_resource_evidence mutableCopy];
                evidence[@"memory_sample_at_stop"]=last_memory_sample;
                stop_resource_evidence=evidence;
            }
            if (measured && observed>6*1024*1024*1024ULL && !reason) {
                reason=@"HOST_RESOURCE_PRESSURE";
                stop_resource_evidence=@{@"trigger":@"observed_memory_limit",@"limit_bytes":@(6*1024*1024*1024ULL),@"pressure_flags":@(memory_pressure),@"sample":last_memory_sample};
            }
            if (statvfs(run.fileSystemRepresentation,&disk)!=0 && !reason) reason=@"RESOURCE_MONITOR_FAILED";
            else if ((uint64_t)disk.f_bavail*disk.f_frsize<2*1024*1024*1024ULL+HOST_MANAGED_BUDGET && !reason) reason=@"DISK_PRESSURE";
            if (!is_fixture && started) {
                struct stat st;
                if ((lstat([[run stringByAppendingPathComponent:@"work.raw"] fileSystemRepresentation],&st)!=0 || st.st_size!=4294967296LL || !S_ISREG(st.st_mode)) && !reason) reason=@"WORKSPACE_CONFIGURATION_ERROR";
            }
            if (!reason) {
                NSMutableDictionary *sample=[last_memory_sample mutableCopy]; sample[@"event"]=@"SAMPLE"; sample[@"pressure_flags"]=@(memory_pressure);
                emit(sample,NO);
            }
        }
        begin_stop(now,(memory_pressure&DISPATCH_MEMORYPRESSURE_CRITICAL)!=0);
        if (stop_at && !kill_sent && ((memory_pressure&DISPATCH_MEMORYPRESSURE_CRITICAL) || now-stop_at>=2000000000ULL)) {
            for (NSMutableDictionary *item in [tracked reverseObjectEnumerator]) if (![item[@"role"] isEqual:@"guardian"]) signal_one(item,SIGKILL);
            kill_sent=YES; emit(@{@"event":@"SIGKILL_SENT",@"stop_elapsed_ns":@(now-stop_at)},YES);
        }
        int status; pid_t exited;
        while ((exited=waitpid(-1,&status,WNOHANG))>0) {
            for (NSMutableDictionary *item in tracked) if ([item[@"pid"] intValue]==exited) {
                item[@"exited"]=@YES; item[@"wait_status"]=@(status);
                if ([item[@"role"] isEqual:@"guardian"]) { guardian_reaped=YES; guardian_status=status; if (!guardian_closed && (!reason || [reason isEqual:@"EXCHANGE_COMPLETE"])) reason=@"RESOURCE_MONITOR_FAILED"; }
                if ([item[@"role"] isEqualToString:@"vm"] && !exchange_done && !reason) reason=@"VM_START_FAILED";
            }
        }
        begin_stop(now,(memory_pressure&DISPATCH_MEMORYPRESSURE_CRITICAL)!=0);
        BOOL other_exited=YES;
        for (NSDictionary *item in tracked) if (![item[@"role"] isEqual:@"guardian"] && ![item[@"exited"] boolValue]) other_exited=NO;
        if (reason && stop_at && other_exited && guardian_lifeline>=0) { close(guardian_lifeline); guardian_lifeline=-1; guardian_closed=YES; }
        if (guardian_pid>0 && !guardian_closed && guardian_identity(guardian_pid,guardian_start,getpgrp())!=1 && (!reason || [reason isEqual:@"EXCHANGE_COMPLETE"])) reason=@"RESOURCE_MONITOR_FAILED";
        BOOL all_exited=YES;
        for (NSDictionary *item in tracked) if (![item[@"exited"] boolValue]) all_exited=NO;
        if (reason && stop_at && (all_exited || (now>=stop_at && now-stop_at>=10000000000ULL))) {
            NSString *final_reason=all_exited?reason:@"VM_STOP_FAILED";
            BOOL guardian_confirmed=guardian_reaped && WIFEXITED(guardian_status) && WEXITSTATUS(guardian_status)==0;
            NSString *guardian_path=[control stringByAppendingPathComponent:@"guardian-result.json"];
            NSDictionary *guardian_result=owner_path(guardian_path,0600,NO)?bounded_json_file(guardian_path):nil;
            BOOL guardian_valid=guardian_confirmed && [guardian_result[@"schema"] isEqual:@1] && [guardian_result[@"parent_pid"] isEqual:@(getpid())] && [guardian_result[@"parent_start_abstime"] isEqual:@(self.ri_proc_start_abstime)] && [guardian_result[@"guardian_pid"] isEqual:@(guardian_pid)] && [guardian_result[@"guardian_start_abstime"] isEqual:@(guardian_start)] && [guardian_result[@"parent_pipe_eof"] isEqual:@YES] && [guardian_result[@"parent_same_identity_live_at_eof"] isEqual:@YES] && [guardian_result[@"parent_stop_intent_seen"] isEqual:@YES] && [guardian_result[@"all_targets_exited"] isEqual:@YES] && [guardian_result[@"monitor_failed"] isEqual:@NO];
            if ([final_reason isEqual:@"EXCHANGE_COMPLETE"] && !guardian_valid) final_reason=@"RESOURCE_MONITOR_FAILED";
            if (all_exited) children_released=NO;
            emit(@{@"event":@"FINISHED",@"reason":final_reason,@"original_reason":reason,@"all_exited":@(all_exited),@"stop_elapsed_ns":@(now-stop_at),@"sigkill_sent":@(kill_sent),@"transfer_allowed":@(transfer_allowed),@"processes":[tracked copy],@"guardian_exit":@{@"confirmed":@(guardian_confirmed),@"result_valid":@(guardian_valid)},@"resource_evidence":stop_resource_evidence?:NSNull.null,@"product_scan":@NO},YES);
            close(log_fd);
            if (broker_fd>=0) close(broker_fd); if (listener>=0) close(listener); if (helper_output>=0) close(helper_output); if (helper_input>=0) close(helper_input); close(null_fd);
            if (pressure_source) dispatch_source_cancel(pressure_source);
            unlink(address.sun_path);
            return all_exited && [final_reason isEqualToString:@"EXCHANGE_COMPLETE"]?0:1;
        }
        usleep(10000);
    } }
} }
