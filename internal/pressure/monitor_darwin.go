package pressure

/*
#cgo CFLAGS: -fblocks -std=c11
#include <dispatch/dispatch.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

typedef struct {
    dispatch_source_t source;
    dispatch_queue_t queue;
    dispatch_semaphore_t cancelled;
    int read_fd;
    int write_fd;
    atomic_uint pending;
    atomic_int failed;
} fg_pressure;

static fg_pressure *fg_pressure_open(void) {
    fg_pressure *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    int descriptors[2];
    if (pipe(descriptors) != 0) { free(m); return NULL; }
    m->read_fd = descriptors[0]; m->write_fd = descriptors[1];
    if (fcntl(m->read_fd, F_SETFD, FD_CLOEXEC) != 0 || fcntl(m->write_fd, F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(m->write_fd, F_SETFL, O_NONBLOCK) != 0) {
        close(m->read_fd); close(m->write_fd); free(m); return NULL;
    }
    m->queue = dispatch_queue_create("filegate.broker.memory-pressure", DISPATCH_QUEUE_SERIAL);
    m->cancelled = dispatch_semaphore_create(0);
    if (m->queue && m->cancelled) m->source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MEMORYPRESSURE, 0,
        DISPATCH_MEMORYPRESSURE_NORMAL | DISPATCH_MEMORYPRESSURE_WARN | DISPATCH_MEMORYPRESSURE_CRITICAL, m->queue);
    if (!m->source) {
        if (m->cancelled) dispatch_release(m->cancelled);
        if (m->queue) dispatch_release(m->queue);
        close(m->read_fd); close(m->write_fd); free(m); return NULL;
    }
    dispatch_source_set_event_handler(m->source, ^{
        atomic_fetch_or(&m->pending, (unsigned int)dispatch_source_get_data(m->source));
        unsigned char notice = 1;
        if (write(m->write_fd, &notice, 1) != 1 && errno != EAGAIN) atomic_store(&m->failed, 1);
    });
    dispatch_source_set_cancel_handler(m->source, ^{
        close(m->write_fd);
        dispatch_semaphore_signal(m->cancelled);
    });
    dispatch_resume(m->source);
    return m;
}

static int fg_pressure_read(fg_pressure *m, uint32_t *level, uint32_t *pending, uint64_t *now) {
    size_t size = sizeof(*level);
    mach_timebase_info_data_t base;
    if (atomic_load(&m->failed) || sysctlbyname("kern.memorystatus_vm_pressure_level", level, &size, NULL, 0) != 0 ||
        size != sizeof(*level) || (*level != 1 && *level != 2 && *level != 4) ||
        mach_timebase_info(&base) != KERN_SUCCESS || !base.numer || !base.denom) return -1;
    __uint128_t value = (__uint128_t)mach_continuous_time() * base.numer / base.denom;
    if (value > UINT64_MAX) return -1;
    *now = (uint64_t)value;
    *pending = atomic_exchange(&m->pending, 0);
    if (*pending & ~7U) { atomic_store(&m->failed, 1); return -1; }
    return 0;
}

static void fg_pressure_close(fg_pressure *m) {
    dispatch_source_cancel(m->source);
    dispatch_semaphore_wait(m->cancelled, DISPATCH_TIME_FOREVER);
    dispatch_sync(m->queue, ^{});
    dispatch_release(m->source);
    dispatch_release(m->cancelled);
    dispatch_release(m->queue);
    free(m);
}
*/
import "C"

import (
	"os"
	"sync"
)

type Monitor struct {
	mu     sync.Mutex
	native *C.fg_pressure
	reader *os.File
	events chan struct{}
	done   chan struct{}
}

func Open() (*Monitor, error) {
	native := C.fg_pressure_open()
	if native == nil {
		return nil, Unavailable
	}
	m := &Monitor{native: native, reader: os.NewFile(uintptr(native.read_fd), "pressure-events"), events: make(chan struct{}, 1), done: make(chan struct{})}
	go func() {
		defer close(m.done)
		defer close(m.events)
		buffer := make([]byte, 64)
		for {
			if _, err := m.reader.Read(buffer); err != nil {
				return
			}
			select {
			case m.events <- struct{}{}:
			default:
			}
		}
	}()
	return m, nil
}

func (m *Monitor) Read() (Sample, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.native == nil {
		return Sample{}, Unavailable
	}
	var level, pending C.uint32_t
	var now C.uint64_t
	if C.fg_pressure_read(m.native, &level, &pending, &now) != 0 && C.fg_pressure_read(m.native, &level, &pending, &now) != 0 {
		return Sample{}, Unavailable
	}
	return Sample{Level: uint32(level), Pending: uint32(pending), ContinuousNS: uint64(now)}, nil
}

func (m *Monitor) Events() <-chan struct{} { return m.events }

func (m *Monitor) Close() {
	m.mu.Lock()
	if m.native != nil {
		C.fg_pressure_close(m.native)
		m.native = nil
	}
	m.mu.Unlock()
	m.reader.Close()
	<-m.done
}
