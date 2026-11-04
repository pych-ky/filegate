//go:build linux && arm64 && cgo

package freshclamadapter

/*
#cgo LDFLAGS: -ldl
#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import "unsafe"

type nativeLibrary struct{ bridge *C.fg_bridge }

func newLibrary() (library, error) {
	b := C.fg_new()
	if b == nil {
		return nil, invalid
	}
	return &nativeLibrary{bridge: b}, nil
}

func (l *nativeLibrary) load(path string) error {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	if C.fg_load(l.bridge, p) != 0 {
		return invalid
	}
	return nil
}
func (l *nativeLibrary) bind(path string) error {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	if C.fg_bind(l.bridge, p) != 0 {
		return invalid
	}
	return nil
}
func (l *nativeLibrary) restore(s Snapshot) error {
	u, r := C.CString(s.UUID), C.CString(s.LastRay)
	defer C.free(unsafe.Pointer(u))
	defer C.free(unsafe.Pointer(r))
	retry := max(s.RetryAfterUTC, s.MaxRetryAfterUTC)
	if C.fg_restore(l.bridge, u, C.int64_t(retry), r) != 0 {
		return invalid
	}
	return nil
}
func (l *nativeLibrary) initialize(database, temporary string) error {
	d, t := C.CString(database), C.CString(temporary)
	defer C.free(unsafe.Pointer(d))
	defer C.free(unsafe.Pointer(t))
	if C.fg_initialize(l.bridge, d, t) != 0 {
		return invalid
	}
	return nil
}

func asciiArray(p *C.char, size int) (string, error) {
	data := C.GoBytes(unsafe.Pointer(p), C.int(size))
	for n, c := range data {
		if c == 0 {
			return string(data[:n]), nil
		}
		if c > 127 {
			return "", invalid
		}
	}
	return string(data), nil
}

func (l *nativeLibrary) current() (state, error) {
	var v C.fg_state
	if C.fg_export(l.bridge, &v) != 0 {
		return state{}, invalid
	}
	s := state{Initialized: v.initialized != 0, Invalid: v.invalid != 0, Blocked: v.blocked != 0, Final: v.final != 0,
		DatSaveFailures: uint32(v.dat_save_failures), DatSaveAttempts: uint32(v.dat_save_attempts), RequestCount: uint32(v.request_count), ResponseCount: uint32(v.response_count),
		HTTPStatus: int32(v.http_status), RetryAfter: int64(v.retry_after), MaxRetryAfter: int64(v.max_retry_after), ResponseUTC: int64(v.response_utc), WaitSeconds: int64(v.wait_seconds)}
	var err error
	for _, item := range []struct {
		target *string
		data   *C.char
		size   int
	}{{&s.UUID, &v.uuid[0], 37}, {&s.LastRay, &v.last_ray[0], 21}, {&s.RetryRaw, &v.retry_after_raw[0], 128}, {&s.DateRaw, &v.date_raw[0], 128}} {
		if *item.target, err = asciiArray(item.data, item.size); err != nil {
			return state{}, err
		}
	}
	return s, nil
}
func (l *nativeLibrary) update(name string, fixture bool) (int, error) {
	n := C.CString(name)
	defer C.free(unsafe.Pointer(n))
	f := C.int(0)
	if fixture {
		f = 1
	}
	return int(C.fg_update(l.bridge, n, f)), nil
}
func (l *nativeLibrary) verify(path string) bool {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	return C.fg_verify(l.bridge, p) == 0
}
func (l *nativeLibrary) finish()  { C.fg_finish(l.bridge) }
func (l *nativeLibrary) cleanup() { C.fg_cleanup(l.bridge) }
func (l *nativeLibrary) close()   { C.fg_free(l.bridge) }
func flushLibraryOutput()         { C.fg_flush() }
