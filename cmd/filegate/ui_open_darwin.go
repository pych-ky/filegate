package main

/*
#cgo LDFLAGS: -framework CoreServices -framework CoreFoundation
#include <CoreServices/CoreServices.h>
#include <stdlib.h>
#include <string.h>

static int filegateOpenUI(const char *value) {
    CFArrayRef apps = LSCopyApplicationURLsForBundleIdentifier(CFSTR("com.microsoft.edgemac"), NULL);
    if (apps == NULL) return 0;
    if (CFArrayGetCount(apps) == 0) { CFRelease(apps); return 0; }
    CFURLRef url = CFURLCreateWithBytes(NULL, (const UInt8 *)value, strlen(value), kCFStringEncodingUTF8, NULL);
    if (url == NULL) { CFRelease(apps); return 0; }
    CFArrayRef items = CFArrayCreate(NULL, (const void **)&url, 1, &kCFTypeArrayCallBacks);
    if (items == NULL) { CFRelease(url); CFRelease(apps); return 0; }
    LSLaunchURLSpec spec = {0};
    spec.appURL = (CFURLRef)CFArrayGetValueAtIndex(apps, 0);
    spec.itemURLs = items;
    spec.launchFlags = kLSLaunchDefaults | kLSLaunchDontSwitch | kLSLaunchDontAddToRecents;
    OSStatus status = LSOpenFromURLSpec(&spec, NULL);
    CFRelease(items);
    CFRelease(url);
    CFRelease(apps);
    return status == noErr;
}
*/
import "C"

import "unsafe"

// LaunchServices receives the bootstrap URL in-process, never through child argv.
func openUI(target string) bool {
	value := C.CString(target)
	defer C.free(unsafe.Pointer(value))
	return C.filegateOpenUI(value) != 0
}
