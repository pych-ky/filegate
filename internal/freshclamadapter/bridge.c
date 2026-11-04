//go:build linux && arm64 && cgo

#include "bridge.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t msgFlags, logFlags;
    uint64_t maxLogSize;
    uint32_t maxAttempts, connectTimeout, requestTimeout, bCompressLocalDatabase;
    char *logFile, *logFacility, *localIP, *userAgent, *proxyServer;
    uint16_t proxyPort;
    char *proxyUsername, *proxyPassword, *databaseDirectory, *tempDirectory;
} fg_config;

_Static_assert(sizeof(fg_state) == 392 && offsetof(fg_state, uuid) == 72, "fixed state ABI");
_Static_assert(sizeof(fg_config) == 112 && offsetof(fg_config, databaseDirectory) == 96, "fixed config ABI");

struct fg_bridge {
    void *handles[33];
    size_t count;
    char *database, *temporary;
    int (*restore)(const char *, int64_t, const char *);
    int (*initialize)(fg_config *);
    int (*export_state)(fg_state *, size_t);
    int (*update)(const char *, const char **, uint32_t, int, const char *, int, void *, int *);
    int (*download)(const char *, void *, int *);
    int (*verify)(const char *, int);
    int (*finish)(void);
    void (*cleanup)(void);
};

fg_bridge *fg_new(void) { return calloc(1, sizeof(fg_bridge)); }

int fg_load(fg_bridge *b, const char *path) {
    if (b->count >= 33) return -1;
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) return -1;
    b->handles[b->count++] = handle;
    return 0;
}

int fg_bind(fg_bridge *b, const char *path) {
    if (fg_load(b, path)) return -1;
    void *h = b->handles[b->count - 1];
    uint32_t (*abi)(void) = dlsym(h, "fgfc_abi");
    const char *(*source)(void) = dlsym(h, "fgfc_source_id");
    static const char expected[] = "1.4.6:5853e1396777bae4d909cd3dd44f58352e7cf9b3:filegate-v1";
    if (!abi || !source || abi() != 1) return -1;
    const char *identity = source();
    if (!identity || strnlen(identity, sizeof(expected)) != sizeof(expected)-1 || memcmp(identity, expected, sizeof(expected))) return -1;
    b->restore = dlsym(h, "fgfc_prepare_restore");
    b->initialize = dlsym(h, "fc_initialize");
    b->export_state = dlsym(h, "fgfc_export");
    b->update = dlsym(h, "fc_update_database");
    b->download = dlsym(h, "fc_download_url_database");
    b->verify = dlsym(h, "fc_test_database");
    b->finish = dlsym(h, "fgfc_finish");
    b->cleanup = dlsym(h, "fc_cleanup");
    return b->restore && b->initialize && b->export_state && b->update && b->download && b->verify && b->finish && b->cleanup ? 0 : -1;
}

int fg_restore(fg_bridge *b, const char *uuid, int64_t retry, const char *ray) { return b->restore(uuid, retry, ray); }

int fg_initialize(fg_bridge *b, const char *database, const char *temporary) {
    b->database = strdup(database); b->temporary = strdup(temporary);
    if (!b->database || !b->temporary) return -1;
    fg_config config = {0};
    config.msgFlags = 4; config.maxAttempts = 1;
    config.connectTimeout = 10; config.requestTimeout = 30;
    config.databaseDirectory = b->database; config.tempDirectory = b->temporary;
    return b->initialize(&config);
}

int fg_export(fg_bridge *b, fg_state *state) { return b->export_state(state, sizeof(*state)); }
int fg_update(fg_bridge *b, const char *name, int fixture) {
    int updated = 0;
    const char *servers[] = {"https://database.clamav.net"};
    return fixture ? b->download(name, NULL, &updated) : b->update(name, servers, 1, 0, NULL, 1, NULL, &updated);
}
int fg_verify(fg_bridge *b, const char *path) { return b->verify(path, 1); }
void fg_finish(fg_bridge *b) { (void)b->finish(); }
void fg_cleanup(fg_bridge *b) { b->cleanup(); }
void fg_free(fg_bridge *b) {
    if (!b) return;
    while (b->count) dlclose(b->handles[--b->count]);
    free(b->database); free(b->temporary); free(b);
}
void fg_flush(void) { fflush(NULL); }
