#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static FILE *(*next_fopen)(const char *, const char *);
static size_t (*next_fwrite)(const void *, size_t, size_t, FILE *);
static int (*next_fclose)(FILE *);
static struct { FILE *file; uint64_t bytes, calls; } streams[8];

__attribute__((constructor)) static void initialize(void) {
    int saved = errno;
    next_fopen = dlsym(RTLD_NEXT, "fopen");
    next_fwrite = dlsym(RTLD_NEXT, "fwrite");
    next_fclose = dlsym(RTLD_NEXT, "fclose");
    if (!next_fopen || !next_fwrite || !next_fclose) {
        dprintf(2, "FILEGATE_MSPACK_OBSERVER failure=resolution\n");
        _exit(125);
    }
    dprintf(2, "FILEGATE_MSPACK_OBSERVER loaded=1\n");
    errno = saved;
}

FILE *fopen(const char *path, const char *mode) {
    if (!next_fopen) initialize();
    FILE *result = next_fopen(path, mode);
    int saved = errno;
    if (result && !strcmp(mode, "wb") && strstr(path, "/avtmp/")) {
        unsigned i;
        for (i = 0; i < 8; i++) {
            if (!streams[i].file) {
                streams[i].file = result;
                streams[i].bytes = streams[i].calls = 0;
                break;
            }
        }
        if (i == 8) dprintf(2, "FILEGATE_MSPACK_OBSERVER failure=slots\n");
    }
    errno = saved;
    return result;
}

size_t fwrite(const void *data, size_t size, size_t count, FILE *file) {
    if (!next_fwrite) initialize();
    size_t result = next_fwrite(data, size, count, file);
    int saved = errno;
    for (unsigned i = 0; i < 8; i++) {
        if (streams[i].file == file) {
            streams[i].bytes += size * result;
            streams[i].calls++;
            break;
        }
    }
    errno = saved;
    return result;
}

int fclose(FILE *file) {
    if (!next_fclose) initialize();
    unsigned found = 8;
    off_t position = -1;
    int saved = errno;
    for (unsigned i = 0; i < 8; i++) {
        if (streams[i].file == file) { found = i; position = ftello(file); break; }
    }
    errno = saved;
    int result = next_fclose(file);
    saved = errno;
    if (found < 8) {
        if (result != 0 || position < 0) dprintf(2, "FILEGATE_MSPACK_OBSERVER failure=close\n");
        dprintf(2, "FILEGATE_MSPACK_OBSERVER bytes=%llu position=%lld write_calls=%llu close_rc=%d\n",
            (unsigned long long)streams[found].bytes, (long long)position,
            (unsigned long long)streams[found].calls, result);
        streams[found].file = NULL;
    }
    errno = saved;
    return result;
}
