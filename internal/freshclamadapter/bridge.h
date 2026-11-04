#ifndef FILEGATE_FRESHCLAM_BRIDGE_H
#define FILEGATE_FRESHCLAM_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
typedef struct {
    uint32_t abi, initialized, invalid, blocked, final, dat_save_failures, dat_save_attempts;
    uint32_t request_count, response_count;
    int32_t http_status;
    int64_t retry_after, max_retry_after, response_utc, wait_seconds;
    char uuid[37], last_ray[21], retry_after_raw[128], date_raw[128];
} fg_state;
typedef struct fg_bridge fg_bridge;
fg_bridge *fg_new(void);
int fg_load(fg_bridge *, const char *);
int fg_bind(fg_bridge *, const char *);
int fg_restore(fg_bridge *, const char *, int64_t, const char *);
int fg_initialize(fg_bridge *, const char *, const char *);
int fg_export(fg_bridge *, fg_state *);
int fg_update(fg_bridge *, const char *, int);
int fg_verify(fg_bridge *, const char *);
void fg_finish(fg_bridge *);
void fg_cleanup(fg_bridge *);
void fg_free(fg_bridge *);
void fg_flush(void);
#endif
