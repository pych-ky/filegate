#ifndef FILEGATE_FRESHCLAM_CONTROL_H
#define FILEGATE_FRESHCLAM_CONTROL_H

#include <stddef.h>
#include <stdint.h>

#define FGFC_ABI 1
#define FGFC_HEADER_VALUE 128

/* 同期一回実行の観測状態。host側generation/時刻正規化とは分ける。 */
struct fgfc_state {
    uint32_t abi;
    uint32_t initialized;
    uint32_t invalid;
    uint32_t blocked;
    uint32_t final;
    uint32_t dat_save_failures;
    uint32_t dat_save_attempts;
    uint32_t request_count;
    uint32_t response_count;
    int32_t http_status;
    int64_t retry_after;
    int64_t max_retry_after;
    int64_t response_utc;
    int64_t wait_seconds;
    char uuid[37];
    char last_ray[21];
    char retry_after_raw[FGFC_HEADER_VALUE];
    char date_raw[FGFC_HEADER_VALUE];
};

uint32_t fgfc_abi(void);
const char *fgfc_source_id(void);
int fgfc_prepare_restore(const char *uuid, int64_t retry_after, const char *last_ray);
int fgfc_export(struct fgfc_state *out, size_t size);
int fgfc_finish(void);

int fgfc_restore_pending(void);
int fgfc_install_restore(void);
int fgfc_begin_request(void);
size_t fgfc_header(const char *data, size_t size);
int fgfc_response(void *curl, long status);
void fgfc_note_memory(void);
void fgfc_dat_result(int status);
int fgfc_write_all(int fd, const void *data, size_t size);

#endif
