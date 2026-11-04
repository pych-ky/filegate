#include <stdbool.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>
#include "libfreshclam.h"
#include "libfreshclam_internal.h"
#include "filegate_control.h"

static struct fgfc_state state;
static int prepared;
static size_t header_bytes;

uint32_t fgfc_abi(void) { return FGFC_ABI; }
const char *fgfc_source_id(void) { return "1.4.6:5853e1396777bae4d909cd3dd44f58352e7cf9b3:filegate-v1"; }

int fgfc_write_all(int fd, const void *data, size_t size)
{
    const char *bytes = data;
    while (size) {
        ssize_t count = write(fd, bytes, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        bytes += count;
        size -= (size_t)count;
    }
    return 0;
}

static int valid_uuid(const char *value)
{
    size_t i;
    if (value == NULL || strlen(value) != 36) return 0;
    for (i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return 0;
        } else if (!isxdigit((unsigned char)value[i])) return 0;
    }
    return value[14] == '4' && strchr("89abAB", value[19]) != NULL;
}

int fgfc_prepare_restore(const char *uuid, int64_t retry_after, const char *last_ray)
{
    size_t i;
    if (prepared || g_freshclamDat != NULL || !valid_uuid(uuid) ||
        retry_after < 0 || retry_after > INT64_C(253402300799) ||
        last_ray == NULL || strlen(last_ray) > CFRAY_LEN) return -1;
    for (i = 0; last_ray[i]; i++) {
        if ((unsigned char)last_ray[i] < 32 || (unsigned char)last_ray[i] > 126) return -1;
    }
    memset(&state, 0, sizeof(state));
    state.abi = FGFC_ABI;
    state.retry_after = state.max_retry_after = retry_after;
    memcpy(state.uuid, uuid, 37);
    memcpy(state.last_ray, last_ray, strlen(last_ray));
    prepared = 1;
    return 0;
}

int fgfc_restore_pending(void) { return prepared; }

int fgfc_install_restore(void)
{
    time_t now = time(NULL);
    if (!prepared || state.initialized || g_freshclamDat != NULL || sizeof(time_t) != 8) return -1;
    if (now < 0 || (int64_t)now > INT64_C(253402300799)) return -1;
    g_freshclamDat = calloc(1, sizeof(*g_freshclamDat));
    if (g_freshclamDat == NULL) return -1;
    g_freshclamDat->version = 1;
    memcpy(g_freshclamDat->uuid, state.uuid, sizeof(g_freshclamDat->uuid));
    g_freshclamDat->retry_after = (time_t)state.retry_after;
    memcpy(g_lastRay, state.last_ray, sizeof(g_lastRay));
    state.initialized = 1;
    state.blocked = state.retry_after > (int64_t)now;
    return 0;
}

void fgfc_note_memory(void)
{
    if (prepared && state.initialized && g_freshclamDat != NULL) {
        state.retry_after = (int64_t)g_freshclamDat->retry_after;
        if (state.retry_after > state.max_retry_after) state.max_retry_after = state.retry_after;
        memcpy(state.last_ray, g_lastRay, sizeof(state.last_ray));
    }
}

int fgfc_begin_request(void)
{
    if (!prepared) return 1;
    fgfc_note_memory();
    if (state.final || state.invalid || state.blocked || !state.initialized) return 0;
    if (state.retry_after > (int64_t)time(NULL)) {
        state.blocked = 1;
        return 0;
    }
    state.request_count++;
    header_bytes = 0;
    state.http_status = 0;
    state.response_utc = 0;
    state.wait_seconds = 0;
    state.retry_after_raw[0] = state.date_raw[0] = 0;
    return 1;
}

static int header_value(char *destination, const char *value, size_t length)
{
    size_t i;
    while (length && (*value == ' ' || *value == '\t')) { value++; length--; }
    while (length && (value[length - 1] == '\r' || value[length - 1] == '\n' ||
                      value[length - 1] == ' ' || value[length - 1] == '\t')) length--;
    if (length == 0 || length >= FGFC_HEADER_VALUE || destination[0]) return 0;
    for (i = 0; i < length; i++) {
        if ((unsigned char)value[i] < 32 || (unsigned char)value[i] > 126) return 0;
    }
    memcpy(destination, value, length);
    destination[length] = 0;
    return 1;
}

size_t fgfc_header(const char *data, size_t size)
{
    if (!prepared) return size;
    if (state.invalid || size > 16384 || header_bytes > 16384 - size) {
        state.invalid = 1;
        return 0;
    }
    header_bytes += size;
    if (size >= 12 && !memcmp(data, "HTTP/", 5)) {
        const char *space = memchr(data, ' ', size);
        if (space == NULL || space + 4 > data + size ||
            !isdigit((unsigned char)space[1]) || !isdigit((unsigned char)space[2]) ||
            !isdigit((unsigned char)space[3])) { state.invalid = 1; return 0; }
        state.http_status = (space[1] - '0') * 100 + (space[2] - '0') * 10 + space[3] - '0';
        state.retry_after_raw[0] = state.date_raw[0] = 0;
        if (state.http_status == 403 || state.http_status == 429) state.blocked = 1;
    } else if (size > 12 && !strncasecmp(data, "Retry-After:", 12)) {
        if (!header_value(state.retry_after_raw, data + 12, size - 12)) state.invalid = 1;
    } else if (size > 5 && !strncasecmp(data, "Date:", 5)) {
        if (!header_value(state.date_raw, data + 5, size - 5)) state.invalid = 1;
    }
    return state.invalid ? 0 : size;
}

static int raw_retry_wait(int64_t *wait)
{
    const char *value = state.retry_after_raw;
    const char *cursor = value;
    int64_t seconds = 0;
    time_t date;
    if (!*value) { *wait = 0; return 0; }
    while (isdigit((unsigned char)*cursor)) cursor++;
    if (!*cursor) {
        while (*value) {
            int digit = *value++ - '0';
            if (seconds > (INT64_C(253402300799) - digit) / 10) return -1;
            seconds = seconds * 10 + digit;
        }
    } else {
        date = curl_getdate(value, NULL);
        if (date < 0 || (int64_t)date > INT64_C(253402300799)) return -1;
        if ((int64_t)date > state.response_utc) seconds = (int64_t)date - state.response_utc;
    }
    *wait = seconds;
    return 0;
}

int fgfc_response(void *handle, long status)
{
    curl_off_t wait = 0;
    int64_t raw_wait = 0;
    if (!prepared) return 0;
    state.response_count++;
    state.http_status = (int32_t)status;
    state.response_utc = (int64_t)time(NULL);
    if (state.blocked && status != 403 && status != 429) { state.invalid = 1; return -1; }
    if (curl_easy_getinfo((CURL *)handle, CURLINFO_RETRY_AFTER, &wait) != CURLE_OK || wait < 0 ||
        state.response_utc < 0 || state.response_utc > INT64_C(253402214399) ||
        wait > INT64_C(253402300799) - state.response_utc) { state.invalid = 1; return -1; }
    if (status == 429 || status == 403) {
        state.blocked = 1;
        /* CURLINFO_RETRY_AFTERの内部上限で配布元の長い禁止期間を短縮しない。 */
        if (raw_retry_wait(&raw_wait) != 0 || raw_wait > INT64_C(253402300799) - state.response_utc) {
            state.invalid = 1;
            return -1;
        }
        if (raw_wait > wait) wait = (curl_off_t)raw_wait;
        state.wait_seconds = status == 403 ? (wait > 86400 ? (int64_t)wait : 86400) :
                                             (wait > 0 ? (int64_t)wait : 14400);
        if (state.response_utc + state.wait_seconds > state.max_retry_after)
            state.max_retry_after = state.response_utc + state.wait_seconds;
    }
    return state.invalid ? -1 : 0;
}

void fgfc_dat_result(int status)
{
    if (!prepared) return;
    state.dat_save_attempts++;
    if (status != FC_SUCCESS) state.dat_save_failures++;
    fgfc_note_memory();
}

int fgfc_finish(void)
{
    if (!prepared || !state.initialized) return -1;
    fgfc_note_memory();
    state.final = 1;
    return state.invalid ? -1 : 0;
}

int fgfc_export(struct fgfc_state *out, size_t size)
{
    if (!prepared || size != sizeof(state) || out == NULL) return -1;
    fgfc_note_memory();
    memcpy(out, &state, sizeof(state));
    return 0;
}
