/* 診断ランで元の戻り値を保ち、固定sourceの型登録結果とFSGサイズ判定を読む。 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

struct matched_type {
    struct matched_type *next;
    off_t offset;
    int type;
    unsigned short count;
};
_Static_assert(sizeof(struct matched_type) == 24, "fixed ARM64 matched-type ABI");
_Static_assert(sizeof(off_t) == 8 && offsetof(struct matched_type, offset) == 8, "fixed ARM64 offset ABI");
_Static_assert(offsetof(struct matched_type, type) == 16, "fixed ARM64 file-type offset");
_Static_assert(offsetof(struct matched_type, count) == 20, "fixed ARM64 count offset");

static void *original(const char *name)
{
    void *symbol = dlsym(RTLD_NEXT, name);
    if (!symbol) {
        fprintf(stderr, "FILEGATE_ROUTE_OBSERVER failure=missing_symbol\n");
        _exit(120);
    }
    return symbol;
}

__attribute__((constructor)) static void loaded(void)
{
    fprintf(stderr, "FILEGATE_ROUTE_OBSERVER loaded=1\n");
}

int cli_checklimits(const char *who, void *ctx, uint64_t one, uint64_t two, uint64_t three)
{
    int (*check)(const char *, void *, uint64_t, uint64_t, uint64_t) = original("cli_checklimits");
    int result = check(who, ctx, one, two, three);
    if (who && !strcmp(who, "cli_scanpe: FSG"))
        fprintf(stderr, "FILEGATE_ROUTE_FSG requested=%llu blocked=%d result=%d\n", (unsigned long long)one, result != 0, result);
    if (who && !strcmp(who, "cli_scanpe: UPX"))
        fprintf(stderr, "FILEGATE_ROUTE_UPX requested=%llu blocked=%d result=%d\n", (unsigned long long)one, result != 0, result);
    return result;
}

int cli_ac_scanbuff(const unsigned char *buffer, uint32_t length, const char **name, void **custom,
                   void *results, const void *root, void *data, uint32_t offset, int type,
                   struct matched_type **matches, unsigned mode, void *ctx)
{
    int (*scan)(const unsigned char *, uint32_t, const char **, void **, void *, const void *, void *,
                uint32_t, int, struct matched_type **, unsigned, void *) = original("cli_ac_scanbuff");
    int result = scan(buffer, length, name, custom, results, root, data, offset, type, matches, mode, ctx);
    if (type == 506 && offset == 0 && matches && *matches) {
        unsigned nodes = 0;
        off_t last = 0;
        struct matched_type *node = *matches;
        while (node && nodes < 32 && node->type == 506) {
            nodes++;
            last = node->offset;
            node = node->next;
        }
        if (!node)
            fprintf(stderr, "FILEGATE_ROUTE_TYPES bytes=%u nodes=%u count=%u last=%lld\n",
                    length, nodes, (*matches)->count, (long long)last);
    }
    return result;
}
