/* 診断ランだけで既存libxmlの属性走査とHTML正規化結果を観測する。 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libxml/xmlreader.h>

static xmlTextReaderPtr active_reader;
static unsigned visited;

__attribute__((constructor)) static void loaded(void)
{
    fprintf(stderr, "FILEGATE_REMAINING_OBSERVER loaded=1\n");
}

static void *original(const char *name)
{
    void *symbol = dlsym(RTLD_NEXT, name);
    if (!symbol) {
        fprintf(stderr, "FILEGATE_REMAINING_OBSERVER failure=missing_symbol\n");
        _exit(120);
    }
    return symbol;
}

int xmlTextReaderMoveToNextAttribute(xmlTextReaderPtr reader)
{
    int (*next)(xmlTextReaderPtr) = original("xmlTextReaderMoveToNextAttribute");
    int result = next(reader);
    if (active_reader != reader) {
        active_reader = reader;
        visited = 0;
    }
    if (result == 1)
        visited++;
    return result;
}

int xmlTextReaderMoveToElement(xmlTextReaderPtr reader)
{
    int (*move)(xmlTextReaderPtr) = original("xmlTextReaderMoveToElement");
    int result = move(reader);
    if (active_reader == reader && visited) {
        fprintf(stderr, "FILEGATE_REMAINING_XML_ATTR visited=%u available=%d\n",
                visited, xmlTextReaderAttributeCount(reader));
        visited = 0;
    }
    return result;
}

void *cl_base64_decode(char *data, size_t length, void *buffer, size_t *decoded_length, int oneline)
{
    void *(*decode)(char *, size_t, void *, size_t *, int) = original("cl_base64_decode");
    void *result = decode(data, length, buffer, decoded_length, oneline);
    const char marker[] = "FileGate benign boundary marker.";
    size_t size = result && decoded_length ? *decoded_length : 0;
    fprintf(stderr, "FILEGATE_REMAINING_XML_BASE64 bytes=%zu marker=%d\n", size,
            result && size == sizeof(marker) - 1 && memcmp(result, marker, sizeof(marker) - 1) == 0);
    return result;
}

bool html_normalise_map(void *ctx, void *map, const char *directory, void *hrefs, const void *dconf)
{
    bool (*normalize)(void *, void *, const char *, void *, const void *) = original("html_normalise_map");
    bool result = normalize(ctx, map, directory, hrefs, dconf);
    char path[4096], body[8193];
    int length = snprintf(path, sizeof(path), "%s/notags.html", directory);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        fprintf(stderr, "FILEGATE_REMAINING_OBSERVER failure=path_bound\n");
        return result;
    }
    FILE *file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "FILEGATE_REMAINING_OBSERVER failure=normal_output_missing\n");
        return result;
    }
    size_t size = fread(body, 1, sizeof(body) - 1, file);
    int extra = fgetc(file);
    int failed = ferror(file);
    fclose(file);
    if (failed || extra != EOF) {
        fprintf(stderr, "FILEGATE_REMAINING_OBSERVER failure=normal_output_bound\n");
        return result;
    }
    body[size] = '\0';
    size_t run = 0, longest = 0;
    for (size_t i = 0; i < size; i++) {
        run = body[i] == 'A' ? run + 1 : 0;
        if (run > longest)
            longest = run;
    }
    fprintf(stderr, "FILEGATE_REMAINING_HTML bytes=%zu longest_A=%zu tail=%d\n",
            size, longest, strstr(body, "ZZBOUNDARYZZ x") != NULL);
    return result;
}
