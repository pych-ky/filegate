#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <libxml/parser.h>
#include <libxml/dict.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlversion.h>

/* 診断ランだけで採用readerの返値と既存errorを観測し、入力や設定を変更しない。 */
static _Thread_local unsigned reader_depth;
static _Thread_local int name_limit_seen;

/* 2.13.9の固定ソースに対応する先頭部分を、診断時だけ読み取る。 */
struct reader_prefix {
    int mode;
    xmlDocPtr doc;
    int validate, allocs, state;
    xmlParserCtxtPtr ctxt;
};
struct dict_pool {
    struct dict_pool *next;
    xmlChar *free, *end;
    size_t size, count;
};
struct dict_layout {
    int references;
    void *table;
    size_t size;
    unsigned count;
    struct dict_pool *strings;
    xmlDictPtr subdict;
    unsigned seed;
    size_t limit;
};
_Static_assert(offsetof(struct reader_prefix, ctxt) == 32, "fixed ARM64 reader layout");
_Static_assert(offsetof(struct dict_layout, limit) == 56, "fixed ARM64 dictionary layout");

static void record_dictionary(xmlTextReaderPtr reader)
{
    struct reader_prefix prefix;
    struct dict_layout dict;
    struct dict_pool *next;
    xmlParserCtxtPtr ctxt;
    const xmlChar *name;
    size_t usage = 0, available = 0, pools = 0;
    unsigned i;
    memcpy(&prefix, reader, sizeof(prefix));
    ctxt = prefix.ctxt;
    if (!ctxt || !ctxt->dict || !ctxt->input ||
        ctxt->input->cur - ctxt->input->base < 26) return;
    name = ctxt->input->cur - 26;
    if (name[0] != 'a') return;
    for (i = 1; i < 26; ++i) if (name[i] < '0' || name[i] > '9') return;
    if (*ctxt->input->cur != '/' || xmlDictExists(ctxt->dict, name, 26) != NULL) return;
    memcpy(&dict, ctxt->dict, sizeof(dict));
    for (next = dict.strings; next; ) {
        struct dict_pool pool;
        if (++pools > 32) return;
        memcpy(&pool, next, sizeof(pool));
        if (pool.end < pool.free) return;
        if ((size_t)(pool.end - pool.free) > available) available = pool.end - pool.free;
        usage += pool.size;
        next = pool.next;
    }
    if (dict.limit == 10000000 && usage == xmlDictGetUsage(ctxt->dict) &&
        usage > dict.limit && available <= 26 && dict.subdict == NULL &&
        dict.count + 1 <= dict.size / 8 * 7) {
        fprintf(stderr, "FILEGATE_XML_OBSERVER failure=xml-dictionary limit=%zu usage=%zu max_free=%zu count=%u table=%zu pools=%zu pending_name_length=26 resize_required=0\n",
                dict.limit, usage, available, dict.count, dict.size, pools);
    }
}

static void emit_error(const char *kind, const xmlError *error)
{
    fprintf(stderr, "FILEGATE_XML_OBSERVER failure=%s code=%d domain=%d\n", kind, error->code, error->domain);
}

int xmlCopyError(const xmlError *from, xmlErrorPtr to)
{
    int (*original)(const xmlError *, xmlErrorPtr) = dlsym(RTLD_NEXT, "xmlCopyError");
    int result;
    if (original == NULL) _exit(2);
    result = original(from, to);
    if (result == 0 && reader_depth && from != NULL && from->domain == XML_FROM_PARSER &&
        from->code == XML_ERR_NAME_TOO_LONG && !name_limit_seen) {
        name_limit_seen = 1;
        emit_error("xml-name-size", from);
    }
    return result;
}

static void record_failure(xmlTextReaderPtr reader, int result)
{
    const xmlError *error;
    const char *kind = "unclassified";
    if (result != -1) return;
    error = xmlTextReaderGetLastError(reader);
    if (error == NULL) return;
    if (error->code == XML_ERR_NO_MEMORY) {
        kind = "xml-parser-memory";
        record_dictionary(reader);
    }
    else if (error->domain == XML_FROM_PARSER && error->code == XML_ERR_NAME_REQUIRED && name_limit_seen)
        kind = "xml-name-size-followup";
    else if (error->message == NULL) kind = "unclassified";
    else if (strstr(error->message, "Text node too long")) kind = "xml-text-size";
    else if (strstr(error->message, "Name too long")) kind = "xml-name-size";
    else if (strstr(error->message, "Excessive depth")) kind = "xml-element-depth";
    else if (strstr(error->message, "Maximum entity nesting depth exceeded")) kind = "xml-entity-depth";
    else if (strstr(error->message, "Maximum entity amplification factor exceeded")) kind = "xml-entity-amplification";
    else if (strstr(error->message, "Buffer size limit exceeded")) kind = "xml-lookup-size";
    emit_error(kind, error);
}

__attribute__((constructor)) static void identify(void)
{
#if !defined(__linux__) || !defined(__aarch64__)
    _exit(2);
#else
    if (strcmp(xmlParserVersion, "21309") != 0) _exit(2);
    fputs("FILEGATE_XML_OBSERVER loaded=21309\n", stderr);
#endif
}

int xmlTextReaderRead(xmlTextReaderPtr reader)
{
    int (*original)(xmlTextReaderPtr) = dlsym(RTLD_NEXT, "xmlTextReaderRead");
    int result;
    if (original == NULL) _exit(2);
    if (reader_depth++ == 0) name_limit_seen = 0;
    result = original(reader);
    record_failure(reader, result);
    reader_depth--;
    return result;
}

int xmlTextReaderNext(xmlTextReaderPtr reader)
{
    int (*original)(xmlTextReaderPtr) = dlsym(RTLD_NEXT, "xmlTextReaderNext");
    int result;
    if (original == NULL) _exit(2);
    if (reader_depth++ == 0) name_limit_seen = 0;
    result = original(reader);
    record_failure(reader, result);
    reader_depth--;
    return result;
}
