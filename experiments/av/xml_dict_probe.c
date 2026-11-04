#include <stdio.h>
#include <string.h>
#include <libxml/dict.h>
#include <libxml/xmlversion.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>

/* ClamAVの非公開contextと混同しない、固定依存APIの上限到達対照試験。 */
int main(void)
{
#if !defined(__linux__) || !defined(__aarch64__)
    return 2;
#else
    xmlDictPtr dict;
    const xmlChar *first_failure = NULL;
    size_t index, usage_before = 0, usage_after = 0, prior_limit;
    int retry_succeeded = 0, matched;
    char name[64];
    if (strcmp(xmlParserVersion, "21309") != 0) return 2;
    dict = xmlDictCreate();
    if (dict == NULL) return 1;
    prior_limit = xmlDictSetLimit(dict, XML_MAX_DICTIONARY_LIMIT);
    (void)prior_limit;
    for (index = 0; index < 1000000; index++) {
        int length = snprintf(name, sizeof(name), "a%025zu", index);
        if (length < 0 || (size_t)length >= sizeof(name)) {
            xmlDictFree(dict);
            return 1;
        }
        first_failure = xmlDictLookup(dict, (const xmlChar *)name, length);
        if (first_failure == NULL) break;
    }
    usage_before = xmlDictGetUsage(dict);
    if (first_failure == NULL && index < 1000000) {
        /* この比較用dictだけ増やし、同一nameの失敗が上限に依存するか確認する。 */
        prior_limit = xmlDictSetLimit(dict, 4 * XML_MAX_DICTIONARY_LIMIT);
        retry_succeeded = xmlDictLookup(dict, (const xmlChar *)name, -1) != NULL;
        usage_after = xmlDictGetUsage(dict);
    } else {
        prior_limit = 0;
    }
    printf("{\"schema_version\":1,\"evidence_kind\":\"dependency_API_measurement_not_ClamAV_context\","
           "\"runtime_version\":\"%s\",\"fixed_limit\":%d,\"limit_readback\":%zu,"
           "\"comparison_only_limit\":%d,"
           "\"first_failure_index\":%zu,\"usage_before\":%zu,\"usage_after\":%zu,"
           "\"same_name_retry_with_larger_comparison_limit_succeeded\":%s,"
           "\"fixture_1000000_names_reaches_limit\":%s,\"product_enabled\":false}\n",
           xmlParserVersion, XML_MAX_DICTIONARY_LIMIT, prior_limit, 4 * XML_MAX_DICTIONARY_LIMIT, index, usage_before, usage_after,
           retry_succeeded ? "true" : "false", index < 1000000 ? "true" : "false");
    matched = first_failure == NULL && prior_limit == XML_MAX_DICTIONARY_LIMIT && retry_succeeded &&
              index < 1000000 && usage_before > XML_MAX_DICTIONARY_LIMIT && usage_after > usage_before;
    xmlDictFree(dict);
    xmlCleanupParser();
    return matched ? 0 : 1;
#endif
}
