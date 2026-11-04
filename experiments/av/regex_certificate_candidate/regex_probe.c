#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "regex.h"
#include "utils.h"
#include "regex2.h"

int main(void)
{
    for (int extended = 0; extended <= 1; extended++) {
        for (int count = 100; count <= 102; count++) {
            char pattern[512], literal[128];
            strcpy(pattern, extended ? "^()" : "^\\(\\)");
            for (int index = 0; index < count; index++)
                strcat(pattern, "\\1");
            strcat(pattern, "x$");
            memset(literal, '1', count);
            strcpy(literal + count, "x");
            regex_t compiled = {0};
            int error = cli_regcomp_real(&compiled, pattern, REG_NOSUB | (extended ? REG_EXTENDED : 0));
            if (error)
                return 2;
            int opcodes = 0;
            for (sopno index = 0; index < compiled.re_g->nstates; index++)
                opcodes += OP(compiled.re_g->strip[index]) == OBACK_;
            int empty = cli_regexec(&compiled, "x", 0, NULL, 0);
            int digits = cli_regexec(&compiled, literal, 0, NULL, 0);
            printf("{\"syntax\":\"%s\",\"references\":%d,\"backrefs\":%d,\"OBACK_opcodes\":%d,\"empty_match_code\":%d,\"literal_match_code\":%d}\n",
                   extended ? "ERE" : "BRE", count, compiled.re_g->backrefs, opcodes, empty, digits);
            cli_regfree(&compiled);
        }
    }
    return 0;
}
