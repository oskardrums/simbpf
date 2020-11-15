#include "simbpf.h"
#include "grammar.h"
#include "lexicon.h"
#include <assert.h>

struct sb_bpf_cc_s * sb_parse_and_compile()
{
    void * scanner = NULL;
    struct sb_bpf_cc_s * b = NULL;
    struct prog_s * p = NULL;
    struct sb_graph_s * g = NULL;
    yylex_init(&scanner);
    if (yyparse(&p, scanner) == 0) {
        assert(p);
        if ((g = sb_prog_compile(p)) != NULL) {
            b = sb_graph_compile(g, g->v->next, NULL);
            sb_graph_destroy(g);
            sb_prog_destroy(p);
            yylex_destroy(scanner);
            return b;
        }
    }
    return NULL;
}

