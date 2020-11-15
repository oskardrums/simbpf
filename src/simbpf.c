#include "simbpf.h"
#include "grammar.h"
#include <assert.h>

struct sb_bpf_cc_s * sb_parse_and_compile()
{
    struct prog_s * p = NULL;
    struct sb_graph_s * g = NULL;
    if (yyparse(&p) == 0) {
        assert(p);
        if ((g = sb_prog_compile(p)) != NULL) {
            return sb_graph_compile(g, g->v->next, NULL);
        }
    }
    return NULL;
}

