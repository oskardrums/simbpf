#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "bpf.h"

int bpf_compile_graph(struct graph_s * g, struct vertex_s * entry, struct bpf_insn ** output)
{
    struct bpf_insn_baton * baton = NULL;
    size_t current = 0;
    size_t capacity = 1024;
    struct bpf_insn * result = NULL;

    baton = (typeof(baton))entry->weight;

    while (baton->length > capacity - current) capacity <<= 1;
    result = (typeof(result))calloc(sizeof(*result), capacity);
    if (result == NULL) {
        perror("malloc");
        return -1;
    }

    memcpy(result, baton->insns, baton->length*sizeof(baton->insns[0]));
    current += baton->length;

    struct edge_s * e = NULL;
    for (e = graph_edges_from(g, entry); e != NULL; e = graph_edges_from_r(g, entry, e)) {
        printf("%p %p %p %p\n", entry, e, e->src, e->next);
    }


    if (output != NULL) {
        *output = result;
    }

    return current;
}
