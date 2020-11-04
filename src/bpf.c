#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "bpf.h"

struct bpf_cc_s * bpf__append(struct bpf_cc_s * cc, struct bpf_baton_s * baton)
{
    size_t capacity = cc->capacity;
    if (baton != NULL) {
        while (baton->length > (cc->capacity - cc->current)) capacity <<= 1;
        if (capacity > cc->capacity) {
            cc = (typeof(cc))realloc(cc, sizeof(*cc) + sizeof(cc->insns[0]) * capacity);
            if (cc == NULL) {
                perror("realloc");
                return NULL;
            }
        }
        memcpy(&(cc->insns[cc->current]), baton->insns, baton->length*sizeof(baton->insns[0]));
        cc->current += baton->length;
    }
    return cc;
}

struct bpf_cc_s * bpf_compile_graph(struct graph_s * g, struct vertex_s * entry)
{
    struct bpf_cc_s * cc = (typeof(cc))malloc(sizeof(*cc) + sizeof(cc->insns[0]) * INITIAL_CAPACITY);
    if (cc == NULL) {
        perror("malloc");
        return NULL;
    }
    memset(cc, 0, sizeof(*cc) + sizeof(cc->insns[0]) * INITIAL_CAPACITY);
    cc->capacity = INITIAL_CAPACITY;

    cc = bpf__append(cc, entry->weight);
    if (cc == NULL) {
        perror("append");
        return NULL;
    }

    struct edge_s * e = NULL;
    for (e = graph_edges_from(g, entry); e != NULL; e = graph_edges_from_r(g, entry, e)) {
        printf("%p %p %p %p\n", entry, e, e->src, e->next);
    }

    return cc;
}
