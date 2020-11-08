#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "simbpf/bpf.h"

struct bpf_cc_s * bpf__concat(struct bpf_cc_s * cc, struct bpf_cc_s * other)
{
    size_t capacity = cc->capacity;
    if (other != NULL) {
        while (other->current > (cc->capacity - cc->current)) capacity <<= 1;
        if (capacity > cc->capacity) {
            cc = (typeof(cc))realloc(cc, sizeof(*cc) + sizeof(cc->insns[0]) * capacity);
            if (cc == NULL) {
                perror("realloc");
                return NULL;
            }
        }
        memcpy(&(cc->insns[cc->current]), other->insns, other->current*sizeof(other->insns[0]));
        cc->current += other->current;
    }
    return cc;
}

struct bpf_cc_s * bpf__append(struct bpf_cc_s * cc, struct bpf_baton_s * baton)
{
    size_t capacity = cc->capacity;
    bpf_cc_dump(cc);
    if (baton != NULL) {
        while (baton->len > (cc->capacity - cc->current)) capacity <<= 1;
        if (capacity > cc->capacity) {
            cc = (typeof(cc))realloc(cc, sizeof(*cc) + sizeof(cc->insns[0]) * capacity);
            if (cc == NULL) {
                perror("realloc");
                return NULL;
            }
        }
        memcpy(&(cc->insns[cc->current]), baton->insns, baton->len*sizeof(baton->insns[0]));
        cc->current += baton->len;
    }
    return cc;
}

struct bpf_cc_s * bpf_compile_graph(struct graph_s * g, struct vertex_s * entry)
{
    struct edge_s * e = NULL;
    struct bpf_baton_s * entry_baton = entry->weight;
    struct bpf_cc_s * cc = (typeof(cc))malloc(sizeof(*cc) + sizeof(cc->insns[0]) * INITIAL_CAPACITY);
    if (cc == NULL) {
        perror("malloc");
        return NULL;
    }
    memset(cc, 0, sizeof(*cc) + sizeof(cc->insns[0]) * INITIAL_CAPACITY);
    cc->capacity = INITIAL_CAPACITY;

    entry_baton->addr = cc->current;
    cc = bpf__append(cc, entry_baton);
    if (cc == NULL) {
        perror("append");
        return NULL;
    }

    for (e = graph_edges_from(g, entry); e != NULL; e = graph_edges_from_r(g, entry, e)) {
        printf("loop1\n");
        struct bpf_baton_s * dst_baton = e->dst->weight;
        struct bpf_baton_s * e_baton = e->weight;

        e_baton->addr = cc->current;

        if (dst_baton->addr != 0) {
            e_baton->insns[0].off = dst_baton->addr - e_baton->addr;
        }

        cc = bpf__append(cc, e->weight);
        if (cc == NULL) {
            perror("append");
            return NULL;
        }
    }

    for (e = graph_edges_from(g, entry); e != NULL; e = graph_edges_from_r(g, entry, e)) {
        printf("loop2\n");
        struct bpf_cc_s * sub_cc = NULL;
        struct bpf_baton_s * e_baton = e->weight;
        struct bpf_baton_s * src_baton = e->src->weight;

        if (cc->insns[e_baton->addr].off == 0) {
            cc->insns[e_baton->addr].off = cc->current - src_baton->addr;
            sub_cc = bpf_compile_graph(g, e->dst);
            if (sub_cc == NULL) {
                perror("compile");
                return NULL;
            }
            cc = bpf__concat(cc, sub_cc);
            free(sub_cc);
            if (cc == NULL) {
                perror("concat");
                return NULL;
            }
        }
    }

    return cc;
}

void bpf_cc_dump(struct bpf_cc_s * cc) {
    printf("%lu/%lu\n", cc->current, cc->capacity);
    for (size_t i = 0; i < cc->current; i++) {
        struct bpf_insn * o = &cc->insns[cc->current];
        printf("0x%02x, %u, %u, %d, %d\n", o->code, o->dst_reg, o->src_reg, o->off, o->imm);
    }
}
