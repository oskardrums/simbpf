#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "simbpf/graph.h"

struct sb_graph_s * sb_graph_create()
{
    struct sb_graph_s * g = (typeof(g))malloc(sizeof(*g));
    if (g == NULL) {
        perror("malloc");
        return NULL;
    }
    memset(g, 0, sizeof(*g));

    g->v = (typeof(g->v))malloc(sizeof(*g->v));
    if (g->v == NULL) {
        perror("malloc");
        free(g);
        return NULL;
    }
    memset(g->v, 0, sizeof(*g->v));

    g->e = (typeof(g->e))malloc(sizeof(*g->e));
    if (g->e == NULL) {
        perror("malloc");
        free(g);
        return NULL;
    }
    memset(g->e, 0, sizeof(*g->e));

    return g;
}


struct sb_vertex_s * sb_graph_vertex(struct sb_graph_s * g, void * weight) 
{
    struct sb_vertex_s * temp = NULL;
    struct sb_vertex_s * tail = g->v;
    while (temp = tail->next) {
        tail = temp;
    }
    tail->next = (typeof(tail->next))malloc(sizeof(*tail->next));
    if (tail->next == NULL) {
        perror("malloc");
        return NULL;
    }
    memset(tail->next, 0, sizeof(*tail->next));
    tail->next->weight = weight;
    tail->next->next = NULL;
    return tail->next;
}


struct sb_edge_s * sb_graph_edge(struct sb_graph_s * g, void * weight, struct sb_vertex_s * src, struct sb_vertex_s * dst) 
{
    struct sb_edge_s * temp = NULL;
    struct sb_edge_s * tail = g->e;
    while (temp = tail->next) {
        tail = temp;
    }
    tail->next = (typeof(tail->next))malloc(sizeof(*tail->next));
    if (tail->next == NULL) {
        perror("malloc");
        return NULL;
    }
    memset(tail->next, 0, sizeof(*tail->next));
    tail->next->weight = weight;
    tail->next->src = src;
    tail->next->dst = dst;
    tail->next->next = NULL;
    return tail->next;
}

struct sb_edge_s * sb_graph_edges_to_except_r(struct sb_graph_s * g, struct sb_vertex_s * except, struct sb_vertex_s * dst, struct sb_edge_s * r)
{
    struct sb_edge_s * temp = NULL;

    for (temp = (r ? r->next : g->e); temp != NULL; temp = temp->next) {
        if (temp->src != except && temp->dst == dst) {
            return temp;
        }
    }

    return NULL;
}

struct sb_edge_s * sb_graph_edges_to_except(struct sb_graph_s * g, struct sb_vertex_s * except, struct sb_vertex_s * dst)
{
    return sb_graph_edges_to_except_r(g, except, dst, NULL);
}

struct sb_edge_s * sb_graph_edges_from_to(struct sb_graph_s * g, struct sb_vertex_s * src, struct sb_vertex_s * dst)
{
    return sb_graph_edges_from_to_r(g, src, dst, NULL);
}

struct sb_edge_s * sb_graph_edges_from_to_r(struct sb_graph_s * g, struct sb_vertex_s * src, struct sb_vertex_s * dst, struct sb_edge_s * r)
{
    struct sb_edge_s * temp = NULL;

    for (temp = (r ? r->next : g->e); temp != NULL; temp = temp->next) {
        if (temp->src == src && temp->dst == dst) {
            return temp;
        }
    }

    return NULL;
}

struct sb_edge_s * sb_graph_edges_to_r(struct sb_graph_s * g, struct sb_vertex_s * dst, struct sb_edge_s * r)
{
    struct sb_edge_s * temp = NULL;

    for (temp = (r ? r->next : g->e); temp != NULL; temp = temp->next) {
        if (temp->dst == dst) {
            return temp;
        }
    }

    return NULL;
}

struct sb_edge_s * sb_graph_edges_to(struct sb_graph_s * g, struct sb_vertex_s * dst)
{
    return sb_graph_edges_to_r(g, dst, NULL);
}

struct sb_edge_s * sb_graph_edges_from_r(struct sb_graph_s * g, struct sb_vertex_s * src, struct sb_edge_s * r)
{
    struct sb_edge_s * temp = NULL;

    for (temp = (r ? r->next : g->e); temp != NULL; temp = temp->next) {
        if (temp->src == src) {
            return temp;
        }
    }

    return NULL;
}

struct sb_edge_s * sb_graph_edges_from(struct sb_graph_s * g, struct sb_vertex_s * src)
{
    return sb_graph_edges_from_r(g, src, NULL);
}

void sb_graph_destroy(struct sb_graph_s * g)
{
    struct sb_edge_s * e = NULL;
    struct sb_vertex_s * v = NULL;

    while (e = g->e->next) {
        g->e->next = e->next;
        free(e);
    }
    free(g->e);

    while (v = g->v->next) {
        g->v->next = v->next;
        free(v);
    }
    free(g->v);

    free(g);
}

static long depth = 0;

struct sb_bpf_cc_s * sb_graph_compile(struct sb_graph_s * g, struct sb_vertex_s * entry, struct sb_bpf_cc_s * cc)
{
    struct sb_edge_s * e = NULL;
    struct sb_vw_s * entry_w = entry->weight;
    struct sb_block_s * entry_b = entry_w->block;

    printf("sb_graph_compile: entering depth=%ld\n", depth);

    if (entry_w->set) {
        printf("been here done that\n");
        return cc;
    }

    if (cc == NULL) {
        if ((cc = sb_bpf_cc_create()) == NULL) {
            perror("sb_graph_compile: can't create compiler context");
            return NULL;
        }
        depth = 0;
    } else {
        ++depth;
    }

    printf("setting vw@%p->addr = %lu (was %lu)\n", entry_w, cc->current, entry_w->addr);
    entry_w->addr = cc->current;
    cc = sb_bpf_cc_push(cc, entry_b);
    if (cc == NULL) {
        perror("push");
        return NULL;
    }

    for (e = sb_graph_edges_from(g, entry); e != NULL; e = sb_graph_edges_from_r(g, entry, e)) {
        struct sb_ew_s * ew = e->weight;
        ew->addr = cc->current;
        if ((cc = sb_bpf_cc_push(cc, ew->block)) == NULL) {
            perror("push");
            return NULL;
        }
    }

    entry_w->set = true;

    for (e = sb_graph_edges_from(g, entry); e != NULL; e = sb_graph_edges_from_r(g, entry, e)) {
        struct sb_ew_s * ew = e->weight;
        struct sb_vw_s * dst_w = e->dst->weight;
        struct sb_edge_s * coe = NULL;

        if (!(dst_w->set)) {
            for (coe = sb_graph_edges_to_except(g, e->src, e->dst); coe != NULL; coe = sb_graph_edges_to_except_r(g, e->src, e->dst, coe)) {
                cc = sb_graph_compile(g, coe->src, cc);
                if (cc == NULL) {
                    perror("compile");
                    return NULL;
                }
            }
            cc = sb_graph_compile(g, e->dst, cc);
            if (cc == NULL) {
                perror("compile");
                return NULL;
            }
        }
        printf("fixing jump %lu->%lu (%d)\n", ew->addr, dst_w->addr, cc->insns[ew->addr].off);
        cc->insns[ew->addr].off = dst_w->addr - ew->addr - 1;
    }

    return cc;
}

