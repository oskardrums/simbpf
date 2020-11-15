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

void sb_ew_destroy(struct sb_ew_s * ew)
{
    if (ew != NULL) {
        if (ew->block != NULL) {
            sb_block_destroy(ew->block);
        }
        free(ew);
    }
}

struct sb_ew_s * sb_ew_create(struct bpf_insn * p, size_t n)
{
    struct sb_ew_s * ew = NULL;

    if ((ew =(typeof(ew))malloc(sizeof(*ew))) == NULL) {
        return NULL;
    }

    memset(ew, 0, sizeof(*ew));

    if ((ew->block = sb_block_create(p, n)) == NULL) {
        free(ew);
        return NULL;
    }

    return ew;
}

void sb_vw_destroy(struct sb_vw_s * vw)
{
    if (vw != NULL) {
        if (vw->block != NULL) {
            sb_block_destroy(vw->block);
        }
        free(vw);
    }
}

struct sb_vw_s * sb_vw_create(struct bpf_insn * p, size_t n)
{
    struct sb_vw_s * vw = NULL;

    if ((vw =(typeof(vw))malloc(sizeof(*vw))) == NULL) {
        return NULL;
    }

    memset(vw, 0, sizeof(*vw));

    if ((vw->block = sb_block_create(p, n)) == NULL) {
        free(vw);
        return NULL;
    }

    return vw;
}

struct sb_vertex_s * sb_graph_vertex(struct sb_graph_s * g, struct sb_vw_s * weight) 
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

struct sb_edge_s * sb_graph_edge(struct sb_graph_s * g, struct sb_ew_s * weight, struct sb_vertex_s * src, struct sb_vertex_s * dst) 
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
        sb_ew_destroy(e->weight);
        g->e->next = e->next;
        free(e);
    }
    free(g->e);

    while (v = g->v->next) {
        sb_vw_destroy(v->weight);
        g->v->next = v->next;
        free(v);
    }
    free(g->v);

    free(g);
}

struct sb_bpf_cc_s * sb_graph_compile(struct sb_graph_s * g, struct sb_vertex_s * entry, struct sb_bpf_cc_s * cc)
{
    struct sb_edge_s * e = NULL;
    struct sb_vertex_s * fallthrough_v = NULL;
    struct sb_vw_s * entry_w = entry->weight;
    struct sb_block_s * entry_b = entry_w->block;

    if (entry_w->set) {
        return cc;
    }

    if (cc == NULL) {
        if ((cc = sb_bpf_cc_create()) == NULL) {
            perror("sb_graph_compile: can't create compiler context");
            return NULL;
        }
    }

    entry_w->addr = cc->current;
    cc = sb_bpf_cc_push(cc, entry_b);
    if (cc == NULL) {
        perror("push");
        return NULL;
    }

    for (e = sb_graph_edges_from(g, entry); e != NULL; e = sb_graph_edges_from_r(g, entry, e)) {
        struct sb_ew_s * ew = e->weight;
        ew->addr = cc->current;
        if (ew->block->len) {
            if ((cc = sb_bpf_cc_push(cc, ew->block)) == NULL) {
                perror("push");
                return NULL;
            }
        } else {
            fallthrough_v = e->dst;
        }
    }

    entry_w->set = true;

    if (fallthrough_v && (cc = sb_graph_compile(g, fallthrough_v, cc)) == NULL) {
        perror("compile");
        return NULL;
    }

    for (e = sb_graph_edges_from(g, entry); e != NULL; e = sb_graph_edges_from_r(g, entry, e)) {
        struct sb_ew_s * ew = e->weight;
        struct sb_vw_s * dst_w = e->dst->weight;
        struct sb_edge_s * coe = NULL;

        if (e->dst == fallthrough_v) {
            continue;
        }

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

        if (ew->block->len > 0) {
            cc->insns[ew->addr].off = dst_w->addr - ew->addr - 1;
        }
    }

    return cc;
}


struct sb_vertex_s * sb_graph_vertex_with_insns(struct sb_graph_s * g, struct bpf_insn * p, size_t n)
{
    struct sb_vertex_s * v = NULL;
    struct sb_vw_s * vw = NULL;

    if ((vw = sb_vw_create(p, n)) == NULL) {
        return NULL;
    }

    if ((v = sb_graph_vertex(g, vw)) == NULL) {
        sb_vw_destroy(vw);
        return NULL;
    }

    return v;
}

struct sb_edge_s * sb_graph_edge_with_insns(struct sb_graph_s * g, struct sb_vertex_s * v1, struct sb_vertex_s * v2, struct bpf_insn * p, size_t n)
{
    struct sb_edge_s * e = NULL;
    struct sb_ew_s * ew = NULL;

    if ((ew = sb_ew_create(p, n)) == NULL) {
        return NULL;
    }

    if ((e = sb_graph_edge(g, ew, v1, v2)) == NULL) {
        sb_ew_destroy(ew);
        return NULL;
    }

    return e;
}

struct sb_edge_s * sb_graph_edge_fallthrough(struct sb_graph_s * g, struct sb_vertex_s * v1, struct sb_vertex_s * v2)
{
    return sb_graph_edge_with_insns(g, v1, v2, NULL, 0);
}

struct sb_edge_s * sb_graph_edge_uncond(struct sb_graph_s * g, struct sb_vertex_s * v1, struct sb_vertex_s * v2)
{
    struct bpf_insn is[] = {
        BPF_JMP_A(0),
    };
    return sb_graph_edge_with_insns(g, v1, v2, is, array_sizeof(is));
}

