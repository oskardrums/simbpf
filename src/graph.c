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

struct sb_edge_s * sb_graph_edges_from_to(struct sb_graph_s * g, struct sb_vertex_s * src, struct sb_vertex_s * dst)
{
    return sb_graph_edges_from_to_r(g, src, dst, NULL);
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

struct sb_bpf_cc_s * sb_bpf_cc_create()
{
    struct sb_bpf_cc_s * cc = (typeof(cc))malloc(sizeof(*cc) + sizeof(cc->insns[0]) * SB_GRAPH_INITIAL_CAPACITY);
    if (cc == NULL) {
        perror("malloc");
        return NULL;
    }
    memset(cc, 0, sizeof(*cc) + sizeof(cc->insns[0]) * SB_GRAPH_INITIAL_CAPACITY);
    cc->capacity = SB_GRAPH_INITIAL_CAPACITY;
    return cc;
}

static long depth = 0;

struct sb_bpf_cc_s * sb_graph_compile(struct sb_graph_s * g, struct sb_vertex_s * entry, struct sb_bpf_cc_s * cc)
{
    struct sb_edge_s * e = NULL;
    struct sb_bpf_baton_s * entry_baton = entry->weight;

    printf("sb_graph_compile: entering depth=%ld\n", depth);

    if (entry_baton->complete) {
        printf("been here done that\n");
        return cc;
    }

    if (cc == NULL) {
        if ((cc = sb_bpf_cc_create()) == NULL) {
            perror("sb_graph_compile: can't create compiler context: malloc failed");
            return NULL;
        }
        depth = 0;
    } else {
        ++depth;
    }

    printf("setting baton->addr = %lu (was %lu)\n", cc->current, entry_baton->addr);
    entry_baton->addr = cc->current;
    cc = sb_bpf__append(cc, entry_baton);
    if (cc == NULL) {
        perror("append");
        return NULL;
    }

    for (e = sb_graph_edges_from(g, entry); e != NULL; e = sb_graph_edges_from_r(g, entry, e)) {
        struct sb_bpf_baton_s * e_baton = e->weight;
            printf("edge loop1\n");

        e_baton->addr = cc->current;
        if ((cc = sb_bpf__append(cc, e_baton)) == NULL) {
            perror("append");
            return NULL;
        }
    }

    for (e = sb_graph_edges_from(g, entry); e != NULL; e = sb_graph_edges_from_r(g, entry, e)) {
    //    struct sb_bpf_cc_s * sub_cc = NULL;
        struct sb_bpf_baton_s * e_baton = e->weight;
        struct sb_bpf_baton_s * dst_baton = e->dst->weight;
            printf("edge loop2\n");

        if (dst_baton->complete) {
            printf("THIS shit happend\n");
        } else {
            cc = sb_graph_compile(g, e->dst, cc);
            if (cc == NULL) {
                perror("compile");
                return NULL;
            }
        }
        printf("that shit happend %lu->%lu (%d)\n", e_baton->addr, dst_baton->addr, e_baton->insns[0].off);
        cc->insns[e_baton->addr].off = dst_baton->addr - e_baton->addr - 1;
        e_baton->complete = true;
        /*
        if (!(e_baton->complete)) {
            printf("that shit happend %lu->%lu\n", e_baton->addr, cc->current);
            cc->insns[e_baton->addr].off = cc->current - e_baton->addr - 1;
            e_baton->complete = true;
            cc = sb_graph_compile(g, e->dst, cc);
            if (cc == NULL) {
                perror("compile");
                return NULL;
            }
  //          cc = sb_bpf__concat(cc, sub_cc);
  //          free(sub_cc);
  //          if (cc == NULL) {
  //              perror("concat");
  //              return NULL;
  //          }
        }
        */
    }

    entry_baton->complete = true;

    return cc;
}

