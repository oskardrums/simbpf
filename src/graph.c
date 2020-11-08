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
