#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "graph.h"

struct graph_s * graph_create()
{
    struct graph_s * g = (typeof(g))malloc(sizeof(*g));
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
    g->e = (typeof(g->e))malloc(sizeof(*g->e));
    if (g->e == NULL) {
        perror("malloc");
        free(g);
        return NULL;
    }
    return g;
}


struct vertex_s * graph_vertex(struct graph_s * g, void * weight) 
{
    struct vertex_s * temp = NULL;
    struct vertex_s * tail = g->v;
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


struct edge_s * graph_edge(struct graph_s * g, void * weight, struct vertex_s * src, struct vertex_s * dst) 
{
    struct edge_s * temp = NULL;
    struct edge_s * tail = g->e;
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


struct edge_s * graph_edges_from_to_r(struct graph_s * g, struct vertex_s * src, struct vertex_s * dst, struct edge_s * r)
{
    (void)g;
    (void)src;
    (void)dst;
    (void)r;
    return NULL;
}

struct edge_s * graph_edges_from_to(struct graph_s * g, struct vertex_s * src, struct vertex_s * dst)
{
    struct edge_s * temp = NULL;

    for (temp = g->e; temp != NULL; temp = temp->next) {
        if (temp->src == src && temp->dst == dst) {
            return temp;
        }
    }

    return NULL;
}
