#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include "graph.h"


int main()
{
    struct graph_s * g = graph_create();
    struct vertex_s * v1 = NULL
    struct vertex_s * v2 = NULL;
    struct edge_s * e1 = NULL;
    struct edge_s * e2 = NULL;
    struct edge_s * e3 = NULL;
    struct edge_s * e4 = NULL;
    struct edge_s * e5 = NULL;

    if (g == NULL) {
        perror("graph_create");
        return -1;
    }

    v1 = graph_vertex(g, NULL);
    if (v1 == NULL) {
        perror("graph_vertex");
        return -2;
    }

    v2 = graph_vertex(g, NULL);
    if (v2 == NULL) {
        perror("graph_vertex");
        return -3;
    }

    e1 = graph_edge(g, NULL, v1, v2);
    if (e1 == NULL) {
        perror("graph_edge");
        return -4;
    }

    e2 = graph_edge(g, NULL, v1, v2);
    if (e2 == NULL) {
        perror("graph_edge");
        return -5;
    }

    e3 = graph_edges_from_to(g, v1, v2);
    if (e3 == NULL) {
        perror("graph_edge");
        return -6;
    }
    assert(e1 == e3);

    e4 = graph_edges_from_to_r(g, v1, v2, e3);
    if (e4 == NULL) {
        perror("graph_edge");
        return -7;
    }
    assert(e2 == e4);

    e5 = graph_edges_from_to_r(g, v1, v2, e4);
    assert(e5 == NULL);

    graph_destroy(g);

    return 0;
}
