#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include "graph.h"

int main() {
    struct graph_s * g = graph_create();
    struct vertex_s * v1 = NULL, * v2 = NULL;
    struct edge_s * e1 = NULL;
    struct edge_s * e2 = NULL;
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

    e2 = graph_edges_from_to(g,v1, v2);
    if (e2 == NULL) {
        perror("graph_edge");
        return -5;
    }

    assert(e1 == e2);

    return 0;
}
