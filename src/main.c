#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/filter.h>
#include "bpf.h"
#include "graph.h"

int main()
{
    struct graph_s * g = NULL;
    struct vertex_s * v1 = NULL;
    struct vertex_s * v2 = NULL;
    struct edge_s * e1 = NULL;
//    struct edge_s * e2 = NULL;
    struct edge_s * e3 = NULL;
//    struct edge_s * e4 = NULL;
//    struct edge_s * e5 = NULL;

    struct bpf_baton_s * baton = (typeof(baton))malloc(sizeof(*baton) + sizeof(baton->insns[0]) * 1);
    if (baton == NULL) {
        perror("malloc");
        return 1;
    }
    memset(baton, 0, sizeof(*baton) + sizeof(baton->insns[0]) * 1);
    baton->len = 1;
    baton->insns[0] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);

    struct bpf_baton_s * v2baton = (typeof(baton))malloc(sizeof(*baton) + sizeof(baton->insns[0]) * 2);
    if (v2baton == NULL) {
        perror("malloc");
        return 1;
    }
    memset(v2baton, 0, sizeof(*baton) + sizeof(baton->insns[0]) * 2);
    v2baton->len = 2;
    v2baton->insns[0] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0);
    v2baton->insns[1] = BPF_EXIT_INSN();


    struct bpf_baton_s * e1baton = (typeof(baton))malloc(sizeof(*baton) + sizeof(baton->insns[0]) * 1);
    if (e1baton == NULL) {
        perror("malloc");
        return 1;
    }
    memset(e1baton, 0, sizeof(*baton) + sizeof(baton->insns[0]) * 1);
    e1baton->len = 1;
    e1baton->insns[0] = BPF_JMP_IMM(BPF_JA, BPF_REG_0, 0, 0);

    g = graph_create();
    if (g == NULL) {
        perror("graph_create");
        return -1;
    }

    v1 = graph_vertex(g, baton);
    if (v1 == NULL) {
        perror("graph_vertex");
        return -2;
    }

    v2 = graph_vertex(g, v2baton);
    if (v2 == NULL) {
        perror("graph_vertex");
        return -3;
    }

    e1 = graph_edge(g, e1baton, v1, v2);
    if (e1 == NULL) {
        perror("graph_edge");
        return -4;
    }
/*
    e2 = graph_edge(g, NULL, v1, v2);
    if (e2 == NULL) {
        perror("graph_edge");
        return -5;
    }
*/
    e3 = graph_edges_from_to(g, v1, v2);
    if (e3 == NULL) {
        perror("graph_edge");
        return -6;
    }
    assert(e1 == e3);
/*
    e4 = graph_edges_from_to_r(g, v1, v2, e3);
    if (e4 == NULL) {
        perror("graph_edge");
        return -7;
    }
    assert(e2 == e4);
    e5 = graph_edges_from_to_r(g, v1, v2, e4);
    assert(e5 == NULL);
*/


    struct bpf_cc_s * result = bpf_compile_graph(g, v1);
    bpf_cc_dump(result);
    free(result);
    free(baton);
    free(e1baton);
    free(v2baton);

    graph_destroy(g);

    return 0;
}
