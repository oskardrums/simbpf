#ifndef SIMBPF_GRAPH_H
#define SIMBPF_GRAPH_H

#include "simbpf/bpf.h"

struct sb_vw_s
{
    bool set;
    size_t addr;
    struct sb_block_s * block;
};

struct sb_vertex_s
{
    struct sb_vw_s * weight;
    struct sb_vertex_s * next;
};

struct sb_ew_s
{
    size_t addr;
    struct sb_block_s * block;
};

struct sb_edge_s
{
    struct sb_ew_s * weight;
    struct sb_vertex_s * src;
    struct sb_vertex_s * dst;
    struct sb_edge_s * next;
};

struct sb_graph_s
{
    struct sb_vertex_s * v;
    struct sb_edge_s * e;
};

struct sb_graph_s * sb_graph_create();

void sb_graph_destroy(struct sb_graph_s * g) __attribute__((nonnull));

struct sb_vertex_s * sb_graph_vertex(struct sb_graph_s * g, void * weight) __attribute__((nonnull(1)));

struct sb_edge_s * sb_graph_edge(struct sb_graph_s * g, void * weight, struct sb_vertex_s * src, struct sb_vertex_s * dst) __attribute__((nonnull(1, 3, 4)));

struct sb_edge_s * sb_graph_edges_from_to(struct sb_graph_s * g, struct sb_vertex_s * src, struct sb_vertex_s * dst) __attribute__((nonnull(1, 2, 3)));

struct sb_edge_s * sb_graph_edges_from_to_r(struct sb_graph_s * g, struct sb_vertex_s * src, struct sb_vertex_s * dst, struct sb_edge_s * r) __attribute__((nonnull(1, 2, 3)));

struct sb_edge_s * sb_graph_edges_to_except(struct sb_graph_s * g, struct sb_vertex_s * except, struct sb_vertex_s * dst) __attribute__((nonnull(1, 2, 3)));

struct sb_edge_s * sb_graph_edges_to_except_r(struct sb_graph_s * g, struct sb_vertex_s * except, struct sb_vertex_s * dst, struct sb_edge_s * r) __attribute__((nonnull(1, 2, 3)));

struct sb_edge_s * sb_graph_edges_from(struct sb_graph_s * g, struct sb_vertex_s * src) __attribute__((nonnull(1, 2)));

struct sb_edge_s * sb_graph_edges_from_r(struct sb_graph_s * g, struct sb_vertex_s * src, struct sb_edge_s * r) __attribute__((nonnull(1, 2)));

struct sb_edge_s * sb_graph_edges_to(struct sb_graph_s * g, struct sb_vertex_s * src) __attribute__((nonnull(1, 2)));

struct sb_edge_s * sb_graph_edges_to_r(struct sb_graph_s * g, struct sb_vertex_s * src, struct sb_edge_s * r) __attribute__((nonnull(1, 2)));

struct sb_bpf_cc_s * sb_graph_compile(struct sb_graph_s * g, struct sb_vertex_s * entry, struct sb_bpf_cc_s *) __attribute__((nonnull(1,2)));

#endif
