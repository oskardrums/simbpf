#ifndef SIMBPF_GRAPH_H
#define SIMBPF_GRAPH_H
/*
#define def_list(node)         \
struct node##_list_s             \
{                              \
    struct node##_s * curr;      \
    struct node##_list_s * next; \
}


def_list(vertex);
def_list(edge);
*/

struct sb_vertex_s
{
    void * weight;
    struct sb_vertex_s * next;
};

struct sb_edge_s
{
    void * weight;
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
struct sb_edge_s * sb_graph_edges_from(struct sb_graph_s * g, struct sb_vertex_s * src) __attribute__((nonnull(1, 2)));
struct sb_edge_s * sb_graph_edges_from_r(struct sb_graph_s * g, struct sb_vertex_s * src, struct sb_edge_s * r) __attribute__((nonnull(1, 2)));
#endif
