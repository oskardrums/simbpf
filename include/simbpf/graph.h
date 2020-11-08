#ifndef SIMBPF_GRAPH_H
#define SIMBPF_GRAPH_H

#define def_list(node)         \
struct node##_list_s             \
{                              \
    struct node##_s * curr;      \
    struct node##_list_s * next; \
}


def_list(vertex);
def_list(edge);

struct vertex_s
{
    void * weight;
    struct vertex_s * next;
};

struct edge_s
{
    void * weight;
    struct vertex_s * src;
    struct vertex_s * dst;
    struct edge_s * next;
};

struct graph_s
{
    struct vertex_s * v;
    struct edge_s * e;
};

struct graph_s * graph_create();
void graph_destroy(struct graph_s * g) __attribute__((nonnull));
struct vertex_s * graph_vertex(struct graph_s * g, void * weight) __attribute__((nonnull(1)));
struct edge_s * graph_edge(struct graph_s * g, void * weight, struct vertex_s * src, struct vertex_s * dst) __attribute__((nonnull(1, 3, 4)));
struct edge_s * graph_edges_from_to(struct graph_s * g, struct vertex_s * src, struct vertex_s * dst) __attribute__((nonnull(1, 2, 3)));
struct edge_s * graph_edges_from_to_r(struct graph_s * g, struct vertex_s * src, struct vertex_s * dst, struct edge_s * r) __attribute__((nonnull(1, 2, 3)));
struct edge_s * graph_edges_from(struct graph_s * g, struct vertex_s * src) __attribute__((nonnull(1, 2)));
struct edge_s * graph_edges_from_r(struct graph_s * g, struct vertex_s * src, struct edge_s * r) __attribute__((nonnull(1, 2)));
#endif
