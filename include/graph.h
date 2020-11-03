#ifndef GRAPH_H
#define GRAPH_H

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
struct vertex_s * graph_vertex(struct graph_s * g, void * weight) __attribute__((nonnull(1)));
#endif
