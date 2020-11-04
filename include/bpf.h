#ifndef GRAPH_BPF_H
#define GRAPH_BPF_H

#include <linux/bpf.h>
#include <linux/filter.h>

#include "bpf_insn.h"
#include "graph.h"

struct bpf_insn_baton
{
    size_t length;
    struct bpf_insn insns[];
};

int bpf_compile_graph(struct graph_s * g, struct vertex_s * entry, struct bpf_insn ** output) __attribute__((nonnull(1,2)));
#endif
