#ifndef SIMBPF_BPF_H
#define SIMBPF_BPF_H

#include <linux/bpf.h>
#include <linux/filter.h>

#include "bpf_insn.h"
#include "simbpf/graph.h"

#define SB_GRAPH_INITIAL_CAPACITY 1024

struct sb_bpf_cc_s {
    size_t current;
    size_t capacity;
    struct bpf_insn insns[];
};

struct sb_bpf_baton_s
{
    size_t addr;
    size_t len;
    struct bpf_insn insns[];
};

struct sb_bpf_cc_s * sb_bpf_compile_graph(struct sb_graph_s * g, struct sb_vertex_s * entry) __attribute__((nonnull(1,2)));

void sb_bpf_cc_dump(struct sb_bpf_cc_s *);

#endif
