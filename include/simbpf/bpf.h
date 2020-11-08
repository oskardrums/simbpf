#ifndef SIMBPF_BPF_H
#define SIMBPF_BPF_H

#include <linux/bpf.h>
#include <linux/filter.h>

#include "bpf_insn.h"
#include "graph.h"

#define INITIAL_CAPACITY 1024

struct bpf_cc_s {
    size_t current;
    size_t capacity;
    struct bpf_insn insns[];
};

struct bpf_baton_s
{
    size_t addr;
    size_t len;
    struct bpf_insn insns[];
};

struct bpf_cc_s * bpf_compile_graph(struct graph_s * g, struct vertex_s * entry) __attribute__((nonnull(1,2)));

void bpf_cc_dump(struct bpf_cc_s *);

#endif