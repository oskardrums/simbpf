#ifndef SIMBPF_BPF_H
#define SIMBPF_BPF_H

#include <stdbool.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/filter.h>

#include "bpf_insn.h"

struct sb_bpf_cc_s {
    size_t current;
    size_t capacity;
    struct bpf_insn insns[];
};

struct sb_bpf_baton_s
{
    size_t addr;
    size_t len;
    bool complete;
    struct bpf_insn insns[];
};

struct sb_bpf_cc_s * sb_bpf__append(struct sb_bpf_cc_s * cc, struct sb_bpf_baton_s * baton);
struct sb_bpf_cc_s * sb_bpf__concat(struct sb_bpf_cc_s * cc, struct sb_bpf_cc_s * other);

void sb_bpf_cc_dump(struct sb_bpf_cc_s *);

struct sb_bpf_baton_s * sb_bpf_baton_create(size_t);
#endif
