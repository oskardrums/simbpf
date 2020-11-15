#ifndef SIMBPF_BPF_H
#define SIMBPF_BPF_H

#include <stdbool.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/filter.h>

#include "bpf_insn.h"

#define SB_INSNS_INITIAL_CAPACITY 1024

struct sb_bpf_cc_s {
    size_t current;
    size_t capacity;
    struct bpf_insn insns[];
};

struct sb_block_s
{
    size_t len;
    struct bpf_insn insns[];
};

struct sb_bpf_cc_s * sb_bpf_cc_create(void);
void sb_bpf_cc_destroy(struct sb_bpf_cc_s *);

void sb_block_destroy(struct sb_block_s *);

struct sb_bpf_cc_s * sb_bpf_cc_push(struct sb_bpf_cc_s * cc, struct sb_block_s *);

struct sb_bpf_cc_s * sb_bpf__concat(struct sb_bpf_cc_s * cc, struct sb_bpf_cc_s * other);

void sb_bpf_cc_dump(struct sb_bpf_cc_s *);

struct sb_block_s * sb_block_create(struct bpf_insn *, size_t);

size_t sb__bpf_size_to_size(int bs);
#endif
