#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "simbpf/bpf.h"

struct sb_block_s * sb_block_create(struct bpf_insn * p, size_t n)
{
    struct sb_block_s * b = (typeof(b))malloc(sizeof(*b) + sizeof(b->insns[0]) * n);
    if (b == NULL) {
        return NULL;
    }
    
    memset(b->insns, 0, sizeof(*b) + sizeof(b->insns[0]) * (n - 1));
    b->len = n;
    memcpy(b->insns, p, sizeof(b->insns[0]) * n);

    return b;
}

void sb_block_destroy(struct sb_block_s * b)
{
    if (b != NULL) {
        free(b);
    }
}

struct sb_bpf_cc_s * sb_bpf_cc_create()
{
    struct sb_bpf_cc_s * cc = (typeof(cc))malloc(sizeof(*cc) + sizeof(cc->insns[0]) * SB_INSNS_INITIAL_CAPACITY);
    if (cc == NULL) {
        perror("sb_bpf_cc_create: malloc failed");
        return NULL;
    }
    memset(cc, 0, sizeof(*cc) + sizeof(cc->insns[0]) * SB_INSNS_INITIAL_CAPACITY);
    cc->capacity = SB_INSNS_INITIAL_CAPACITY;
    return cc;
}

void sb_bpf_cc_destroy(struct sb_bpf_cc_s * cc)
{
    if (cc != NULL) {
        free(cc);
    }
}

struct sb_bpf_cc_s * sb_bpf_cc_push(struct sb_bpf_cc_s * cc, struct sb_block_s * block)
{
    size_t capacity = cc->capacity;
    if (block != NULL) {
        while (block->len > (cc->capacity - cc->current)) capacity <<= 1;
        if (capacity > cc->capacity) {
            cc = (typeof(cc))realloc(cc, sizeof(*cc) + sizeof(cc->insns[0]) * capacity);
            if (cc == NULL) {
                perror("realloc");
                return NULL;
            }
        }
        memcpy(&(cc->insns[cc->current]), block->insns, block->len*sizeof(block->insns[0]));
        cc->current += block->len;
    }
    return cc;
}


void sb_bpf_cc_dump(struct sb_bpf_cc_s * cc) {
    printf("%lu/%lu\n", cc->current, cc->capacity);
    for (size_t i = 0; i < cc->current; i++) {
        struct bpf_insn o = cc->insns[i];
        printf("%lu:\t0x%02x, %u, %u, %d, %d\n", i, o.code, o.dst_reg, o.src_reg, o.off, o.imm);
    }
}


size_t sb__bpf_size_to_size(int bs)
{
    switch (bs) {
        case BPF_B:
            return 1;
            break;
        case BPF_H:
            return 2;
            break;
        case BPF_W:
            return 4;
            break;
        case BPF_DW:
            return 8;
            break;
        default:
            return 0;
            break;
    }
}
