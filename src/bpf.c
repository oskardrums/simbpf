#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "simbpf/bpf.h"

struct sb_bpf_cc_s * sb_bpf__concat(struct sb_bpf_cc_s * cc, struct sb_bpf_cc_s * other)
{
    size_t capacity = cc->capacity;
    if (other != NULL) {
        while (other->current > (cc->capacity - cc->current)) capacity <<= 1;
        if (capacity > cc->capacity) {
            cc = (typeof(cc))realloc(cc, sizeof(*cc) + sizeof(cc->insns[0]) * capacity);
            if (cc == NULL) {
                perror("realloc");
                return NULL;
            }
        }
        memcpy(&(cc->insns[cc->current]), other->insns, other->current*sizeof(other->insns[0]));
        printf("updating current %lu + %lu = ", cc->current, other->current);
        cc->current += other->current;
        printf("%lu\n", cc->current);
    }
    return cc;
}

struct sb_bpf_cc_s * sb_bpf__append(struct sb_bpf_cc_s * cc, struct sb_bpf_baton_s * baton)
{
    size_t capacity = cc->capacity;
    if (baton != NULL) {
        while (baton->len > (cc->capacity - cc->current)) capacity <<= 1;
        if (capacity > cc->capacity) {
            cc = (typeof(cc))realloc(cc, sizeof(*cc) + sizeof(cc->insns[0]) * capacity);
            if (cc == NULL) {
                perror("realloc");
                return NULL;
            }
        }
        memcpy(&(cc->insns[cc->current]), baton->insns, baton->len*sizeof(baton->insns[0]));
        printf("updating current %lu + %lu = ", cc->current, baton->len);
        cc->current += baton->len;
        printf("%lu\n", cc->current);
        for (size_t i = 0; i < baton->len; ++i) {
            struct bpf_insn o = baton->insns[i];
            printf("%lu: 0x%02x, %u, %u, %d, %d\n", cc->current - 1, o.code, o.dst_reg, o.src_reg, o.off, o.imm);
        }
    }
    return cc;
}


void sb_bpf_cc_dump(struct sb_bpf_cc_s * cc) {
    printf("%lu/%lu\n", cc->current, cc->capacity);
    for (size_t i = 0; i < cc->current; i++) {
        struct bpf_insn o = cc->insns[i];
        printf("%lu: 0x%02x, %u, %u, %d, %d\n", i, o.code, o.dst_reg, o.src_reg, o.off, o.imm);
    }
}

struct sb_bpf_baton_s * sb_bpf_baton_create(size_t len) {
    struct sb_bpf_baton_s * baton = (typeof(baton))malloc(sizeof(*baton) + sizeof(baton->insns[0]) * len);
    if (baton != NULL) {
        memset(baton, 0, sizeof(*baton) + sizeof(baton->insns[0]) * len);
        baton->len = len;
    }
    return baton;
}
