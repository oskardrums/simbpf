#ifndef SIMBPF_AST_H
#define SIMBPF_AST_H

#include "simbpf/graph.h"

#include <stddef.h>
#include <stdint.h>

enum sd_ast_type_e {
    SB_AST_TYPE_ASSERT,
};

struct sb_ast_s {
    int type;
    union {
        struct {
            size_t offset;
            size_t size;
            uint64_t value;
        } ast_assert;

        struct {
            size_t value;
        } ast_return;
    } data;
};

struct sb_ast_s * sb_ast_create(void);
void sb_ast_destroy(struct sb_ast_s *);

struct sb_ast_s * sb_ast_set_type(struct sb_ast_s *, int type);
struct sb_ast_s * sb_ast_assert_set_data(struct sb_ast_s *, size_t offset, size_t size, uint64_t value);

struct sb_graph_s * sb_ast_compile(struct sb_ast_s *) __attribute__((nonnull(1)));
#endif
