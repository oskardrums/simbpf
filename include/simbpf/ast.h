#ifndef SIMBPF_AST_H
#define SIMBPF_AST_H

#include "simbpf/graph.h"

#include <stddef.h>
#include <stdint.h>

enum sd_ast_type_e {
    SB_AST_TYPE_ASSERT,
    SB_AST_TYPE_FUNCTION,
    SB_AST_TYPE_RETURN,
};

struct sb_ast_s {
    int type;
    union {

        struct {
            size_t offset;
            size_t size;
            uint64_t value;
            struct sb_ast_s * tail;
        } ast_assert;

        struct {
            int value;
        } ast_return;

        struct {
            struct sb_ast_s * body;
        } ast_function;

    } data;
};

struct sb_ast_s * sb_ast_create(int type);
void sb_ast_destroy(struct sb_ast_s *);

struct sb_ast_s * sb_ast_function_set_data(struct sb_ast_s * ast, struct sb_ast_s * body);
struct sb_ast_s * sb_ast_assert_set_data(struct sb_ast_s *, size_t offset, size_t size, uint64_t value, struct sb_ast_s * tail);
struct sb_ast_s * sb_ast_return_set_data(struct sb_ast_s * ast, int value);

struct sb_graph_s * sb_ast_compile(struct sb_ast_s *) __attribute__((nonnull(1)));
#endif
