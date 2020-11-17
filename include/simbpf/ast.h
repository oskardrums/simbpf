#ifndef SIMBPF_AST_H
#define SIMBPF_AST_H

#include "simbpf/graph.h"

#include <stddef.h>
#include <stdint.h>

struct match_s {
    size_t op;
    struct expr_s * expr;
};

struct arm_s {
    struct match_s * match;
    struct expr_s * expr;
    struct arm_s * next;
    struct sb_vertex_s * then_v;
};

enum expr_type_e {
    EXPR_TYPE_CONST,
    EXPR_TYPE_READ_U8,
    EXPR_TYPE_READ_U16,
    EXPR_TYPE_TEST,
};

struct expr_s {
    enum expr_type_e type;
    union {
        size_t value; // argument for EXPR_TYPE_CONST, EXPR_TYPE_READ_*
        struct {      // argument for EXPR_TYPE_TEST
            struct expr_s * expr;
            struct arm_s  * arms;
            struct expr_s * tail;
        } test; 
    } data;
};

struct prog_s {
    struct expr_s * expr;
};

struct prog_s * sb_prog(struct expr_s *);
struct expr_s * sb_expr_const(size_t);
struct expr_s * sb_expr_read_u8(size_t);
struct expr_s * sb_expr_read_u16(size_t);
struct expr_s * sb_expr_test(struct expr_s *, struct arm_s *, struct expr_s *);
struct arm_s  * sb_arm(struct match_s *, struct expr_s *);
struct arm_s  * sb_arms(struct arm_s *, struct arm_s *);
struct match_s* sb_match(size_t, struct expr_s *);

void sb_expr_destroy(struct expr_s * e);
void sb_match_destroy(struct match_s * m);
void sb_arm_destroy(struct arm_s * a);
void sb_prog_destroy(struct prog_s * p);

struct sb_vertex_s * sb_arm_emit(struct arm_s * a, struct sb_graph_s * g, struct sb_vertex_s * fallthrough_v, struct sb_vertex_s * tail_v);
struct sb_vertex_s * sb_expr_emit_test(struct expr_s * e, struct sb_graph_s * g, struct sb_vertex_s * fallthrough_v, struct sb_vertex_s * ret_v);
struct sb_vertex_s * sb_expr_emit_const(struct expr_s * e, struct sb_graph_s * g, struct sb_vertex_s * fallthrough_v, struct sb_vertex_s * ret_v);
struct sb_vertex_s * sb_expr_emit_read(struct expr_s * e, struct sb_graph_s * g, struct sb_vertex_s * fallthrough_v, struct sb_vertex_s * ret_v, int bpf_size);
struct sb_vertex_s * sb_expr_emit(struct expr_s * e, struct sb_graph_s * g, struct sb_vertex_s * fallthrough_v, struct sb_vertex_s * ret_v);
struct sb_graph_s * sb_prog_compile(struct prog_s * p);
#endif
