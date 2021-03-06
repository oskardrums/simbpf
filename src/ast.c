#include "simbpf/ast.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

struct prog_s * sb_prog_create()
{
    struct prog_s * p = (typeof(p)) malloc (sizeof(*p));
    if (p != NULL) {
        memset(p, 0, sizeof(*p));
    }
    return p;
}

void sb_expr_destroy(struct expr_s * e)
{
    if (e) {
        switch (e->type) {
            case EXPR_TYPE_CONST:
            case EXPR_TYPE_READ_U8:
            case EXPR_TYPE_READ_U16:
                break;
            case EXPR_TYPE_TEST:
                sb_expr_destroy(e->data.test.expr);
                sb_arm_destroy(e->data.test.arms);
                sb_expr_destroy(e->data.test.tail);
                break;
            default:
                printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
                break;
        }
        free(e);
    }
}

void sb_match_destroy(struct match_s * m)
{
    if (m) {
        sb_expr_destroy(m->expr);
        free(m);
    }
}

void sb_arm_destroy(struct arm_s * a)
{
    if (a) {
        sb_match_destroy(a->match);
        sb_expr_destroy(a->expr);
        sb_arm_destroy(a->next);
        free(a);
    }
}

void sb_prog_destroy(struct prog_s * p)
{
    if (p) {
        sb_expr_destroy(p->expr);
        free(p);
    }
}

struct prog_s * sb_prog(struct expr_s * expr)
{
    struct prog_s * p = sb_prog_create();
    if (p != NULL) {
        p->expr = expr;
    }
    return p;
}

struct expr_s * sb_expr_create(int type)
{
    struct expr_s * e = (typeof(e))malloc(sizeof(*e));
    if (e != NULL) {
        memset(e, 0, sizeof(*e));
        e->type = type;
    }
    return e;
}

struct expr_s * sb_expr_const(size_t value)
{
    struct expr_s * e = sb_expr_create(EXPR_TYPE_CONST);
    if (e != NULL) {
        e->data.value = value;
    }
    return e;
}

struct expr_s * sb_expr_read_u8(size_t offset)
{
    struct expr_s * e = sb_expr_create(EXPR_TYPE_READ_U8);
    if (e != NULL) {
        e->data.value = offset;
    }
    return e;
}
struct expr_s * sb_expr_read_u16(size_t offset)
{
    struct expr_s * e = sb_expr_create(EXPR_TYPE_READ_U16);
    if (e != NULL) {
        e->data.value = offset;
    }
    return e;
}
struct expr_s * sb_expr_test(struct expr_s * expr, struct arm_s * arms, struct expr_s * tail)
{
    struct expr_s * e = sb_expr_create(EXPR_TYPE_TEST);
    if (e != NULL) {
        e->data.test.expr = expr;
        e->data.test.arms = arms;
        e->data.test.tail = tail;
    }
    return e;
}
struct arm_s * sb_arm_create()
{
    struct arm_s * a = (typeof(a)) malloc (sizeof(*a));
    if (a != NULL) {
        memset(a, 0, sizeof(*a));
    }
    return a;
}
struct arm_s * sb_arm(struct match_s * match, struct expr_s * expr)
{
    struct arm_s * a = sb_arm_create();
    if (a != NULL) {
        a->match = match;
        a->expr = expr;
    }
    return a;
}
struct arm_s * sb_arms(struct arm_s * head, struct arm_s * new)
{
    new->next = head;
    /*
    struct arm_s *b = NULL, * a = head;
    while ((b = a) && (a = a->next));
    b->next = tail;
    */
    return new;
}

struct match_s * sb_match_create()
{
    struct match_s * m = (typeof(m)) malloc (sizeof(*m));
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
    return m;
}
struct match_s * sb_match(size_t op, struct expr_s * expr)
{
    struct match_s * m = sb_match_create();
    if (m != NULL) {
        m->op = op;
        m->expr = expr;
    }
    return m;
}


struct sb_vertex_s * sb_expr_emit_test(struct expr_s * e, struct sb_graph_s * g, struct sb_vertex_s * fallthrough_v, struct sb_vertex_s * ret_v)
{
    bool err = false;
    struct sb_vertex_s * expr_v = NULL;
    struct sb_vertex_s * store_v = NULL;
    struct arm_s * t = NULL;
    struct sb_vertex_s * tail_v = NULL;
    struct sb_vertex_s * then_v = NULL;

    struct bpf_insn store_i[] = {
        BPF_MOV64_REG(BPF_REG_X, BPF_REG_A),
    };

    struct bpf_insn load_to_then_i[] = {
        BPF_JMP_REG(0, BPF_REG_X, BPF_REG_A, 0),
    };

    if ((then_v = sb_expr_emit(e->data.test.arms->expr, g, fallthrough_v, ret_v)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;

    }

    if (fallthrough_v == NULL) {
        if (sb_graph_edge_uncond(g, then_v, ret_v) == NULL) {
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            return NULL;
        }
    }

    e->data.test.arms->then_v = then_v;
    for (t = e->data.test.arms->next; t != NULL; t = t->next) {
        if ((then_v = sb_expr_emit(t->expr, g, then_v, ret_v)) == NULL) {
            err = true;
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            goto cleanup;
        }
        t->then_v = then_v;
        if (sb_graph_edge_uncond(g, then_v, ret_v) == NULL) {
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            return NULL;
        }
    }

    if (e->data.test.tail) {
        if ((tail_v = sb_expr_emit(e->data.test.tail, g, then_v, ret_v)) == NULL) {
            err = true;
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            goto cleanup;
        }
        if (sb_graph_edge_uncond(g, tail_v, ret_v) == NULL) {
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            return NULL;
        }
    }

    for (t = e->data.test.arms; t != NULL; t = t->next) {
        if ((tail_v = sb_expr_emit(t->match->expr, g, tail_v, ret_v)) == NULL) {
            err = true;
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            goto cleanup;
        }
        load_to_then_i[0].code = BPF_JMP | BPF_OP(t->match->op) | BPF_X;
        if (sb_graph_edge_with_insns(
                        g,
                        tail_v,
                        t->then_v,
                        load_to_then_i,
                        array_sizeof(load_to_then_i))
                        == NULL)
        {
            err = true;
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            goto cleanup;
        }
    }

    if ((store_v = sb_graph_vertex_with_insns(g, store_i, array_sizeof(store_i), tail_v)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((expr_v = sb_expr_emit(e->data.test.expr, g, store_v, ret_v)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }


cleanup:
    if (err) {
        return NULL;
    }
    return expr_v;
}

struct sb_vertex_s * sb_expr_emit_const(struct expr_s * e, struct sb_graph_s * g, struct sb_vertex_s * fallthrough_v, struct sb_vertex_s * ret_v)
{
    bool err = false;
    struct sb_vertex_s * load_v = NULL;
    struct bpf_insn load_i[] = {
        BPF_MOV64_IMM(BPF_REG_A, e->data.value),
    };

    if ((load_v = sb_graph_vertex_with_insns(g, load_i, array_sizeof(load_i), fallthrough_v)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if (fallthrough_v == NULL) {
        if (sb_graph_edge_uncond(g, load_v, ret_v) == NULL) {
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            return NULL;
        }
    }

cleanup:
    if (err) {
        return NULL;
    }
    return load_v;
}

struct sb_vertex_s * sb_expr_emit_read(struct expr_s * e, struct sb_graph_s * g, struct sb_vertex_s * fallthrough_v, struct sb_vertex_s * ret_v, int bpf_size)
{
    bool err = false;
    struct sb_vertex_s * bounds_check_v = NULL;
    struct sb_vertex_s * body_v = NULL;
    struct sb_edge_s * bounds_check_to_ret_e = NULL;

    struct bpf_insn bounds_check_i[] = {
        BPF_MOV64_REG(BPF_REG_TMP, BPF_REG_8),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_TMP, e->data.value + sb__bpf_size_to_size(bpf_size))
    };
    struct bpf_insn bounds_check_to_ret_i[] = {
        BPF_JMP_REG(BPF_JGT, BPF_REG_TMP, BPF_REG_9, 0),
    };
    struct bpf_insn body_i[] = {
        BPF_LDX_MEM(bpf_size, BPF_REG_A, BPF_REG_8, e->data.value),
    };

    if ((body_v = sb_graph_vertex_with_insns(g, body_i, array_sizeof(body_i), fallthrough_v)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((bounds_check_v = sb_graph_vertex_with_insns(g, bounds_check_i, array_sizeof(bounds_check_i), body_v)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((bounds_check_to_ret_e = sb_graph_edge_with_insns(
                    g,
                    bounds_check_v,
                    ret_v,
                    bounds_check_to_ret_i, 
                    array_sizeof(bounds_check_to_ret_i)
                    )) == NULL)
    {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if (fallthrough_v == NULL) {
        if (sb_graph_edge_uncond(g, body_v, ret_v) == NULL) {
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            return NULL;
        }
    }

cleanup:
    if (err) {
        return NULL;
    }
    return bounds_check_v;
}

struct sb_vertex_s * sb_expr_emit(struct expr_s * e, struct sb_graph_s * g, struct sb_vertex_s * fallthrough_v, struct sb_vertex_s * ret_v)
{
    struct sb_vertex_s * expr_v = NULL;

    switch (e->type) {
        case EXPR_TYPE_CONST:
            expr_v = sb_expr_emit_const(e, g, fallthrough_v, ret_v);
            break;
        case EXPR_TYPE_READ_U8:
            expr_v = sb_expr_emit_read(e, g, fallthrough_v, ret_v, BPF_B);
            break;
        case EXPR_TYPE_READ_U16:
            expr_v = sb_expr_emit_read(e, g, fallthrough_v, ret_v, BPF_H);
            break;
        case EXPR_TYPE_TEST:
            expr_v = sb_expr_emit_test(e, g, fallthrough_v, ret_v);
            break;
        default:
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            return NULL;
            break;
    }

    return expr_v;
}

struct sb_graph_s * sb_prog_compile(struct prog_s * p)
{
    bool err = false;
    struct sb_graph_s * g = NULL;

    struct sb_vertex_s * prolog_v = NULL;
    struct sb_vertex_s * expr_v = NULL;
    struct sb_vertex_s * epilog_v = NULL;

    struct bpf_insn prolog_i[] = {
        BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, 0),
        BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_1, 4),
        BPF_MOV64_IMM(BPF_REG_A, XDP_DROP),
    };

    struct bpf_insn epilog_i[] = {
        BPF_EXIT_INSN(),
    };

    if ((g = sb_graph_create()) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((prolog_v = sb_graph_vertex_with_insns(g, prolog_i, array_sizeof(prolog_i), NULL)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }


    if ((epilog_v = sb_graph_vertex_with_insns(g, epilog_i, array_sizeof(epilog_i), NULL)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((expr_v = sb_expr_emit(p->expr, g, NULL, epilog_v)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    prolog_v->fallthrough = expr_v;

cleanup:
    if (err) {
        if (g != NULL) {
            sb_graph_destroy(g);
            g = NULL;
        }
    }
    return g;
}
