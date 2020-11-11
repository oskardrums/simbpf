#include "simbpf/ast.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

struct sb_vertex_s * sb_ast__compile_recurse(struct sb_ast_s * ast, struct sb_graph_s * g, struct sb_vertex_s * ret);

struct sb_ast_s * sb_ast_create(int type)
{
    struct sb_ast_s * ast = (typeof(ast))malloc(sizeof(*ast));
    if (ast != NULL) {
        ast->type = type;
    }
    return ast;
}

struct sb_ast_s * sb_ast_return_set_data(struct sb_ast_s * ast, int value)
{
    assert(ast->type == SB_AST_TYPE_RETURN);
    ast->data.ast_return.value = value;
    return ast;
}

struct sb_ast_s * sb_ast_function_set_data(struct sb_ast_s * ast, struct sb_ast_s * body)
{
    assert(ast->type == SB_AST_TYPE_FUNCTION);
    ast->data.ast_function.body = body;
    return ast;
}

struct sb_ast_s * sb_ast_assert_set_data(struct sb_ast_s * ast, size_t offset, size_t size, uint64_t value, struct sb_ast_s * tail)
{
    assert(ast->type == SB_AST_TYPE_ASSERT);
    ast->data.ast_assert.offset = offset;
    ast->data.ast_assert.size = size;
    ast->data.ast_assert.value = value;
    ast->data.ast_assert.tail = tail;
    return ast;
}

void sb_ast_destroy(struct sb_ast_s * ast)
{
    if (ast != NULL) {
        free(ast);
    }
}

struct sb_vertex_s * sb_ast__emit_function(struct sb_ast_s * ast, struct sb_graph_s * g)
{
    bool err = false;

    struct sb_vertex_s * prolog_v = NULL;
    struct sb_vertex_s * body_v = NULL;
    struct sb_vertex_s * epilog = NULL;
    struct sb_edge_s * prolog_to_body_e = NULL;

    struct bpf_insn prolog_i[] = {
        BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, 0),
        BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_1, 4),
        BPF_MOV64_IMM(BPF_REG_0, XDP_DROP),
    };

    struct bpf_insn epilog_i[] = {
        BPF_EXIT_INSN(),
    };

    if ((prolog_v = sb_graph_vertex_with_insns(g, prolog_i, array_sizeof(prolog_i))) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((epilog = sb_graph_vertex_with_insns(g, epilog_i, array_sizeof(epilog_i))) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((body_v = sb_ast__compile_recurse(ast->data.ast_function.body, g, epilog)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((prolog_to_body_e = sb_graph_edge_uncond(g, prolog_v, body_v)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

cleanup:
    if (err) {
        return NULL;
    }

    return prolog_v;
}

struct sb_vertex_s * sb_ast__emit_return(struct sb_ast_s * ast, struct sb_graph_s * g, struct sb_vertex_s * ret_v)
{
    bool err = false;
    struct sb_vertex_s * load_v = NULL;
    struct sb_edge_s * load_to_ret_e = NULL;

    struct bpf_insn load_i[] = {
        BPF_MOV64_IMM(BPF_REG_0, ast->data.ast_return.value),
    };

    if ((load_v = sb_graph_vertex_with_insns(g, load_i, array_sizeof(load_i))) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((load_to_ret_e = sb_graph_edge_uncond(g, load_v, ret_v)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

cleanup:
    if (err) {
        return NULL;
    }
    return load_v;
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

struct sb_vertex_s * sb_ast__emit_assert(struct sb_ast_s * ast, struct sb_graph_s * g, struct sb_vertex_s * ret_v)
{
    bool err = false;
    struct sb_vertex_s * bounds_check_v = NULL;
    struct sb_vertex_s * body_v = NULL;
    struct sb_vertex_s * tail = NULL;
    struct sb_edge_s * bounds_check_to_ret_e = NULL;
    struct sb_edge_s * bounds_check_to_body_e = NULL;
    struct sb_edge_s * body_to_tail_e = NULL;
    struct sb_edge_s * body_to_ret_e = NULL;


    struct bpf_insn bounds_check_i[] = {
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_8),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, ast->data.ast_assert.offset + sb__bpf_size_to_size(ast->data.ast_assert.size))
    };
    struct bpf_insn body_i[] = {
        BPF_LDX_MEM(ast->data.ast_assert.size, BPF_REG_3, BPF_REG_8, ast->data.ast_assert.offset),
    };
    struct bpf_insn bounds_check_to_ret_i[] = {
        BPF_JMP_REG(BPF_JGT, BPF_REG_3, BPF_REG_9, 0),
    };
    struct bpf_insn body_to_ret_i[] = {
        BPF_JMP_IMM(BPF_JGT, BPF_REG_3, ast->data.ast_assert.value, 0),
    };
    if ((bounds_check_v = sb_graph_vertex_with_insns(g, bounds_check_i, array_sizeof(bounds_check_i))) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((body_v = sb_graph_vertex_with_insns(g, body_i, array_sizeof(body_i))) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((bounds_check_to_body_e = sb_graph_edge_fallthrough(g, bounds_check_v, body_v)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }


    if ((bounds_check_to_ret_e = sb_graph_edge_with_insns(
                    g,
                    bounds_check_v,
                    ret_v,
                    bounds_check_to_ret_i, 
                    sizeof(bounds_check_to_ret_i)/sizeof(bounds_check_to_ret_i[0])
                    )) == NULL)
    {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((tail = sb_ast__compile_recurse(ast->data.ast_assert.tail, g, ret_v)) != NULL) {
        if ((body_to_tail_e = sb_graph_edge_fallthrough(g, body_v, tail)) == NULL) {
            err = true;
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            goto cleanup;
        }
    }
    /*
    } else {
    }


    if ((body_to_tail_e = sb_graph_edge_uncond(g, body_v, tail)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }
*/
    if ((body_to_ret_e = sb_graph_edge_with_insns(g, body_v, ret_v, body_to_ret_i, array_sizeof(body_to_ret_i))) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

cleanup:
    if (err) {
        return NULL;
    }
    printf("sb_ast__emit_assert: bounds_check_v is still %p\n", bounds_check_v);
    return bounds_check_v;
}

struct sb_vertex_s * sb_ast__compile_recurse(struct sb_ast_s * ast, struct sb_graph_s * g, struct sb_vertex_s * ret) {

    if (ast == NULL) {
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    switch (ast->type) {
        case SB_AST_TYPE_FUNCTION:
            printf("sb_ast__compile_recurse: SB_AST_TYPE_FUNCTION\n");
            return sb_ast__emit_function(ast, g);
            break;
        case SB_AST_TYPE_ASSERT:
            printf("sb_ast__compile_recurse: SB_AST_TYPE_ASSERT\n");
            return sb_ast__emit_assert(ast, g, ret);
            break;
        case SB_AST_TYPE_RETURN:
            printf("sb_ast__compile_recurse: SB_AST_TYPE_RETURN\n");
            return sb_ast__emit_return(ast, g, ret);
            break;
        default:
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            goto cleanup;
            break;
    }

cleanup:
    return NULL;
}

struct sb_graph_s * sb_ast_compile(struct sb_ast_s * ast) {
    bool err = false;
    struct sb_vertex_s * func = NULL;
    struct sb_graph_s * g = NULL;


    if ((g = sb_graph_create()) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((func = sb_ast__compile_recurse(ast, g, NULL)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

cleanup:
    if (err) {
        if (g != NULL) {
            sb_graph_destroy(g);
            g = NULL;
        }
    }

    return g;
}
