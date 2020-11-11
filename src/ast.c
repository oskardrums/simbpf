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
    struct sb_vertex_s * prolog = NULL;
    struct sb_vertex_s * body = NULL;
    struct sb_vertex_s * epilog = NULL;
    struct sb_edge_s * prolog_to_body = NULL;
    struct sb_bpf_baton_s * prolog_baton = NULL; 
    struct sb_bpf_baton_s * epilog_baton = NULL; 
    struct sb_bpf_baton_s * prolog_to_body_baton = NULL; 

    prolog_baton = sb_bpf_baton_create(3);
    if (prolog_baton == NULL) {
        return NULL;
    }
    prolog_baton->insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, 0);
    prolog_baton->insns[1] = BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_1, 4);
    prolog_baton->insns[2] = BPF_MOV64_IMM(BPF_REG_0, XDP_DROP);

    prolog = sb_graph_vertex(g, prolog_baton);
    if (prolog == NULL) {
        free(prolog_baton);
        return NULL;
    }

    epilog_baton = sb_bpf_baton_create(1);
    if (epilog_baton == NULL) {
        free(prolog_baton);
        return NULL;
    }
    epilog_baton->insns[0] = BPF_EXIT_INSN();

    epilog = sb_graph_vertex(g, epilog_baton);
    if (epilog == NULL) {
        free(prolog_baton);
        free(epilog_baton);
        return NULL;
    }

    body = sb_ast__compile_recurse(ast->data.ast_function.body, g, epilog);
    if (body == NULL) {
        free(prolog_baton);
        free(epilog_baton);
        return NULL;
    }

    prolog_to_body_baton = sb_bpf_baton_create(1);
    if (prolog_to_body_baton == NULL) {
        free(prolog_baton);
        free(epilog_baton);
        return NULL;
    }
    prolog_to_body_baton->insns[0] = BPF_JMP_A(0);

    prolog_to_body = sb_graph_edge(g, prolog_to_body_baton, prolog, body);
    if (prolog_to_body == NULL) {
        free(prolog_baton);
        free(epilog_baton);
        free(prolog_to_body_baton);
        return NULL;
    }

    return prolog;
}

struct sb_vertex_s * sb_ast__emit_return(struct sb_ast_s * ast, struct sb_graph_s * g, struct sb_vertex_s * ret)
{
    bool err = false;
    struct sb_vertex_s * load = NULL;
    struct sb_edge_s * load_to_ret = NULL;
    struct sb_bpf_baton_s * load_baton = NULL; 
    struct sb_bpf_baton_s * load_to_ret_baton = NULL; 
    
    if ((load_baton = sb_bpf_baton_create(1)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }
    load_baton->insns[0] = BPF_MOV64_IMM(BPF_REG_0, ast->data.ast_return.value);

    if ((load = sb_graph_vertex(g, load_baton)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((load_to_ret_baton = sb_bpf_baton_create(1)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }
    load_to_ret_baton->insns[0] = BPF_JMP_A(0);

    if ((load_to_ret = sb_graph_edge(g, load_to_ret_baton, load, ret)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

cleanup:
    if (err) {
        if (load_baton != NULL) {
            free(load_baton);
        }
        if (load_to_ret_baton != NULL) {
            free(load_to_ret_baton);
        }
    }
    return load;
}


struct sb_vertex_s * sb_graph_vertex_with_insns(struct sb_graph_s * g, struct bpf_insn * p, size_t n)
{
    size_t i;
    struct sb_vertex_s * v = NULL;
    struct sb_bpf_baton_s * b = NULL;
    if ((b = sb_bpf_baton_create(n)) == NULL) {
        return NULL;
    }

    for (i = 0; i < n; ++i) {
        b->insns[i] = p[i];
    }

    if ((v = sb_graph_vertex(g, b)) == NULL) {
        free(b);
        return NULL;
    }

    return v;
}

struct sb_edge_s * sb_graph_edge_with_insns(struct sb_graph_s * g, struct sb_vertex_s * v1, struct sb_vertex_s * v2, struct bpf_insn * p, size_t n)
{
    size_t i;
    struct sb_edge_s * e = NULL;
    struct sb_bpf_baton_s * b = NULL;
    if ((b = sb_bpf_baton_create(n)) == NULL) {
        return NULL;
    }

    for (i = 0; i < n; ++i) {
        b->insns[i] = p[i];
    }

    if ((e = sb_graph_edge(g, b, v1, v2)) == NULL) {
        free(b);
        return NULL;
    }

    return e;
}

struct sb_edge_s * sb_graph_edge_uncond(struct sb_graph_s * g, struct sb_vertex_s * v1, struct sb_vertex_s * v2)
{
    struct sb_edge_s * e = NULL;
    struct sb_bpf_baton_s * b = NULL;
    if ((b = sb_bpf_baton_create(1)) == NULL) {
        return NULL;
    }

    b->insns[0] = BPF_JMP_A(0);

    if ((e = sb_graph_edge(g, b, v1, v2)) == NULL) {
        free(b);
        return NULL;
    }

    return e;
}

#define array_sizeof(x) sizeof((x))/sizeof((x)[0])
struct sb_vertex_s * sb_ast__emit_assert(struct sb_ast_s * ast, struct sb_graph_s * g, struct sb_vertex_s * ret)
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
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, ast->data.ast_assert.offset + ast->data.ast_assert.size)
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

    if ((bounds_check_to_ret_e = sb_graph_edge_with_insns(
                    g,
                    bounds_check_v,
                    ret,
                    bounds_check_to_ret_i, 
                    sizeof(bounds_check_to_ret_i)/sizeof(bounds_check_to_ret_i[0])
                    )) == NULL)
    {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((bounds_check_to_body_e = sb_graph_edge_uncond(g, bounds_check_v, body_v)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }


    if ((tail = sb_ast__compile_recurse(ast->data.ast_assert.tail, g, ret)) != NULL) {
        printf("dddddddd\n");
        if ((body_to_tail_e = sb_graph_edge_uncond(g, body_v, tail)) == NULL) {
            err = true;
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            goto cleanup;
        }
    } else {
        printf("eeeeeeee\n");
    }

    if ((body_to_tail_e = sb_graph_edge_uncond(g, body_v, tail)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((body_to_ret_e = sb_graph_edge_with_insns(g, body_v, ret, body_to_ret_i, array_sizeof(body_to_ret_i))) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

cleanup:
    if (err) {
        return NULL;
    }
    return bounds_check_v;
}

struct sb_vertex_s * sb_ast__compile_recurse(struct sb_ast_s * ast, struct sb_graph_s * g, struct sb_vertex_s * ret) {
    if (ast == NULL) {
        return NULL;
    }

    switch (ast->type) {
        case SB_AST_TYPE_FUNCTION:
            return sb_ast__emit_function(ast, g);
            break;
        case SB_AST_TYPE_ASSERT:
            return sb_ast__emit_assert(ast, g, ret);
            break;
        case SB_AST_TYPE_RETURN:
            return sb_ast__emit_return(ast, g, ret);
            break;
        default:
            return NULL;
            break;
    }
}

struct sb_graph_s * sb_ast_compile(struct sb_ast_s * ast) {
    bool err = false;
    struct sb_vertex_s * func = NULL;
    struct sb_graph_s * g = NULL;


    if ((g = sb_graph_create()) == NULL) {
        err = true;
        goto cleanup;
    }

    if ((func = sb_ast__compile_recurse(ast, g, NULL)) == NULL) {
        err = true;
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
