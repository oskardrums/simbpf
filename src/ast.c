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

    prolog_baton = sb_bpf_baton_create(1);
    if (prolog_baton == NULL) {
        return NULL;
    }
    prolog_baton->insns[0] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);

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

struct sb_vertex_s * sb_ast__emit_assert(struct sb_ast_s * ast, struct sb_graph_s * g, struct sb_vertex_s * ret)
{
    bool err = false;
    struct sb_vertex_s * load = NULL;
    struct sb_vertex_s * tail = NULL;
    struct sb_edge_s * load_to_tail = NULL;
    struct sb_edge_s * load_to_ret = NULL;
    struct sb_bpf_baton_s * load_baton = NULL; 
    struct sb_bpf_baton_s * load_to_tail_baton = NULL; 
    struct sb_bpf_baton_s * load_to_ret_baton = NULL; 
    
    if ((load_baton = sb_bpf_baton_create(1)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }
    load_baton->insns[0] = BPF_LD_ABS(ast->data.ast_assert.size, ast->data.ast_assert.offset);

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
    load_to_ret_baton->insns[0] = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, ast->data.ast_assert.value, 0);

    if ((load_to_ret = sb_graph_edge(g, load_to_ret_baton, load, ret)) == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    if ((tail = sb_ast__compile_recurse(ast->data.ast_assert.tail, g, ret)) != NULL) {
        if ((load_to_tail_baton = sb_bpf_baton_create(1)) == NULL) {
            err = true;
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            goto cleanup;
        }
        load_to_tail_baton->insns[0] = BPF_JMP_A(0);

        if ((load_to_tail = sb_graph_edge(g, load_to_tail_baton, load, tail)) == NULL) {
            err = true;
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            goto cleanup;
        }
    }

cleanup:
    if (err) {
        if (load_baton != NULL) {
            free(load_baton);
        }
        if (load_to_tail_baton != NULL) {
            free(load_to_tail_baton);
        }
        if (load_to_ret_baton != NULL) {
            free(load_to_ret_baton);
        }
    }
    return load;
}

struct sb_vertex_s * sb_ast__compile_recurse(struct sb_ast_s * ast, struct sb_graph_s * g, struct sb_vertex_s * ret) {
    if (ast == NULL) {
        return NULL;
    }

    switch (ast->type) {
        case SB_AST_TYPE_ASSERT:
            return sb_ast__emit_assert(ast, g, ret);
            break;
        case SB_AST_TYPE_FUNCTION:
            return sb_ast__emit_function(ast, g);
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
