#include "simbpf/ast.h"
#include <stdlib.h>
#include <assert.h>

struct sb_ast_s * sb_ast_create()
{
    struct sb_ast_s * ast = (typeof(ast))malloc(sizeof(*ast));
    if (ast == NULL) {
        return NULL;
    }
    return ast;
}

struct sb_ast_s * sb_ast_set_type(struct sb_ast_s * ast, int type)
{
    ast->type = type;
    return ast;
}

struct sb_ast_s * sb_ast_assert_set_data(struct sb_ast_s * ast, size_t offset, size_t size, uint64_t value)
{
    assert(ast->type == SB_AST_TYPE_ASSERT);
    ast->data.ast_assert.offset = offset;
    ast->data.ast_assert.size = size;
    ast->data.ast_assert.value = value;
    return ast;
}

void sb_ast_destroy(struct sb_ast_s * ast)
{
    if (ast != NULL) {
        free(ast);
    }
}

struct sb_vertex_s * sb_ast__emit_assert(struct sb_ast_s * ast, struct sb_graph_s * g, struct sb_vertex_s * fail)
{
    struct sb_vertex_s * v1 = NULL;
    struct sb_bpf_baton_s * load_baton = NULL; //sb_bpf_baton_create(1);
    struct sb_edge_s * e1 = NULL;
    struct sb_bpf_baton_s * edge_baton = NULL; //sb_bpf_baton_create(1);
    
    load_baton = sb_bpf_baton_create(1);
    if (load_baton == NULL) {
        return NULL;
    }
    load_baton->insns[0] = BPF_LD_ABS(ast->data.ast_assert.size, ast->data.ast_assert.offset);

    edge_baton = sb_bpf_baton_create(1);
    if (edge_baton == NULL) {
        free(load_baton);
        return NULL;
    }
    edge_baton->insns[0] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, ast->data.ast_assert.value, 0);

    v1 = sb_graph_vertex(g, load_baton);
    if (v1 == NULL) {
        free(load_baton);
        free(edge_baton);
        return NULL;
    }

    e1 = sb_graph_edge(g, edge_baton, v1, fail);
    if (e1 == NULL) {
        free(load_baton);
        free(edge_baton);
        // TODO - also delete v1 from g somehow
        return NULL;
    }

    return v1;
}

struct sb_vertex_s * sb_ast__compile_recurse(struct sb_ast_s * ast, struct sb_graph_s * g, struct sb_vertex_s * ret) {
    switch (ast->type) {
        case SB_AST_TYPE_ASSERT:
            return sb_ast__emit_assert(ast, g, ret);
            break;
        default:
            return NULL;
            break;
    }
}

struct sb_graph_s * sb_ast_compile(struct sb_ast_s * ast) {
    struct sb_vertex_s * ret = NULL;
    struct sb_bpf_baton_s * ret_baton = NULL;
    struct sb_vertex_s * body = NULL;
    struct sb_edge_s * ent_to_body_edge = NULL;
    struct sb_bpf_baton_s * ent_to_body_edge_baton = NULL;
    struct sb_vertex_s * ent = NULL;
    struct sb_bpf_baton_s * ent_baton = NULL;
    struct sb_graph_s * g = sb_graph_create();

    if (g == NULL) {
        return NULL;
    }

    ent_baton = sb_bpf_baton_create(1);
    if (ent_baton == NULL) {
        sb_graph_destroy(g);
        return NULL;
    }
    ent_baton->insns[0] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);
    ent = sb_graph_vertex(g, ent_baton);

    ret_baton = sb_bpf_baton_create(1);
    if (ret_baton == NULL) {
        sb_graph_destroy(g);
        return NULL;
    }
    ret_baton->insns[0] = BPF_EXIT_INSN();
    ret = sb_graph_vertex(g, ret_baton);

    ent_to_body_edge_baton = sb_bpf_baton_create(1);
    if (ent_to_body_edge_baton == NULL) {
        sb_graph_destroy(g);
        return NULL;
    }
    ent_to_body_edge_baton->insns[0] = BPF_JMP_A(0);
    ent_to_body_edge = sb_graph_vertex(g, ent_to_body_edge_baton);
    body = sb_ast__compile_recurse(ast, g, ret);
    
    return g;
}
