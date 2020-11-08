#include "simbpf/ast.h"

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

struct sb_ast_s * sb_ast_assert_set_data(struct sb_ast_s * ast, size_t offset, size_t size, void * data)
{
    assert(ast->type == SB_AST_TYPE_ASSERT);
    ast->data.offset = offset;
    ast->data.size = size;
    ast->data.data = data;
    return ast;
}

{
    struct sb_ast_s * ast = (typeof(ast))malloc(sizeof(*ast));
    if (ast == NULL) {
        return NULL;
    }
    return ast;
}

void sb_ast_destroy(struct sb_ast_s * ast)
{
    if (ast != NULL) {
        free(ast);
    }
}

