#include "simbpf.h"
#include <assert.h>
#include <stdio.h>
#include <net/ethernet.h>

int test_ast()
{
    struct sb_bpf_cc_s * b = NULL;
    struct sb_graph_s * g = NULL;
    struct sb_ast_s * ast = NULL;

    printf("test_ast: sb_ast_create\n");
    ast = sb_ast_create();
    if (ast == NULL) {
        return -1;
    }

    printf("test_ast: sb_ast_set_type\n");
    ast = sb_ast_set_type(ast, SB_AST_TYPE_ASSERT);
    if (ast == NULL) {
        return -1;
    }

    printf("test_ast: sb_ast_assert_set_data\n");
    ast = sb_ast_assert_set_data(ast, 12, 2, ETH_P_ARP);
    if (ast == NULL) {
        return -1;
    }

    printf("test_ast: sb_ast_compile\n");
    g = sb_ast_compile(ast);
    if (g == NULL) {
        return -1;
    }

    printf("test_ast: sb_graph_compile g=%p entry=%p\n", g, g->v->next);
    b = sb_graph_compile(g, g->v->next);
    if (b == NULL) {
        return -1;
    }

    sb_bpf_cc_dump(b);

    printf("test_ast: sb_graph_destroy\n");
    sb_graph_destroy(g);

    printf("test_ast: sb_ast_destroy\n");
    sb_ast_destroy(ast);

    return 0;
}

int main()
{
    assert(test_ast() == 0);
    return 0;
}
