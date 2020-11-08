#include "simbpf.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <net/ethernet.h>

int test_ast()
{
    bool err = false;
    struct sb_bpf_cc_s * b = NULL;
    struct sb_graph_s * g = NULL;
    struct sb_ast_s * func = NULL;
    struct sb_ast_s * assertion = NULL;

    printf("test_ast: sb_ast_create(SB_AST_TYPE_ASSERT)\n");
    assertion = sb_ast_create(SB_AST_TYPE_ASSERT);
    if (assertion == NULL) {
        err = true;
        goto cleanup;
    }
    assertion = sb_ast_assert_set_data(assertion, 12, 2, ETH_P_ARP, NULL);
    if (assertion == NULL) {
        err = true;
        goto cleanup;
    }

    printf("test_ast: sb_ast_create(SB_AST_TYPE_FUNCTION)\n");
    func = sb_ast_create(SB_AST_TYPE_FUNCTION);
    if (func == NULL) {
        err = true;
        goto cleanup;
    }

    func = sb_ast_function_set_data(func, assertion);
    if (func == NULL) {
        err = true;
        goto cleanup;
    }

    printf("test_ast: sb_ast_compile\n");
    g = sb_ast_compile(func);
    if (g == NULL) {
        err = true;
        goto cleanup;
    }

    printf("test_ast: sb_graph_compile g=%p entry=%p\n", g, g->v->next);
    b = sb_graph_compile(g, g->v->next);
    if (b == NULL) {
        err = true;
        goto cleanup;
    }

    sb_bpf_cc_dump(b);

    free(b);

    printf("test_ast: sb_graph_destroy\n");
    sb_graph_destroy(g);

    printf("test_ast: sb_ast_destroy\n");
    sb_ast_destroy(assertion);
    sb_ast_destroy(func);

cleanup:
    if (err) {
        return -1;
    }
    return 0;
}

int main()
{
    assert(test_ast() == 0);
    return 0;
}
