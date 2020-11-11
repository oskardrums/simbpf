#include "simbpf.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int test_ast()
{
    bool err = false;
    struct sb_bpf_cc_s * b = NULL;
    struct sb_graph_s * g = NULL;
    struct sb_ast_s * func = NULL;
    struct sb_ast_s * assertion = NULL;
    struct sb_ast_s * ret = NULL;
    int prog_fd = -1;
    char buffer[4096];

    printf("test_ast: sb_ast_create(SB_AST_TYPE_RETURN)\n");
    ret = sb_ast_create(SB_AST_TYPE_RETURN);
    if (ret == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    ret = sb_ast_return_set_data(ret, XDP_PASS);
    if (ret == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    printf("test_ast: sb_ast_create(SB_AST_TYPE_ASSERT)\n");
    assertion = sb_ast_create(SB_AST_TYPE_ASSERT);
    if (assertion == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }
    assertion = sb_ast_assert_set_data(assertion, 12, BPF_H, ETH_P_ARP, ret);
    if (assertion == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    printf("test_ast: sb_ast_create(SB_AST_TYPE_FUNCTION)\n");
    func = sb_ast_create(SB_AST_TYPE_FUNCTION);
    if (func == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    func = sb_ast_function_set_data(func, assertion);
    if (func == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    printf("test_ast: sb_ast_compile\n");
    g = sb_ast_compile(func);
    if (g == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    printf("test_ast: sb_graph_compile g=%p entry=%p\n", g, g->v->next);
    b = sb_graph_compile(g, g->v->next, NULL);
    if (b == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    sb_bpf_cc_dump(b);

    printf("test_ast: bpf_load_program\n");
    prog_fd = bpf_load_program(BPF_PROG_TYPE_XDP, b->insns, b->current, "GPL", 0, buffer, 4096);
    if (prog_fd < 0) {
        printf(buffer);
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    printf("test_ast: bpf_set_link_xdp_fd\n");
    if (bpf_set_link_xdp_fd(1, prog_fd, 0) < 0) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    free(b);

    printf("test_ast: bpf_set_link_xdp_fd second time arround\n");
    if (bpf_set_link_xdp_fd(1, -1, 0) < 0) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    printf("test_ast: sb_graph_destroy\n");
    sb_graph_destroy(g);

    printf("test_ast: sb_ast_destroy\n");
    sb_ast_destroy(assertion);
    sb_ast_destroy(func);

cleanup:
    if (err) {
        if (prog_fd >= 0) {
            close(prog_fd);
        }
        prog_fd = -1;
        return -1;
    }
    return 0;
}

int main()
{
    assert(test_ast() == 0);
    return 0;
}
