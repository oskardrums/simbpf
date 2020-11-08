#include "simbpf.h"
#include <assert.h>
#include <net/ethernet.h>

int test_ast()
{
    struct sb_ast_s * ast = sb_ast_create();
    unsigned short eth_p = ETH_P_ARP;

    if (ast == NULL) {
        return -1;
    }
    ast = sb_ast_set_type(ast, SB_AST_TYPE_ASSERT);
    if (ast == NULL) {
        return -1;
    }
    ast = sb_ast_assert_set_data(ast, 12, 2, &eth_p);
    if (ast == NULL) {
        return -1;
    }
    sb_ast_destroy(ast);
    return 0;
}

int main()
{
    assert(test_ast() == 0);
    return 0;
}
