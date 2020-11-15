#include "simbpf.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#ifdef HAVE_LIBBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#endif

int test()
{
    bool err = false;
    struct sb_bpf_cc_s * b = NULL;
#ifdef HAVE_LIBBPF
    int prog_fd = -1;
    char buffer[4096];
#endif
    printf("[*] parse and compile\n");
    b = sb_parse_and_compile();
    if (b == NULL) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    printf("[*] resulting program: ");
    sb_bpf_cc_dump(b);

#ifdef HAVE_LIBBPF
    printf("[*] load BPF program\n");
    prog_fd = bpf_load_program(BPF_PROG_TYPE_XDP, b->insns, b->current, "GPL", 0, buffer, 4096);
    if (prog_fd < 0) {
        printf(buffer);
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }

    printf("[*] attach to interface\n");
    if (bpf_set_link_xdp_fd(1, prog_fd, 0) < 0) {
        err = true;
        printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
        goto cleanup;
    }
#endif

cleanup:
    printf("[*] cleanup\n");

    if (b != NULL) {
        free(b);
    }
#ifdef HAVE_LIBBPF
    if (prog_fd >= 0) {
        close(prog_fd);
    }
#endif

    if (err) {
        return -1;
    } else {
#ifdef HAVE_LIBBPF
        bpf_set_link_xdp_fd(1, -1, 0);
#endif
        return 0;
    }

}

int main()
{
    assert(test() == 0);
    return 0;
}
