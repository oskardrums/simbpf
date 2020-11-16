#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "simbpf.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <linux/limits.h>

#ifdef HAVE_LIBBPF
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#endif

void print_help(char * argv0)
{
    fprintf(stderr, "usage: %s [OPTIONS]\n", argv0);
    fprintf(stderr, "\nOPTIONS:\n");
    fprintf(stderr, "  -c PATH: input file, if omitted read source code from stdin\n");
    fprintf(stderr, "  -o PATH: output file\n");
#ifdef HAVE_LIBBPF
    fprintf(stderr, "  -i IFNAME: interface to bind program to, if omitted no binding occurs\n");
#endif
}

int main(int argc, char ** argv) {
    bool err = false;
    char * input_path = NULL;
    char * output_path = NULL;
    size_t arglen = 0;
    struct sb_bpf_cc_s * b = NULL;
    int opt;
#ifdef HAVE_LIBBPF
    int ifindex = 0, prog_fd = -1;
#endif

    while ((opt = getopt(argc, argv, "c:o:i:")) != -1) {
        switch (opt) {
#ifdef HAVE_LIBBPF
            case 'i':
                ifindex = if_nametoindex(optarg);
                if (ifindex == 0) {
                    err = true;
                    perror("if_nametoindex");
                    goto cleanup;
                }
                break;
#endif
            case 'c':
                arglen = strnlen(optarg, PATH_MAX);
                input_path = (char *) malloc (arglen);
                if (input_path == NULL) {
                    err = true;
                    perror("malloc");
                    goto cleanup;
                }
                memcpy(input_path, optarg, arglen);
                break;
            case 'o':
                arglen = strnlen(optarg, PATH_MAX);
                output_path = (char *) malloc (arglen);
                if (output_path == NULL) {
                    err = true;
                    perror("malloc");
                    goto cleanup;
                }
                memcpy(output_path, optarg, arglen);
                break;
           default: /* '?' */
                print_help(argv[0]);
                err = true;
                goto cleanup;
                break;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "%s: unrecognized positional argument '%s'\n", argv[0], argv[optind]);
        print_help(argv[0]);
        err = true;
        goto cleanup;
    }

    b = sb_parse_and_compile(input_path);

#ifdef HAVE_LIBBPF
    if (ifindex > 0) {
        prog_fd = bpf_load_program(BPF_PROG_TYPE_XDP, b->insns, b->current, "GPL", 0, NULL, 0);
        if (prog_fd < 0) {
            err = true;
            perror("BPF load failed");
            goto cleanup;
        }
        if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0) {
            err = true;
            printf("err at %s:%s:%u\n", __FILE__,  __FUNCTION__, __LINE__);
            goto cleanup;
        }
    }
#endif

    if (b != NULL) {
        sb_bpf_cc_dump(b);
        sb_bpf_cc_destroy(b);
    }

cleanup:
    if (input_path != NULL) {
        free(input_path);
    }
    if (output_path != NULL) {
        free(output_path);
    }
#ifdef HAVE_LIBBPF
    if (prog_fd >= 0) {
        close(prog_fd);
    }
#endif

    return err;
};
