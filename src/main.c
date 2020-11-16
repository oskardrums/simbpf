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

void print_help(char * argv0)
{
    fprintf(stderr, "usage: %s [OPTIONS]\n", argv0);
    fprintf(stderr, "\nOPTIONS:\n");
    fprintf(stderr, "  -i PATH: input file (if omitted, read stdin)\n");
    fprintf(stderr, "  -o PATH: output file\n");
}

void print_error(char * argv0, char * msg)
{
    fprintf(stderr, "%s: %s\n", argv0, msg);
    print_help(argv0);
}

int main(int argc, char ** argv) {
    bool err = false;
    char * input_path = NULL;
    char * output_path = NULL;
    size_t arglen = 0;
    struct sb_bpf_cc_s * b = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "i:o:")) != -1) {
        switch (opt) {
            case 'i':
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

    return err;
};
