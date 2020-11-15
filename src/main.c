#include "simbpf.h"

int main() {
    struct sb_bpf_cc_s * b = sb_parse_and_compile();
    sb_bpf_cc_dump(b);
    sb_bpf_cc_destroy(b);

    return 0;
};
