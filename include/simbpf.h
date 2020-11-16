#ifndef SIMBPF_H
#define SIMBPF_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "simbpf/graph.h"
#include "simbpf/bpf.h"
#include "simbpf/ast.h"

struct sb_bpf_cc_s * sb_parse_and_compile(char *);

#endif
