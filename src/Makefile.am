#SUFFIXES = .c .h .y .l
AM_YFLAGS = -d
bin_PROGRAMS = simbpf
simbpf_SOURCES = lexicon.l grammar.y main.c bpf.c graph.c ast.c simbpf.c
BUILT_SOURCES = grammar.h
lib_LIBRARIES = libsb.a
libsb_a_SOURCES = lexicon.l grammar.y bpf.c graph.c ast.c simbpf.c
