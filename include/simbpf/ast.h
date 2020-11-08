#ifndef SIMBPF_AST_H
#define SIMBPF_AST_H


struct sb_ast_s {
    int type;
    union {
        struct {
            size_t offset;
            size_t size;
            char * data;
        } ast_assert;

        struct {
            size_t value;
        } ast_return;
    } data;
};

struct sb_ast_s * sb_ast_create(void);
void sb_ast_destroy(struct sb_ast_s *);

struct sb_ast_s * sb_ast_set_type(struct sb_ast_s *, int type);
struct sb_ast_s * sb_ast_assert_set_data(struct sb_ast_s *, size_t offset, size_t size, void * data);

#endif
