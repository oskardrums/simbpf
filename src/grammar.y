%parse-param { struct prog_s ** res_p }

%{
  #include <stdio.h>  /* For printf, etc. */
  #include "simbpf.h"
  int yylex (void);
  void yyerror (struct prog_s **, char const *);
%}

%union {
	size_t n;
        struct prog_s * prog;
        struct expr_s * expr;
        struct arm_s * arm;
        struct match_s * match;
}

%define lr.type ielr
%expect 2

%token N 
%token AT CASE THEN END STOP 
%token DROP PASS 
%token U8 U16
%token EQ

%type <n> N comp
%type <prog> prog
%type <expr> expr
%type <arm> arms arm
%type <match> match


%%

prog:                           { YYABORT;                                }
        | expr STOP             { $$ = sb_prog($1); *res_p = $$;      }
        ;
expr:     N                     { $$ = sb_expr_const($1);                 }
        | DROP                  { $$ = sb_expr_const(XDP_DROP);           }
        | PASS                  { $$ = sb_expr_const(XDP_PASS);           }
        | U8  AT N              { $$ = sb_expr_read_u8($3);               }
        | U16 AT N              { $$ = sb_expr_read_u16($3);              }
        | expr CASE arms        { $$ = sb_expr_test($1, $3);              }
        ;
arms:     arm                   { $$ = $1;                     }
        | arms END arm          { $$ = sb_arms($1, $3);               }
        ;
arm:      match THEN expr       { $$ = sb_arm($1, $3);         }
        ;
match:    comp expr             { $$ = sb_match($1, $2);               }
        ;
comp:     EQ                    { $$ = BPF_JEQ; }
        ;

%%

void yyerror (struct prog_s ** res_p, char const * s)
{
(void) res_p;
  fprintf (stderr, "%s\n", s);
}

