%{
/* Must come first for _LARGE_FILE_API on AIX. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <string.h>
#include "grammar.h"
#include "simbpf.h"
%}

%option noyywrap
%option noinput
%option nounput
%option reentrant
%option bison-bridge
%option header-file = "lexicon.h"

HEX		(0x[0-9A-Fa-f]+)
N		([0-9]+)

%%
[ \r\n\t]		;
"u16"                   { return U16;  }
"u8"                    { return U8;   }
"->"                    { return THEN; }
"drop"                  { return DROP; }
"pass"                  { return PASS; }
{HEX}			{ yylval->n = strtoul(yytext + 2, NULL, 16); return N;}
{N}			{ yylval->n = strtoul(yytext, NULL, 10); return N;}
"@"                     { return AT;   }
":"			{ return CASE; }
";"			{ return END;  }
"."			{ return STOP; }
"="			{ return EQ;   }
%%
