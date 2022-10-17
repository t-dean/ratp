%option outfile="test/schema_scanner.c" header-file="test/schema_scanner.h"
%option reentrant bison-bridge
%option noyywrap nounput noinput

%{
#include "schema_tester.h"
#include "schema_parser.h"

#include <stddef.h>

extern int
yyerror(yyscan_t scanner, struct schema *schema, const char *msg);

int
escape_lit(char *buf, size_t buf_len, const char *src);
%}
%%

  /* Comments (not passed to parser */
#.*

  /* Pass through characters */
[x:=,<>\[\]\n]      { return *yytext; }

  /* Symbols */
"---"               { return ENDARROW; }
"--->"              { return OUTARROW; }
"<---"              { return INARROW; }

  /* Reserved words */
SN                  { return SN; }
AN                  { return AN; }
CTL                 { return CTL; }
DATA                { return DATA; }
LEN                 { return LEN; }
MDL                 { return MDL; }

CONNECT             { yylval->cmd = CMD_CONNECT; return CONNECT; }
LISTEN              { yylval->cmd = CMD_LISTEN;  return LISTEN; }
CLOSE               { yylval->cmd = CMD_CLOSE;   return CLOSE; }
WAIT                { yylval->cmd = CMD_WAIT;    return WAIT; }
SEND                { yylval->cmd = CMD_SEND;    return SEND; }

SYN-SENT            { yylval->state = RATP_CON_STATE_SYN_SENT;     return SYN_SENT; }
LISTENING           { yylval->state = RATP_CON_STATE_LISTEN;       return LISTENING; }
SYN-RECEIVED        { yylval->state = RATP_CON_STATE_SYN_RECEIVED; return SYN_RECEIVED; }
ESTABLISHED         { yylval->state = RATP_CON_STATE_ESTABLISHED;  return ESTABLISHED; }
FIN-WAIT            { yylval->state = RATP_CON_STATE_FIN_WAIT;     return FIN_WAIT; }
LAST-ACK            { yylval->state = RATP_CON_STATE_LAST_ACK;     return LAST_ACK; }
CLOSING             { yylval->state = RATP_CON_STATE_CLOSING;      return CLOSING; }
TIME-WAIT           { yylval->state = RATP_CON_STATE_TIME_WAIT;    return TIME_WAIT; }
CLOSED              { yylval->state = RATP_CON_STATE_CLOSED;       return CLOSED; }

SYN                 { yylval->ctl = RATP_PKT_HDR_CTRL_SYN; return SYN; }
ACK                 { yylval->ctl = RATP_PKT_HDR_CTRL_ACK; return ACK; }
FIN                 { yylval->ctl = RATP_PKT_HDR_CTRL_FIN; return FIN; }
RST                 { yylval->ctl = RATP_PKT_HDR_CTRL_RST; return RST; }
EOR                 { yylval->ctl = RATP_PKT_HDR_CTRL_EOR; return EOR; }
SO                  { yylval->ctl = RATP_PKT_HDR_CTRL_SO;  return SO; }

  /* Actual lexing */
\"(\\.|[^"\\])*\"   {
                      if (escape_lit(yylval->str, sizeof(yylval->str), yytext) != 0)
                      {
                        (void)yyerror(yyscanner, NULL, "Invalid string literal");
                      }
                      return STRING;
                    }

0|[1-9][0-9]*       {
                      yylval->num = atoi(yytext);
                      return NUMBER;
                    }

[ \t]               ;

.                   yyerror(yyscanner, NULL, "Invalid character");

%%
int
escape_lit(char *buf, size_t buf_len, const char *src)
{
  size_t src_i;
  size_t buf_i;
  char c;

  if (*src != '"')
  {
    /* ERROR: String literals must start with a '"' */
    buf[0] = '\0';
    return 1;
  }

  for (src_i = 1, buf_i = 0;
        buf_i < buf_len - 1 && src[src_i] != '"' && src[src_i] != '\0';
        buf_i++)
  {
    c = src[src_i++];
    if (c == '\\')
    {
      if (c == '\0')
      {
        /* ERROR: End of string while looking for escapped character */
        buf[0] = '\0';
        return 1;
      }
      switch (c)
      {
        case 'a':
          c = '\a';
          break;
        case 'b':
          c = '\b';
          break;
        case 'f':
          c = '\f';
          break;
        case 'n':
          c = '\n';
          break;
        case 'r':
          c = '\r';
          break;
        case 't':
          c = '\t';
          break;
        case 'v':
          c = '\v';
          break;
        default:
          /* Default to literal character */
          break;
      }
    }
      buf[buf_i] = c;
  }

  if (src[src_i] != '"')
  {
    /* ERROR: String lieterals must end with a '"' */
    buf[0] = '\0';
    return 1;
  }

  buf[buf_i] = '\0';

  return 0;
}
