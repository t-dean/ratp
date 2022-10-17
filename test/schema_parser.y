%lex-param    { yyscan_t scanner }
%parse-param  { yyscan_t scanner }
%parse-param  { struct schema *schema }

%pure-parser

%{
#include "schema_tester.h"
#include <stdio.h>
#include <string.h>
%}

%{
typedef void *yyscan_t;

int
yyerror(yyscan_t scanner, struct schema *schema, const char *msg);
%}

%union
{
#define MAX_STRLEN (1024)
  char str[MAX_STRLEN + 1];
  ratp_con_state state;
  ratp_pkt_hdr_ctrl ctl;
  ratp_command cmd;
  int num;
  struct ratp_pkt pkt;
  struct packet_fmt pkt_fmt;
  struct command command;
}

%token ENDARROW
%token OUTARROW
%token INARROW
%token SN
%token AN
%token CTL
%token DATA
%token LEN
%token MDL

%token <cmd> CONNECT
%token <cmd> LISTEN
%token <cmd> CLOSE
%token <cmd> WAIT
%token <cmd> SEND

%token <state> SYN_SENT
%token <state> LISTENING
%token <state> SYN_RECEIVED
%token <state> ESTABLISHED
%token <state> FIN_WAIT
%token <state> LAST_ACK
%token <state> CLOSING
%token <state> TIME_WAIT
%token <state> CLOSED

%token <ctl> SYN
%token <ctl> ACK
%token <ctl> FIN
%token <ctl> RST
%token <ctl> EOR
%token <ctl> SO

%token <str> STRING
%token <num> NUMBER

%type <state> state
%type <command> command

%type <pkt_fmt> packet_fmt;
%type <pkt_fmt> dropped_packet
%type <pkt_fmt> sent_packet

%type <pkt> packet_contents

%type <num> sn
%type <num> an
%type <ctl> ctl
%type <ctl> ctl_opts
%type <ctl> opt
%type <num> len
%type <str> data

%start input

%{
extern int
yylex (YYSTYPE *yylval_param, yyscan_t yyscanner);
%}

%%

input: lines

lines: line lines
     | ;

line: decl '\n'

decl: commands  { schema->lines++; }
    | states    { schema->lines++; }
    | packet    { schema->lines++; }

commands: command command {
                            if (schema->lines >= sizeof(schema->entries) / sizeof(schema->entries[0]))
                            {
                              yyerror(scanner, schema, "Reached line limit");
                              YYERROR;
                            }
                            struct schema_entry *entry = &schema->entries[schema->lines];
                            entry->type = COMMAND_LINE;
                            entry->u.cmd_line.left_cmd = $1;
                            entry->u.cmd_line.right_cmd = $2;
                          }

command: '[' CONNECT ']'      { $$.cmd = $2; $$.send_buf[0] = '\0'; }
       | '[' LISTEN ']'       { $$.cmd = $2; $$.send_buf[0] = '\0'; }
       | '[' CLOSE ']'        { $$.cmd = $2; $$.send_buf[0] = '\0'; }
       | '[' WAIT NUMBER ']'  { $$.cmd = $2; $$.send_buf[0] = '\0'; $$.wait_time_ms = $3; }
       | '[' SEND STRING ']'  { $$.cmd = $2; strncpy((char *)$$.send_buf, $3, sizeof($$.send_buf)); }
       | '[' ']'              { $$.cmd = NO_COMMAND; $$.send_buf[0] = '\0'; }

states: state state {
                      if (schema->lines >= sizeof(schema->entries) / sizeof(schema->entries[0]))
                      {
                        yyerror(scanner, schema, "Reached line limit");
                        YYERROR;
                      }
                      struct schema_entry *entry = &schema->entries[schema->lines];
                      entry->type = STATE_LINE;
                      entry->u.state_line.left_state = $1;
                      entry->u.state_line.right_state = $2;
                    }

packet: state packet_fmt state {
                                 if (schema->lines >= sizeof(schema->entries) / sizeof(schema->entries[0]))
                                 {
                                   yyerror(scanner, schema, "Reached line limit");
                                   YYERROR;
                                 }
                                 struct schema_entry *entry = &schema->entries[schema->lines];
                                 entry->type = PACKET_LINE;
                                 entry->u.pkt_line.left_state = $1;
                                 entry->u.pkt_line.pkt_fmt = $2;
                                 entry->u.pkt_line.right_state = $3;
                               }

state: SYN_SENT
     | LISTENING
     | SYN_RECEIVED
     | ESTABLISHED
     | FIN_WAIT
     | LAST_ACK
     | CLOSING
     | TIME_WAIT
     | CLOSED


packet_fmt: dropped_packet
          | sent_packet

dropped_packet: '[' 'x' ']' sent_packet { $$ = $4; $$.dropped = true; }

sent_packet: ENDARROW packet_contents OUTARROW {
                                                 $$.dropped = false;
                                                 $$.left_tx = true;
                                                 $$.pkt = $2;
                                               }
           | INARROW packet_contents ENDARROW {
                                                $$.dropped = false;
                                                $$.left_tx = false;
                                                $$.pkt = $2;
                                              }

packet_contents: sn ctl           {
                                    ratp_pkt_init(&$$);
                                    ratp_pkt_set_sn(&$$, $1);
                                    $$.hdr.ctrl |= $2;
                                  }
               | sn ctl len       {
                                    ratp_pkt_init(&$$);
                                    ratp_pkt_set_sn(&$$, $1);
                                    $$.hdr.ctrl |= $2;
                                    $$.hdr.len = $3;
                                  }
               | sn ctl data      {
                                    ratp_pkt_init(&$$);
                                    ratp_pkt_set_sn(&$$, $1);
                                    $$.hdr.ctrl |= $2;
                                    $$.hdr.len = (uint8_t)strlen($3);
                                    $$.data.data_base = (uint8_t *)strdup($3);
                                    $$.data.data_start = 0;
                                    $$.data.data_base_len = $$.hdr.len;
                                  }
               | sn an ctl        {
                                    ratp_pkt_init(&$$);
                                    ratp_pkt_set_sn(&$$, $1);
                                    ratp_pkt_set_an(&$$, $2);
                                    $$.hdr.ctrl |= $3;
                                  }
               | sn an ctl len    {
                                    ratp_pkt_init(&$$);
                                    ratp_pkt_set_sn(&$$, $1);
                                    ratp_pkt_set_an(&$$, $2);
                                    $$.hdr.ctrl |= $3;
                                    $$.hdr.len = $4;
                                  }
               | sn an ctl data   {
                                    ratp_pkt_init(&$$);
                                    ratp_pkt_set_sn(&$$, $1);
                                    ratp_pkt_set_an(&$$, $2);
                                    $$.hdr.ctrl |= $3;
                                    $$.hdr.len = (uint8_t)strlen($4);
                                    $$.data.data_base = (uint8_t *)strdup($4);
                                    $$.data.data_start = 0;
                                    $$.data.data_base_len = $$.hdr.len;
                                  }

sn: '<' SN '=' NUMBER '>' {
                            if ($4 > 1)
                            {
                              yyerror(scanner, NULL, "Invalid sequence number");
                            }
                            $$ = $4;
                          }

an: '<' AN '=' NUMBER '>' {
                            if ($4 > 1)
                            {
                              yyerror(scanner, NULL, "Invalid sequence number");
                            }
                            $$ = $4;
                          }

ctl: '<' CTL '=' ctl_opts '>' { $$ = $4; }

ctl_opts: opt
        | opt ',' ctl_opts  { $$ = $1 | $3; }

opt: SYN
   | ACK
   | FIN
   | RST
   | EOR
   | SO

len: '<' LEN '=' NUMBER '>' { $$ = $4; }
   | '<' MDL '=' NUMBER '>' { $$ = $4; }

data: '<' DATA '=' STRING '>' { strncpy($$, $4, sizeof($$)); }

%%

int
yyerror(yyscan_t scanner, struct schema *schema, const char *msg)
{
  (void)scanner;
  (void)schema;
  return fprintf(stderr, "%s\n", msg);
}
