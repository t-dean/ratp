#ifndef SCHEMA_TESTER_H
#define SCHEMA_TESTER_H

#include "ratp.h"

#include <stdbool.h>
#include <stdint.h>

#define MAX_ENTRIES (100U)

typedef enum
{
  NO_COMMAND,
  CMD_CONNECT,
  CMD_LISTEN,
  CMD_WAIT,
  CMD_SEND,
  CMD_CLOSE
} ratp_command;

typedef enum
{
  STATE_LINE,
  PACKET_LINE,
  COMMAND_LINE
} line_type;

struct state_line
{
  ratp_con_state left_state;
  ratp_con_state right_state;
};

struct packet_fmt
{
  struct ratp_pkt pkt; /* Expected packet to be sent */
  bool dropped;        /* Is the packet dropped after being sent? */
  bool left_tx;        /* true => sent from left; false => sent from right */
};

struct packet_line
{
  ratp_con_state left_state;
  ratp_con_state right_state;
  struct packet_fmt pkt_fmt;
};

struct command
{
  ratp_command cmd;
  uint8_t send_buf[4096];
  uint32_t wait_time_ms;
};

struct command_line
{
  struct command left_cmd;
  struct command right_cmd;
};

struct schema_entry
{
  line_type type;
  union
  {
    struct state_line state_line;
    struct packet_line pkt_line;
    struct command_line cmd_line;
  } u;
};

struct schema
{
  const char *filename;
  struct schema_entry entries[MAX_ENTRIES]; /* The series of lines */
  size_t lines;                             /* Total number of lines */
};

#define RUN_SCHEMA_TEST(filename) do\
                       {\
                         if (test_schema_file(filename) != 0)\
                         {\
                           failed++;\
                           printf("%-60s " COLOR_RED "FAILED" COLOR_RESET "\n", "Schema " filename);\
                         }\
                         else\
                         {\
                           passed++;\
                           printf("%-60s " COLOR_GREEN "PASSED" COLOR_RESET "\n", "Schema " filename);\
                         }\
                       } while (0)

int
test_schema_file(const char *filename);

#endif /* SCHEMA_TESTER_H */
