#include "schema_tester.h"

#include "ratp_packet_parser.h"
#include "ratp.h"

#include "schema_parser.h"
#include "schema_scanner.h"

/* Parser declaration not included in schema_parser.h */
extern int yyparse(yyscan_t scanner, struct schema *schema);

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define GREY "\033[0;90m"
#define YELLOW "\033[0;33m"
#define RED "\033[0;31m"
#define BOLD_RED "\033[1;31m"
#define RESET "\033[0m"

static const char *log_level_strmap[] =
{
  [RATP_LOG_LEVEL_DEBUG] = GREY "DEBUG" RESET,
  [RATP_LOG_LEVEL_INFO] = "INFO",
  [RATP_LOG_LEVEL_WARN] = YELLOW "WARNING" RESET,
  [RATP_LOG_LEVEL_ERROR] = RED "ERROR" RESET,
  [RATP_LOG_LEVEL_FATAL] = BOLD_RED "FATAL" RESET,
};

/**
 * Logging function
 *
 * \param[in,out] unused Unused
 * \param[in] level The log level
 * \param[in] fmt The format string
 * \param[in] args The arguments to populate the format string
 *
 * \note Logging must be enabled when building the RATP library to generate
 * calls to the logging function
 */
static void
left_logger_fn(void *unused, ratp_log_level level, const char *fmt, va_list args);

/**
 * Logging function
 *
 * \param[in,out] unused Unused
 * \param[in] level The log level
 * \param[in] fmt The format string
 * \param[in] args The arguments to populate the format string
 *
 * \note Logging must be enabled when building the RATP library to generate
 * calls to the logging function
 */
static void
right_logger_fn(void *unused, ratp_log_level level, const char *fmt, va_list args);

struct timer
{
  struct ratp_timeout_callback cb;

  bool armed;
  uint32_t start_time;
  uint32_t timeout_ms;
};

#define PACKET_QUEUE_SIZE (10U)
struct packet_queue
{
  struct ratp_pkt pkts[PACKET_QUEUE_SIZE];
  size_t size;
  size_t head;
  size_t tail;
};

static void
packet_queue_init(struct packet_queue *q)
{
  q->size = 0;
  q->head = 0;
  q->tail = 0;
}

static bool
packet_queue_push(struct packet_queue *q, const struct ratp_pkt *pkt)
{
  struct ratp_pkt pkt_copy;
  uint8_t *pkt_copy_data;

  pkt_copy = *pkt;
  if (ratp_pkt_has_data(pkt))
  {
    pkt_copy_data = malloc(pkt->hdr.len);
    if (pkt_copy_data == NULL)
    {
      return false;
    }
    assert(pkt->data.data_start == 0);
    assert(pkt->data.data_base_len >= pkt->hdr.len);
    memcpy(pkt_copy_data, pkt->data.data_base, pkt->hdr.len);
    pkt_copy.data.data_base = pkt_copy_data;
  }
  if (q->size < PACKET_QUEUE_SIZE)
  {
    q->pkts[q->tail++] = pkt_copy;
    q->tail %= PACKET_QUEUE_SIZE;
    q->size++;
    return true;
  }

  return false;
}

static bool
packet_queue_pop(struct packet_queue *q, struct ratp_pkt *pkt)
{
  if (q->size > 0)
  {
    *pkt = q->pkts[q->head++];
    q->head %= PACKET_QUEUE_SIZE;
    q->size--;
    return true;
  }

  return false;
}

#define LOG_BUF_SIZE (8192U)
struct test_schema_ctx
{
  const struct schema *schema;
  size_t cur_line;
  struct ratp ratp_left, ratp_right;

  /* For test callbacks to populate... */
  struct packet_queue left_rx_queue;
  struct packet_queue right_rx_queue;

  struct timer left_timers[NUM_RATP_TIMER_TYPES];
  uint32_t left_time_ms;

  struct timer right_timers[NUM_RATP_TIMER_TYPES];
  uint32_t right_time_ms;

  char log_buf[LOG_BUF_SIZE];
};

static int
test_schema(const struct schema *schema);

static int
parse_schema(struct schema *schema, const char *filename);

static void
left_tx(void *ctx, const uint8_t *data, size_t data_len);

static void
right_tx(void *ctx, const uint8_t *data, size_t data_len);

static void
left_msg_hdlr(void *ctx, const uint8_t *data, size_t data_len);

static void
right_msg_hdlr(void *ctx, const uint8_t *data, size_t data_len);

static void
left_on_state_change(void *ctx, ratp_con_state old_state,
    ratp_con_state new_state, ratp_status status);

static void
right_on_state_change(void *ctx, ratp_con_state old_state,
    ratp_con_state new_state, ratp_status status);

static bool
left_timer_init(void *ctx, void **timer, ratp_timer_type timer_name, struct ratp_timeout_callback cb);

static void
left_timer_start(void *ctx, void *timer, uint32_t timeout_ms);

static void
left_timer_stop(void *ctx, void *timer);

static uint32_t
left_timer_elapsed_ms(void *ctx, void *timer);

static bool
left_timer_destroy(void *ctx, void *timer);

static bool
right_timer_init(void *ctx, void **timer, ratp_timer_type timer_name, struct ratp_timeout_callback cb);

static void
right_timer_start(void *ctx, void *timer, uint32_t timeout_ms);

static void
right_timer_stop(void *ctx, void *timer);

static uint32_t
right_timer_elapsed_ms(void *ctx, void *timer);

static bool
right_timer_destroy(void *ctx, void *timer);

static void
store_rx_packet(void *ctx, const struct ratp_pkt *pkt);

static void
mdl_err_handler(void *ctx, uint8_t pkt_data_len, uint8_t mdl);

static bool
pkt_data_eq(const struct ratp_pkt *a, const struct ratp_pkt *b);

static bool
pkt_eq(const struct ratp_pkt *a, const struct ratp_pkt *b);

int
test_schema_file(const char *filename)
{
  struct schema *file_schema;
  int rv = 1;
  file_schema = malloc(sizeof(*file_schema)); /* Large struct => heap allocate */

  if (file_schema == NULL)
  {
    fprintf(stderr, "Failed to allocate file schema object\n");
    return 1;
  }

  if (parse_schema(file_schema, filename) != 0)
  {
    free(file_schema);
    return 1;
  }

  rv = test_schema(file_schema);

  free(file_schema);
  return rv;
}

static int
test_schema(const struct schema *schema)
{
  int rv = 0;
  size_t i, timer;
  struct test_schema_ctx ctx;
  ratp_status status;
  struct ratp_pkt pkt;
  struct ratp_callbacks left_callbacks =
  {
    .tx_cb =
    {
      .ctx = &ctx,
      .tx = left_tx,
    },
    .msg_hdlr_cb =
    {
      .ctx = &ctx,
      .msg_hdlr = left_msg_hdlr,
    },
    .on_state_change_cb =
    {
      .ctx = &ctx,
      .on_state_change = left_on_state_change,
    },
    .log_cb =
    {
      .ctx = ctx.log_buf,
      .log = left_logger_fn,
    },
    .timer_cbs =
    {
      .ctx = &ctx,
      .init = left_timer_init,
      .start = left_timer_start,
      .stop = left_timer_stop,
      .elapsed_ms = left_timer_elapsed_ms,
      .destroy = left_timer_destroy,
    }
  };

  struct ratp_callbacks right_callbacks =
  {
    .tx_cb =
    {
      .ctx = &ctx,
      .tx = right_tx,
    },
    .msg_hdlr_cb =
    {
      .ctx = &ctx,
      .msg_hdlr = right_msg_hdlr,
    },
    .on_state_change_cb =
    {
      .ctx = &ctx,
      .on_state_change = right_on_state_change,
    },
    .log_cb =
    {
      .ctx = ctx.log_buf,
      .log = right_logger_fn,
    },
    .timer_cbs =
    {
      .ctx = &ctx,
      .init = right_timer_init,
      .start = right_timer_start,
      .stop = right_timer_stop,
      .elapsed_ms = right_timer_elapsed_ms,
      .destroy = right_timer_destroy,
    }
  };

  ctx.schema = schema;
  ctx.cur_line = 0;
  packet_queue_init(&ctx.right_rx_queue);
  packet_queue_init(&ctx.left_rx_queue);
  ctx.left_time_ms = 0;
  ctx.right_time_ms = 0;
  ctx.log_buf[0] = '\0';

  if (ratp_init(&ctx.ratp_left, &left_callbacks) != RATP_STATUS_OK)
  {
    rv = 1; goto done;
  }
  if (ratp_init(&ctx.ratp_right, &right_callbacks) != RATP_STATUS_OK)
  {
    rv = 1; goto done;
  }

  for (i = 0; i < schema->lines; i++, ctx.cur_line++)
  {
    if (schema->entries[i].type == COMMAND_LINE)
    {
      switch (schema->entries[i].u.cmd_line.left_cmd.cmd)
      {
        case CMD_CONNECT:
          ratp_connect(&ctx.ratp_left);
          break;
        case CMD_LISTEN:
          ratp_listen(&ctx.ratp_left);
          break;
        case CMD_WAIT:
          ctx.left_time_ms += schema->entries[i].u.cmd_line.left_cmd.wait_time_ms;
          for (timer = 0; timer < NUM_RATP_TIMER_TYPES; timer++)
          {
            if (ctx.left_timers[timer].armed &&
                ctx.left_time_ms - ctx.left_timers[timer].start_time >= ctx.left_timers[timer].timeout_ms)
            {
              ctx.left_timers[timer].armed = false;
              ctx.left_timers[timer].cb.timeout(ctx.left_timers[timer].cb.ctx);
            }
          }
          break;
        case CMD_SEND:
          status = ratp_send(&ctx.ratp_left, schema->entries[i].u.cmd_line.left_cmd.send_buf,
              strlen((const char *)schema->entries[i].u.cmd_line.left_cmd.send_buf));
          if (status != RATP_STATUS_OK)
          {
            fprintf(stderr, "ERROR: ratp_send: %s\n", ratp_strerror(status));
          }
          break;
        case CMD_CLOSE:
          ratp_close(&ctx.ratp_left);
          break;
        case NO_COMMAND:
          break;
      }

      switch (schema->entries[i].u.cmd_line.right_cmd.cmd)
      {
        case CMD_CONNECT:
          ratp_connect(&ctx.ratp_right);
          break;
        case CMD_LISTEN:
          ratp_listen(&ctx.ratp_right);
          break;
        case CMD_WAIT:
          ctx.right_time_ms += schema->entries[i].u.cmd_line.right_cmd.wait_time_ms;
          for (timer = 0; timer < NUM_RATP_TIMER_TYPES; timer++)
          {
            if (ctx.right_timers[timer].armed &&
                ctx.right_time_ms - ctx.right_timers[timer].start_time >= ctx.right_timers[timer].timeout_ms)
            {
              ctx.right_timers[timer].armed = false;
              ctx.right_timers[timer].cb.timeout(ctx.right_timers[timer].cb.ctx);
            }
          }
          break;
        case CMD_SEND:
          status = ratp_send(&ctx.ratp_right, schema->entries[i].u.cmd_line.right_cmd.send_buf,
              strlen((const char *)schema->entries[i].u.cmd_line.right_cmd.send_buf));
          if (status != RATP_STATUS_OK)
          {
            fprintf(stderr, "ERROR: ratp_send: %s\n", ratp_strerror(status));
          }
          break;
        case CMD_CLOSE:
          ratp_close(&ctx.ratp_right);
          break;
        case NO_COMMAND:
          break;
      }
    }
    else if (schema->entries[i].type == PACKET_LINE)
    {
      if (schema->entries[i].u.pkt_line.pkt_fmt.left_tx)
      {
        if (!packet_queue_pop(&ctx.right_rx_queue, &pkt))
        {
          fprintf(stderr, "ERROR: %s:%zu: No packet sent from left RATP\n", schema->filename, ctx.cur_line + 1);
          rv = 1; goto done;
        }

        if (!pkt_eq(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, &pkt))
        {
          fprintf(stderr, "ERROR: %s:%zu: Transmit packet mismatch\n", schema->filename, ctx.cur_line + 1);
          fprintf(stderr, "Expected: [%s %s %s %s SN=%" PRIu8 " AN=%" PRIu8 " %s %s] [len: %03" PRIu8 "]\n",
              ratp_pkt_is_ctrl_flag_set(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, RATP_PKT_HDR_CTRL_SYN) ? "SYN" : "---",
              ratp_pkt_is_ctrl_flag_set(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, RATP_PKT_HDR_CTRL_ACK) ? "ACK" : "---",
              ratp_pkt_is_ctrl_flag_set(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, RATP_PKT_HDR_CTRL_FIN) ? "FIN" : "---",
              ratp_pkt_is_ctrl_flag_set(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, RATP_PKT_HDR_CTRL_RST) ? "RST" : "---",
              ratp_pkt_get_sn(&schema->entries[i].u.pkt_line.pkt_fmt.pkt),
              ratp_pkt_get_an(&schema->entries[i].u.pkt_line.pkt_fmt.pkt),
              ratp_pkt_is_ctrl_flag_set(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, RATP_PKT_HDR_CTRL_EOR) ? "EOR" : "---",
              ratp_pkt_is_ctrl_flag_set(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, RATP_PKT_HDR_CTRL_SO) ? "SO" : "--",
              schema->entries[i].u.pkt_line.pkt_fmt.pkt.hdr.len);
          fprintf(stderr, "Found:    [%s %s %s %s SN=%" PRIu8 " AN=%" PRIu8 " %s %s] [len: %03" PRIu8 "]\n",
              ratp_pkt_is_ctrl_flag_set(&pkt, RATP_PKT_HDR_CTRL_SYN) ? "SYN" : "---",
              ratp_pkt_is_ctrl_flag_set(&pkt, RATP_PKT_HDR_CTRL_ACK) ? "ACK" : "---",
              ratp_pkt_is_ctrl_flag_set(&pkt, RATP_PKT_HDR_CTRL_FIN) ? "FIN" : "---",
              ratp_pkt_is_ctrl_flag_set(&pkt, RATP_PKT_HDR_CTRL_RST) ? "RST" : "---",
              ratp_pkt_get_sn(&pkt),
              ratp_pkt_get_an(&pkt),
              ratp_pkt_is_ctrl_flag_set(&pkt, RATP_PKT_HDR_CTRL_EOR) ? "EOR" : "---",
              ratp_pkt_is_ctrl_flag_set(&pkt, RATP_PKT_HDR_CTRL_SO) ? "SO" : "--",
              pkt.hdr.len);
          rv = 1; goto done;
        }
        free((void *)pkt.data.data_base);

        if (schema->entries[i].u.pkt_line.left_state != ctx.ratp_left.state)
        {
          fprintf(stderr, "ERROR: %s:%zu: Unexpected left RATP state: %s\n", schema->filename, ctx.cur_line + 1, ratp_strstate(ctx.ratp_left.state));
          rv = 1; goto done;
        }

        if (schema->entries[i].u.pkt_line.right_state != ctx.ratp_right.state)
        {
          fprintf(stderr, "ERROR: %s:%zu: Unexpected right RATP state: %s\n", schema->filename, ctx.cur_line + 1, ratp_strstate(ctx.ratp_right.state));
          rv = 1; goto done;
        }

        if (!schema->entries[i].u.pkt_line.pkt_fmt.dropped)
        {
          ratp_rx_packet(&ctx.ratp_right, &schema->entries[i].u.pkt_line.pkt_fmt.pkt);
        }
      }
      else /* right TX */
      {
        if (!packet_queue_pop(&ctx.left_rx_queue, &pkt))
        {
          fprintf(stderr, "ERROR: %s:%zu: No packet sent from right RATP\n", schema->filename, ctx.cur_line + 1);
          rv = 1; goto done;
        }

        if (!pkt_eq(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, &pkt))
        {
          fprintf(stderr, "ERROR: %s:%zu: Transmit packet mismatch\n", schema->filename, ctx.cur_line + 1);
          fprintf(stderr, "Expected: [%s %s %s %s SN=%" PRIu8 " AN=%" PRIu8 " %s %s] [len: %03" PRIu8 "]\n",
              ratp_pkt_is_ctrl_flag_set(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, RATP_PKT_HDR_CTRL_SYN) ? "SYN" : "---",
              ratp_pkt_is_ctrl_flag_set(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, RATP_PKT_HDR_CTRL_ACK) ? "ACK" : "---",
              ratp_pkt_is_ctrl_flag_set(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, RATP_PKT_HDR_CTRL_FIN) ? "FIN" : "---",
              ratp_pkt_is_ctrl_flag_set(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, RATP_PKT_HDR_CTRL_RST) ? "RST" : "---",
              ratp_pkt_get_sn(&schema->entries[i].u.pkt_line.pkt_fmt.pkt),
              ratp_pkt_get_an(&schema->entries[i].u.pkt_line.pkt_fmt.pkt),
              ratp_pkt_is_ctrl_flag_set(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, RATP_PKT_HDR_CTRL_EOR) ? "EOR" : "---",
              ratp_pkt_is_ctrl_flag_set(&schema->entries[i].u.pkt_line.pkt_fmt.pkt, RATP_PKT_HDR_CTRL_SO) ? "SO" : "--",
              schema->entries[i].u.pkt_line.pkt_fmt.pkt.hdr.len);
          fprintf(stderr, "Found:    [%s %s %s %s SN=%" PRIu8 " AN=%" PRIu8 " %s %s] [len: %03" PRIu8 "]\n",
              ratp_pkt_is_ctrl_flag_set(&pkt, RATP_PKT_HDR_CTRL_SYN) ? "SYN" : "---",
              ratp_pkt_is_ctrl_flag_set(&pkt, RATP_PKT_HDR_CTRL_ACK) ? "ACK" : "---",
              ratp_pkt_is_ctrl_flag_set(&pkt, RATP_PKT_HDR_CTRL_FIN) ? "FIN" : "---",
              ratp_pkt_is_ctrl_flag_set(&pkt, RATP_PKT_HDR_CTRL_RST) ? "RST" : "---",
              ratp_pkt_get_sn(&pkt),
              ratp_pkt_get_an(&pkt),
              ratp_pkt_is_ctrl_flag_set(&pkt, RATP_PKT_HDR_CTRL_EOR) ? "EOR" : "---",
              ratp_pkt_is_ctrl_flag_set(&pkt, RATP_PKT_HDR_CTRL_SO) ? "SO" : "--",
              pkt.hdr.len);
          rv = 1; goto done;
        }
        free((void *)pkt.data.data_base);

        if (schema->entries[i].u.pkt_line.left_state != ctx.ratp_left.state)
        {
          fprintf(stderr, "ERROR: %s:%zu: Unexpected left RATP state: %s\n", schema->filename, ctx.cur_line + 1, ratp_strstate(ctx.ratp_left.state));
          rv = 1; goto done;
        }

        if (schema->entries[i].u.pkt_line.right_state != ctx.ratp_right.state)
        {
          fprintf(stderr, "ERROR: %s:%zu: Unexpected right RATP state: %s\n", schema->filename, ctx.cur_line + 1, ratp_strstate(ctx.ratp_right.state));
          rv = 1; goto done;
        }

        if (!schema->entries[i].u.pkt_line.pkt_fmt.dropped)
        {
          ratp_rx_packet(&ctx.ratp_left, &schema->entries[i].u.pkt_line.pkt_fmt.pkt);
        }
      }
    }
    else if (schema->entries[i].type == STATE_LINE)
    {
      if (schema->entries[i].u.pkt_line.left_state != ctx.ratp_left.state)
      {
        fprintf(stderr, "ERROR: %s:%zu: Unexpected left RATP state: %s\n", schema->filename, ctx.cur_line + 1, ratp_strstate(ctx.ratp_left.state));
        rv = 1; goto done;
      }

      if (schema->entries[i].u.pkt_line.right_state != ctx.ratp_right.state)
      {
        fprintf(stderr, "ERROR: %s:%zu: Unexpected right RATP state: %s\n", schema->filename, ctx.cur_line + 1, ratp_strstate(ctx.ratp_right.state));
        rv = 1; goto done;
      }
    }
    else
    {
      fprintf(stderr, "Unknown schema entry type\n");
    }
  }

done:
  if (rv != 0) /* Only print log on failure */
  {
    printf("=================================== RATP LOG ===================================\n");
    printf("%s", ctx.log_buf);
    printf("================================================================================\n");
  }

  return rv;
}

static int
parse_schema(struct schema *schema, const char *filename)
{
  FILE *file;
  yyscan_t scanner;

  if ((file = fopen(filename, "r")) == NULL)
  {
    perror(filename);
    return 1;
  }

  if (yylex_init(&scanner) != 0)
  {
    perror("yylex_init");
    (void)fclose(file);
    return 1;
  }

  yyrestart(file, scanner);

  schema->filename = filename;
  schema->lines = 0;

  if (yyparse(scanner, schema) != 0)
  {
    fprintf(stderr, "%s: failed schema parsing\n", filename);
    if (yylex_destroy(scanner) != 0)
    {
      perror("yylex_destroy");
    }
    (void)fclose(file);
    return 1;
  }

  if (yylex_destroy(scanner) != 0)
  {
    perror("yylex_destroy");
    (void)fclose(file);
    return 1;
  }

  fclose(file);

  return 0;
}

static void
left_tx(void *ctx, const uint8_t *data, size_t data_len)
{
  struct test_schema_ctx *schema_ctx = (struct test_schema_ctx *)ctx;
  struct ratp_pkt_parser pkt_parser;
  struct ratp_pkt_parser_callbacks cbs =
  {
    .ctx = &schema_ctx->right_rx_queue,
    .rx_pkt = store_rx_packet,
    .mdl_err_hdlr = mdl_err_handler
  };
  if (ratp_pkt_parser_init(&pkt_parser, &cbs) != RATP_STATUS_OK)
  {
    fprintf(stderr, "Packet parser initialization failure\n");
  }
  if (ratp_pkt_parser_rx_bytes(&pkt_parser, data, data_len) != RATP_STATUS_OK)
  {
    fprintf(stderr, "Packet parser receive failure\n");
  }
}

static void
right_tx(void *ctx, const uint8_t *data, size_t data_len)
{
  struct test_schema_ctx *schema_ctx = (struct test_schema_ctx *)ctx;
  struct ratp_pkt_parser pkt_parser;
  struct ratp_pkt_parser_callbacks cbs =
  {
    .ctx = &schema_ctx->left_rx_queue,
    .rx_pkt = store_rx_packet,
    .mdl_err_hdlr = mdl_err_handler
  };
  if (ratp_pkt_parser_init(&pkt_parser, &cbs) != RATP_STATUS_OK)
  {
    fprintf(stderr, "Packet parser initialization failure\n");
  }
  if (ratp_pkt_parser_rx_bytes(&pkt_parser, data, data_len) != RATP_STATUS_OK)
  {
    fprintf(stderr, "Packet parser receive failure\n");
  }
}

static void
left_msg_hdlr(void *ctx, const uint8_t *data, size_t data_len)
{
  struct test_schema_ctx *schema_ctx = (struct test_schema_ctx *)ctx;

  (void)schema_ctx;
  (void)data;
  (void)data_len;
}

static void
right_msg_hdlr(void *ctx, const uint8_t *data, size_t data_len)
{
  struct test_schema_ctx *schema_ctx = (struct test_schema_ctx *)ctx;

  (void)schema_ctx;
  (void)data;
  (void)data_len;
}

static void
left_on_state_change(void *ctx, ratp_con_state old_state,
    ratp_con_state new_state, ratp_status status)
{
  struct test_schema_ctx *schema_ctx = (struct test_schema_ctx *)ctx;

  (void)schema_ctx;
  (void)new_state;
  (void)old_state;
  (void)status;
}

static void
right_on_state_change(void *ctx, ratp_con_state old_state,
    ratp_con_state new_state, ratp_status status)
{
  struct test_schema_ctx *schema_ctx = (struct test_schema_ctx *)ctx;

  (void)schema_ctx;
  (void)new_state;
  (void)old_state;
  (void)status;
}

static bool
left_timer_init(void *ctx, void **timer, ratp_timer_type timer_type, struct ratp_timeout_callback cb)
{
  struct test_schema_ctx *schema_ctx = (struct test_schema_ctx *)ctx;
  struct timer **t = (struct timer **)timer;

  *t = &schema_ctx->left_timers[timer_type];
  (*t)->cb = cb;
  (*t)->armed = false;

  return true;
}

static void
left_timer_start(void *ctx, void *timer, uint32_t timeout_ms)
{
  struct test_schema_ctx *schema_ctx = (struct test_schema_ctx *)ctx;
  struct timer *t = (struct timer *)timer;

  t->armed = true;
  t->start_time = schema_ctx->left_time_ms;
  t->timeout_ms = timeout_ms;
}

static void
left_timer_stop(void *ctx, void *timer)
{
  (void)ctx;
  struct timer *t = (struct timer *)timer;

  t->armed = false;
}

static uint32_t
left_timer_elapsed_ms(void *ctx, void *timer)
{
  struct test_schema_ctx *schema_ctx = (struct test_schema_ctx *)ctx;
  struct timer *t = (struct timer *)timer;

  return schema_ctx->left_time_ms - t->start_time;
}

static bool
left_timer_destroy(void *ctx, void *timer)
{
  (void)ctx;
  struct timer *t = (struct timer *)timer;
  memset(&t->cb, 0, sizeof(t->cb));
  t->armed = false;
  t->timeout_ms = 0;

  return true;
}

static bool
right_timer_init(void *ctx, void **timer, ratp_timer_type timer_type, struct ratp_timeout_callback cb)
{
  struct test_schema_ctx *schema_ctx = (struct test_schema_ctx *)ctx;
  struct timer **t = (struct timer **)timer;

  *t = &schema_ctx->right_timers[timer_type];
  (*t)->cb = cb;
  (*t)->armed = false;

  return true;
}

static void
right_timer_start(void *ctx, void *timer, uint32_t timeout_ms)
{
  struct test_schema_ctx *schema_ctx = (struct test_schema_ctx *)ctx;
  struct timer *t = (struct timer *)timer;

  t->armed = true;
  t->start_time = schema_ctx->right_time_ms;
  t->timeout_ms = timeout_ms;
}

static void
right_timer_stop(void *ctx, void *timer)
{
  (void)ctx;
  struct timer *t = (struct timer *)timer;

  t->armed = false;
}

static uint32_t
right_timer_elapsed_ms(void *ctx, void *timer)
{
  struct test_schema_ctx *schema_ctx = (struct test_schema_ctx *)ctx;
  struct timer *t = (struct timer *)timer;

  return schema_ctx->right_time_ms - t->start_time;
}

static bool
right_timer_destroy(void *ctx, void *timer)
{
  (void)ctx;
  struct timer *t = (struct timer *)timer;
  memset(&t->cb, 0, sizeof(t->cb));
  t->armed = false;
  t->timeout_ms = 0;

  return true;
}

static void
store_rx_packet(void *ctx, const struct ratp_pkt *pkt)
{
  struct packet_queue *rx_pkt_queue = (struct packet_queue *)ctx;
  if (!packet_queue_push(rx_pkt_queue, pkt))
  {
    fprintf(stderr, "ERROR: Packet queue full!\n");
  }
}

static void
mdl_err_handler(void *ctx, uint8_t pkt_data_len, uint8_t mdl)
{
  (void)ctx;
  (void)pkt_data_len;
  (void)mdl;
}

static bool
pkt_data_eq(const struct ratp_pkt *a, const struct ratp_pkt *b)
{
  size_t i;
  size_t data_ai;
  size_t data_bi;

  if (!ratp_pkt_has_data(a) && !ratp_pkt_has_data(b))
  {
    /* Neither packet has data */
    return true;
  }

  if (a->hdr.len != b->hdr.len)
  {
    /* Length mismatch */
    return false;
  }

  data_ai = a->data.data_start;
  data_bi = b->data.data_start;
  for (i = 0; i < a->hdr.len; i++)
  {
    if (a->data.data_base[data_ai] != b->data.data_base[data_bi])
    {
      return false;
    }

    data_ai++;
    data_ai %= a->data.data_base_len;

    data_bi++;
    data_bi %= b->data.data_base_len;
  }

  return true;
}

static bool
pkt_eq(const struct ratp_pkt *a, const struct ratp_pkt *b)
{
  return a->hdr.ctrl == b->hdr.ctrl /* CTRL matches */
      && a->hdr.len == b->hdr.len   /* LEN matches */
      && pkt_data_eq(a, b);         /* DATA matches */
}

static void
left_logger_fn(void *ctx, ratp_log_level level, const char *fmt, va_list args)
{
  char *log_buf = (char *)ctx;
  size_t log_buf_len = strlen(log_buf);
  assert(log_buf_len <= LOG_BUF_SIZE);
  size_t log_buf_space = LOG_BUF_SIZE - log_buf_len;
  int rc;


  rc = snprintf(&log_buf[log_buf_len], log_buf_space, "< %s: ", log_level_strmap[level]);
  log_buf_len += (size_t)rc < log_buf_space ? rc : log_buf_space;
  log_buf_space = LOG_BUF_SIZE - log_buf_len;
  rc = vsnprintf(&log_buf[log_buf_len], log_buf_space, fmt, args);
  log_buf_len += (size_t)rc < log_buf_space ? rc : log_buf_space;
  log_buf_space = LOG_BUF_SIZE - log_buf_len;
  if (log_buf_space > 1)
  {
    log_buf[log_buf_len++] = '\n';
    log_buf[log_buf_len] = '\0';
  }
}

static void
right_logger_fn(void *ctx, ratp_log_level level, const char *fmt, va_list args)
{
  char *log_buf = (char *)ctx;
  size_t log_buf_len = strlen(log_buf);
  assert(log_buf_len <= LOG_BUF_SIZE);
  size_t log_buf_space = LOG_BUF_SIZE - log_buf_len;
  int rc;


  rc = snprintf(&log_buf[log_buf_len], log_buf_space, "> %s: ", log_level_strmap[level]);
  log_buf_len += (size_t)rc < log_buf_space ? rc : log_buf_space;
  log_buf_space = LOG_BUF_SIZE - log_buf_len;
  rc = vsnprintf(&log_buf[log_buf_len], log_buf_space, fmt, args);
  log_buf_len += (size_t)rc < log_buf_space ? rc : log_buf_space;
  log_buf_space = LOG_BUF_SIZE - log_buf_len;
  if (log_buf_space > 1)
  {
    log_buf[log_buf_len++] = '\n';
    log_buf[log_buf_len] = '\0';
  }
}
