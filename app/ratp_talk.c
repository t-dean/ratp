#include "ratp.h"
#include "ratp_packet_parser.h"

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/time.h>

/*******************/
/* Structs / Enums */
/*******************/

struct timer
{
  struct ratp_timeout_callback cb;
  uint32_t timer_start;
  uint32_t timer_end;
  bool timer_running;
};

struct timer_list_node;
struct timer_list_node
{
  struct timer timer;
  struct timer_list_node *next;
};

struct timer_list
{
  struct timer_list_node *head;
};

struct ratp_talk_ctx
{
  struct ratp ratp;
  struct timer_list timers;
  int port_fd;
  ratp_log_level log_level;
};

/**************/
/* Prototypes */
/**************/

static void
timer_list_init(struct timer_list *timer_list);

static struct timer_list_node *
timer_list_add(struct timer_list *timer_list, struct ratp_timeout_callback cb);

static int
timer_list_wait_time(struct timer_list *timer_list);

static void
timer_list_run_expired(struct timer_list *timer_list);

static void
timer_list_remove(struct timer_list *timer_list, struct timer_list_node *node);

static void
timer_list_deinit(struct timer_list *timer_list);

/* RATP Callbacks */

static void
ratp_talk_log(void *ctx, ratp_log_level log_level, const char *fmt, va_list args);

static void
ratp_talk_rx_pkt(void *ctx, const struct ratp_pkt *pkt);

static void
ratp_talk_mdl_error(void *ctx, uint8_t pkt_data_len, uint8_t mdl);

static void
ratp_talk_tx(void *ctx, const uint8_t *data, size_t data_len);

static void
ratp_talk_msg_hdlr(void *ctx, const uint8_t *data, size_t data_len);

static void
ratp_talk_state_change(void *ctx, ratp_con_state old_state, ratp_con_state new_state, ratp_status status);

static bool
ratp_talk_timer_init(void *ctx, void **timer, ratp_timer_type type, struct ratp_timeout_callback cb);

static void
ratp_talk_timer_start(void *ctx, void *timer, uint32_t timeout_ms);

static void
ratp_talk_timer_stop(void *ctx, void *timer);

static uint32_t
ratp_talk_timer_elapsed_ms(void *ctx, void *timer);

static bool
ratp_talk_timer_destroy(void *ctx, void *timer);

/********************/
/* Global Functions */
/********************/

int main(int argc, char *argv[])
{
  int rv = 0;
  const char *progname = argv[0];
  struct ratp_talk_ctx app_ctx;
  struct ratp_pkt_parser ratp_parser;
  int c;
  int verbosity = 0;
  bool listen = false;
  const char *preloaded_message = NULL;
  int rc;
  ratp_status ratp_rc;
  ssize_t read_rc;
  uint8_t buf[512];
  struct pollfd fds[2]; // port_fd (0) and stdin (1)
  int poll_timeout;
  struct ratp_callbacks cbs =
  {
    { /* ratp_tx_callback */
      &app_ctx.port_fd,
      ratp_talk_tx
    },
    { /* ratp_msg_hdlr_callback */
      NULL,
      ratp_talk_msg_hdlr
    },
    { /* ratp_on_state_change_callback */
      NULL,
      ratp_talk_state_change
    },
    { /* ratp_log_callback */
      &app_ctx,
      ratp_talk_log
    },
    { /* ratp_timer_callbacks */
      &app_ctx.timers,
      ratp_talk_timer_init,
      ratp_talk_timer_start,
      ratp_talk_timer_stop,
      ratp_talk_timer_elapsed_ms,
      ratp_talk_timer_destroy
    }
  };

  struct ratp_pkt_parser_callbacks parser_cbs =
  {
    &app_ctx.ratp,
    ratp_talk_rx_pkt,
    ratp_talk_mdl_error
  };

  /* Parse command line */
  while ((c = getopt(argc, argv, "vlm:")) != -1)
  {
    switch (c)
    {
      case 'l':
        listen = true;
        break;
      case 'v':
        verbosity++;
        break;
      case 'm':
        preloaded_message = optarg;
        break;
      case '?':
      default:
        fprintf(stderr, "usage: %s [-vl] [-m <message>] <tty>\n", progname);
        rv = 1; goto done;
    }
  }

  argc -= optind;
  argv += optind;

  if (argc != 1)
  {
    fprintf(stderr, "usage: %s [-vl] <tty>\n", progname);
    rv = 1; goto done;
  }

  switch (verbosity)
  {
    case 0:
      app_ctx.log_level = RATP_LOG_LEVEL_FATAL;
      break;
    case 1:
      app_ctx.log_level = RATP_LOG_LEVEL_WARN;
      break;
    case 2:
      app_ctx.log_level = RATP_LOG_LEVEL_INFO;
      break;
    default:
      app_ctx.log_level = RATP_LOG_LEVEL_DEBUG;
      break;
  }

  if ((app_ctx.port_fd = open(argv[0], O_RDWR)) == -1)
  {
    perror(argv[0]);
    rv = 1; goto done;
  }

  /* Initialize program resources */
  timer_list_init(&app_ctx.timers);

  if ((ratp_rc = ratp_pkt_parser_init(&ratp_parser, &parser_cbs)) != RATP_STATUS_OK)
  {
    fprintf(stderr, "Error initializing RATP parser: %s\n", ratp_strerror(ratp_rc));
    rv = 1; goto cleanup;
  }

  if ((ratp_rc = ratp_init(&app_ctx.ratp, &cbs)) != RATP_STATUS_OK)
  {
    fprintf(stderr, "Error initializing RATP: %s\n", ratp_strerror(ratp_rc));
    rv = 1; goto cleanup;
  }

  if (listen)
  {
    if ((ratp_rc = ratp_listen(&app_ctx.ratp)) != RATP_STATUS_OK)
    {
      fprintf(stderr, "Error listening RATP: %s\n", ratp_strerror(ratp_rc));
      rv = 1; goto cleanup;
    }
  }
  else
  {
    if ((ratp_rc = ratp_connect(&app_ctx.ratp)) != RATP_STATUS_OK)
    {
      fprintf(stderr, "Error connecting RATP: %s\n", ratp_strerror(ratp_rc));
      rv = 1; goto cleanup;
    }
  }

  if (preloaded_message != NULL)
  {
    if ((ratp_rc = ratp_send(&app_ctx.ratp, (const uint8_t *)preloaded_message, strlen(preloaded_message))) != RATP_STATUS_OK)
    {
      fprintf(stderr, "Error sending preloaded message: %s\n", ratp_strerror(ratp_rc));
      rv = 1; goto cleanup;
    }
  }

  /*
   * Main loop:
   *  - Send data from stdin
   *  - Process RATP data received on the port
   */
  while (true)
  {
    fds[0].fd = app_ctx.port_fd;
    fds[0].events = POLLIN;

    fds[1].fd = STDIN_FILENO;
    fds[1].events = POLLIN;

    poll_timeout = timer_list_wait_time(&app_ctx.timers);

    rc = poll(fds, 2, poll_timeout);
    if (rc < 0)
    {
      perror("poll");
      rv = 1; goto cleanup;
    }
    if (rc == 0)
    {
      /* Nothing ready but a timer expired */
      timer_list_run_expired(&app_ctx.timers);
    }
    else
    {
      if (fds[0].revents & POLLIN)
      {
        /* Data from peer available */
        read_rc = read(fds[0].fd, &buf, sizeof(buf));
        if (read_rc == -1)
        {
          perror(argv[0]);
        }
        else if (read_rc == 0)
        {
          fprintf(stderr, "%s: empty read", argv[0]);
          rv = 0; goto cleanup;
        }
        else
        {
          if ((ratp_rc = ratp_pkt_parser_rx_bytes(&ratp_parser, buf, (size_t)read_rc)) != RATP_STATUS_OK)
          {
            fprintf(stderr, "RATP parser error: %s\n", ratp_strerror(ratp_rc));
          }
        }
      }
      if (fds[1].revents & POLLIN)
      {
        /* Data from STDIN available */
        read_rc = read(fds[1].fd, &buf, sizeof(buf));
        if (read_rc == -1)
        {
          perror("stdin");
        }
        else if (read_rc == 0)
        {
          (void)ratp_close(&app_ctx.ratp);
        }
        else
        {
          if ((ratp_rc = ratp_send(&app_ctx.ratp, buf, (size_t)read_rc)) != RATP_STATUS_OK)
          {
            fprintf(stderr, "Send error: %s\n", ratp_strerror(ratp_rc));
          }
        }
      }
      timer_list_run_expired(&app_ctx.timers);
    }
  }

cleanup:
  timer_list_deinit(&app_ctx.timers);

done:
  return rv;
}

/*******************/
/* Local Functions */
/*******************/

static uint32_t
gettime(void)
{
  struct timespec ts;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
  {
    perror("clock_gettime");
  }

  // Intentional unsigned integer wrapping
  return (uint32_t)ts.tv_sec * 1000UL + (uint32_t)ts.tv_nsec / 1000000UL;
}

static void
timer_list_init(struct timer_list *timer_list)
{
  assert(timer_list != NULL);

  timer_list->head = NULL;
}

static struct timer_list_node *
timer_list_add(struct timer_list *timer_list, struct ratp_timeout_callback cb)
{
  struct timer_list_node *new_node;

  assert(timer_list != NULL);

  if ((new_node = malloc(sizeof(*new_node))) == NULL)
  {
    perror("malloc");
    exit(1);
  }

  new_node->timer.timer_running = false;
  new_node->timer.cb = cb;
  new_node->next = timer_list->head;

  timer_list->head = new_node;

  return new_node;
}

static int
timer_list_wait_time(struct timer_list *timer_list)
{
  struct timer_list_node *curr;
  int min_time = -1; // -1 => wait forever; when cast to unsigned is INT_MAX
  uint32_t now = gettime();

  assert(timer_list != NULL);

  for (curr = timer_list->head; curr != NULL; curr = curr->next)
  {
    if (curr->timer.timer_running)
    {
      if (now - curr->timer.timer_end <= now - curr->timer.timer_start)
      {
        // We have already passed the timer's end time => zero wait time
        min_time = 0;
      }
      else if (curr->timer.timer_end - now < (uint32_t)min_time)
      {
        /*
         * Narrowing from uint32_t to int is safe
         * since timeouts are capped at INT_MAX
         */
        min_time = (int)(curr->timer.timer_end - now);
      }
    }
  }

  return min_time;
}

static void
timer_list_run_expired(struct timer_list *timer_list)
{
  struct timer_list_node *curr;
  uint32_t now = gettime();

  assert(timer_list != NULL);

  for (curr = timer_list->head; curr != NULL; curr = curr->next)
  {
    if (curr->timer.timer_running)
    {
      if (now - curr->timer.timer_end <= now - curr->timer.timer_start)
      {
        curr->timer.timer_running = false;
        curr->timer.cb.timeout(curr->timer.cb.ctx);
      }
    }
  }
}

static void
timer_list_remove(struct timer_list *timer_list, struct timer_list_node *node)
{
  struct timer_list_node *curr;
  struct timer_list_node *prev = NULL;

  assert(timer_list != NULL);

  for (curr = timer_list->head; curr != NULL; curr = curr->next)
  {
    if (curr == node)
    {
      if (prev != NULL)
      {
        prev->next = curr->next;
      }
      else
      {
        timer_list->head = curr->next;
      }
      free(curr);
      break;
    }

    prev = curr;
  }
}

static void
timer_list_deinit(struct timer_list *timer_list)
{
  struct timer_list_node *tmp;

  assert(timer_list != NULL);

  while (timer_list->head != NULL)
  {
    tmp = timer_list->head;
    timer_list->head = tmp->next;
    free(tmp);
  }
}

#define GREY "\033[0;90m"
#define YELLOW "\033[0;33m"
#define RED "\033[0;31m"
#define BOLD_RED "\033[1;31m"
#define RESET "\033[0m"

static const char * const log_level_strmap[] =
{
  [RATP_LOG_LEVEL_DEBUG] = GREY "DEBUG" RESET,
  [RATP_LOG_LEVEL_INFO] = "INFO",
  [RATP_LOG_LEVEL_WARN] = YELLOW "WARNING" RESET,
  [RATP_LOG_LEVEL_ERROR] = RED "ERROR" RESET,
  [RATP_LOG_LEVEL_FATAL] = BOLD_RED "FATAL" RESET,
};

static void
ratp_talk_log(void *ctx, ratp_log_level log_level, const char *fmt, va_list args)
{
  struct ratp_talk_ctx *app_ctx = (struct ratp_talk_ctx *)ctx;
  struct timeval tv;
  time_t t;
  struct tm *info;
  char buf[32];

  assert(log_level <= RATP_LOG_LEVEL_FATAL);

  if (log_level < app_ctx->log_level)
  {
    return;
  }

  gettimeofday(&tv, NULL);
  t = tv.tv_sec;
  info = localtime(&t);
  strftime(buf, sizeof(buf), "%H:%M:%S", info);

  printf("[%s.%06ld] %s: ", buf, (long int)tv.tv_usec, log_level_strmap[log_level]);
  vprintf(fmt, args);
  putc('\n', stdout);
}

static void
ratp_talk_rx_pkt(void *ctx, const struct ratp_pkt *pkt)
{
  struct ratp *ratp = (struct ratp *)ctx;

  assert(ratp != NULL);
  assert(pkt != NULL);

  ratp_rx_packet(ratp, pkt);
}

static void
ratp_talk_mdl_error(void *ctx, uint8_t pkt_data_len, uint8_t mdl)
{
  (void)ctx;
  fprintf(stderr, "Packet too large: %" PRIu8 " > %" PRIu8 "\n", pkt_data_len, mdl);
}

static void
ratp_talk_tx(void *ctx, const uint8_t *data, size_t data_len)
{
  assert(ctx != NULL);
  assert(data_len == 0 || data != NULL);

  int fd = *(int *)ctx;
  ssize_t rc;

  if (rand() % 10 == 0)
  {
    /* Devious lick */
    printf("I'm in your data, snatchin your bytes :)\n");
    data_len--;
  }

  rc = write(fd, data, data_len);
  if (rc < 0)
  {
    perror("write");
  }
  else if ((size_t)rc != data_len)
  {
    fprintf(stderr, "write: Data truncated (%zu != %zu)\n", (size_t)rc, data_len);
  }
}

static void
ratp_talk_msg_hdlr(void *ctx, const uint8_t *data, size_t data_len)
{
  size_t i;

  (void)ctx;

  assert(data_len == 0 || data != NULL);

  for (i = 0; i < data_len; i++)
  {
    if (isprint(data[i]))
    {
      putchar(data[i]);
    }
  }

  putchar('\n');
}

static void
ratp_talk_state_change(void *ctx, ratp_con_state old_state, ratp_con_state new_state, ratp_status status)
{
  (void)ctx;
  (void)old_state;

  if (new_state == RATP_CON_STATE_CLOSED)
  {
    exit(status != RATP_STATUS_OK); // false == 0 == EXIT_SUCCESS, true == 1 == EXIT_FAILURE
  }
}

static bool
ratp_talk_timer_init(void *ctx, void **timer, ratp_timer_type type, struct ratp_timeout_callback cb)
{
  (void)type; // unused
  struct timer_list *timers = (struct timer_list *)ctx;
  struct timer_list_node *new_timer;

  assert(timers != NULL);
  assert(timer != NULL);

  new_timer = timer_list_add(timers, cb);

  *timer = new_timer;

  return true;
}

static void
ratp_talk_timer_start(void *ctx, void *timer, uint32_t timeout_ms)
{
  struct timer_list_node *timer_to_start = (struct timer_list_node *)timer;
  (void)ctx;

  assert(timer_to_start != NULL);

  /*
   * Since we are using poll timeouts as the mechanism to trigger the timer, a
   * timeout larger then INT_MAX milliseconds will not be representable as the
   * argument to poll is an int. INT_MAX milliseconds is equivalent to ~25 days
   * so it is unlikely a timer for that length of time will be required.
   */

  if (timeout_ms > INT_MAX)
  {
    fprintf(stderr, "Error starting timer: timeout value too large\n");
    return;
  }

  timer_to_start->timer.timer_start = gettime();
  timer_to_start->timer.timer_end = timer_to_start->timer.timer_start + timeout_ms;
  timer_to_start->timer.timer_running = true;
}

static void
ratp_talk_timer_stop(void *ctx, void *timer)
{
  struct timer_list_node *timer_to_stop = (struct timer_list_node *)timer;
  (void)ctx;

  assert(timer_to_stop != NULL);

  timer_to_stop->timer.timer_running = false;
}

static uint32_t
ratp_talk_timer_elapsed_ms(void *ctx, void *timer)
{
  struct timer_list_node *timer_to_check = (struct timer_list_node *)timer;
  (void)ctx;

  assert(timer_to_check != NULL);
  assert(timer_to_check->timer.timer_running);

  return gettime() - timer_to_check->timer.timer_start;
}

static bool
ratp_talk_timer_destroy(void *ctx, void *timer)
{
  struct timer_list *timers = (struct timer_list *)ctx;
  struct timer_list_node *timer_to_del = (struct timer_list_node *)timer;

  assert(timers != NULL);
  assert(timer_to_del != NULL);

  timer_list_remove(timers, timer_to_del);

  return true;
}
