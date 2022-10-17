#ifndef RATP_LOGGING
#error "RATP_LOGGING Must be defined for logging functions to be called"
#endif /* RATP_LOGGING */

#include "ratp_log.h"

#include "test_ratp_log.h"

#include "unit_test.h"

#include <stddef.h>
#include <stdbool.h>

static void
test_ratp_log_fn(void *ctx, ratp_log_level level, const char *fmt, va_list args)
{
  bool *called = (bool *)ctx;

  (void)level;
  (void)fmt;
  (void)args;

  *called = true;
}

DECL_TEST(ratp_log_set_log_level)
{
  bool log_fn_called = false;

  /* Initialize logger to the ERROR level */
  ratp_log_init(RATP_LOG_LEVEL_ERROR, &log_fn_called, test_ratp_log_fn);

  LOG_FATAL("Fatal error: %s", "test fatal error");

  ASSERT(log_fn_called);
  log_fn_called = false;

  LOG_WARN("Warning: %s", "test warning");
  ASSERT(!log_fn_called);

  /* Set the log level to the DEBUG level */
  ratp_log_set_log_level(RATP_LOG_LEVEL_DEBUG);

  LOG_INFO("Info: %s", "test message");
  ASSERT(log_fn_called);

  TEST_END();
}

DECL_TEST(ratp_log)
{
  bool log_fn_called = false;

  /* Initialize logger to the DEBUG level */
  ratp_log_init(RATP_LOG_LEVEL_DEBUG, &log_fn_called, test_ratp_log_fn);

  LOG_FATAL("Fatal error: %s", "test fatal error");

  ASSERT(log_fn_called);
  log_fn_called = false;

  LOG_WARN("Warning: %s", "test warning");
  ASSERT(log_fn_called);
  log_fn_called = false;

  /* Initialize logger without logging function */
  ratp_log_init(RATP_LOG_LEVEL_DEBUG, &log_fn_called, NULL);

  LOG_FATAL("Fatal error: %s", "test fatal error");
  ASSERT(!log_fn_called);

  TEST_END();
}
