#include "ratp.h"
#include "ratp_packet_parser.h" /* for RATP_MAXIMUM_DATA_LENGTH */

#include "test_ratp.h"

#include "unit_test.h"

#include <stddef.h>
#include <stdlib.h>

static bool tx_called;
static void
test_ratp_tx_fn(void *ctx, const uint8_t *data, size_t data_len)
{
  (void)ctx;
  (void)data;
  (void)data_len;

  tx_called = true;
}

static bool msg_hdlr_called;
static void
test_ratp_msg_hdlr_fn(void *ctx, const uint8_t *data, size_t data_len)
{
  (void)ctx;
  (void)data;
  (void)data_len;

  msg_hdlr_called = true;
}

static bool on_state_change_called;
static ratp_con_state on_state_change_old_state;
static ratp_con_state on_state_change_new_state;
static ratp_status on_state_change_status;
static void
test_ratp_on_state_change_fn(void *ctx, ratp_con_state old_state,
    ratp_con_state new_state, ratp_status status)
{
  (void)ctx;

  on_state_change_called = true;
  on_state_change_old_state = old_state;
  on_state_change_new_state = new_state;
  on_state_change_status = status;
}

#define GREY "\033[0;90m"
#define YELLOW "\033[0;33m"
#define RED "\033[0;31m"
#define BOLD_RED "\033[1;31m"
#define RESET "\033[0m"

static int ratp_timer_init_fail_after = -1; /* Never fail by default */
static bool
test_ratp_timer_init_fn(void *ctx, void **timer, ratp_timer_type timer_type,
    struct ratp_timeout_callback cb)
{
  (void)ctx;
  (void)timer;
  (void)timer_type;
  (void)cb;

  if (ratp_timer_init_fail_after < 0)
  {
    /* Timer never fails */
    return true;
  }
  else if (ratp_timer_init_fail_after == 0)
  {
    /* Timer fell to zero, time to fail! */
    return false;
  }
  else
  {
    ratp_timer_init_fail_after--;
    return true;
  }
}

static void
test_ratp_timer_start_fn(void *ctx, void *timer, uint32_t timeout_ms)
{
  (void)ctx;
  (void)timer;
  (void)timeout_ms;
}

static void
test_ratp_timer_stop_fn(void *ctx, void *timer)
{
  (void)ctx;
  (void)timer;
}

static uint32_t
test_ratp_timer_elapsed_ms_fn(void *ctx, void *timer)
{
  (void)ctx;
  (void)timer;

  return 0;
}

static int ratp_timer_destroy_fail_after = -1; /* Never fail by default */
static bool
test_ratp_timer_destroy_fn(void *ctx, void *timer)
{
  (void)ctx;
  (void)timer;

  if (ratp_timer_destroy_fail_after < 0)
  {
    /* Timer never fails */
    return true;
  }
  else if (ratp_timer_destroy_fail_after == 0)
  {
    /* Timer fell to zero, time to fail! */
    return false;
  }
  else
  {
    ratp_timer_destroy_fail_after--;
    return true;
  }
}

static const struct ratp_callbacks default_cbs =
{
  .tx_cb =
  {
    .ctx = NULL,
    .tx = test_ratp_tx_fn,
  },
  .msg_hdlr_cb =
  {
    .ctx = NULL,
    .msg_hdlr = test_ratp_msg_hdlr_fn,
  },
  .on_state_change_cb =
  {
    .ctx = NULL,
    .on_state_change = test_ratp_on_state_change_fn,
  },
  .timer_cbs =
  {
    .ctx = NULL,
    .init = test_ratp_timer_init_fn,
    .start = test_ratp_timer_start_fn,
    .stop = test_ratp_timer_stop_fn,
    .elapsed_ms = test_ratp_timer_elapsed_ms_fn,
    .destroy = test_ratp_timer_destroy_fn,
  }
};

DECL_TEST(ratp_init)
{
  struct ratp ratp;
  struct ratp_callbacks good_cbs =
  {
    .tx_cb =
    {
      .ctx = NULL,
      .tx = test_ratp_tx_fn,
    },
    .msg_hdlr_cb =
    {
      .ctx = NULL,
      .msg_hdlr = test_ratp_msg_hdlr_fn,
    },
    .on_state_change_cb =
    {
      .ctx = NULL,
      .on_state_change = NULL,
    },
    .timer_cbs =
    {
      .ctx = NULL,
      .init = test_ratp_timer_init_fn,
      .start = test_ratp_timer_start_fn,
      .stop = test_ratp_timer_stop_fn,
      .elapsed_ms = test_ratp_timer_elapsed_ms_fn,
      .destroy = test_ratp_timer_destroy_fn,
    }
  };

  struct ratp_callbacks bad_cbs =
  {
    .tx_cb =
    {
      .ctx = NULL,
      .tx = NULL, /* TX function cannot be NULL */
    },
    .msg_hdlr_cb =
    {
      .ctx = NULL,
      .msg_hdlr = test_ratp_msg_hdlr_fn,
    },
    .on_state_change_cb =
    {
      .ctx = NULL,
      .on_state_change = NULL,
    },
    .timer_cbs =
    {
      .ctx = NULL,
      .init = test_ratp_timer_init_fn,
      .start = test_ratp_timer_start_fn,
      .stop = test_ratp_timer_stop_fn,
      .elapsed_ms = test_ratp_timer_elapsed_ms_fn,
      .destroy = test_ratp_timer_destroy_fn,
    }
  };

  ASSERT_EQ(ratp_init(&ratp, &good_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_init(&ratp, &bad_cbs), RATP_STATUS_ERROR_BAD_ARGUMENT);
  ASSERT_EQ(ratp_init(&ratp, NULL), RATP_STATUS_ERROR_BAD_ARGUMENT);
  ASSERT_EQ(ratp_init(NULL, &good_cbs), RATP_STATUS_ERROR_BAD_ARGUMENT);

  TEST_END();
}

DECL_TEST(ratp_init_failed_timer_init)
{
  struct ratp ratp;

  ratp_timer_init_fail_after = 0; /* Fail to initialize the first timer */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_ERROR_TIMER_INIT_FAILURE);

  ratp_timer_init_fail_after = 1; /* Fail to initialize the second timer */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_ERROR_TIMER_INIT_FAILURE);

  ratp_timer_init_fail_after = 1; /* Fail to initialize the second timer */
  ratp_timer_destroy_fail_after = 0; /* Fail to destroy the first timer */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_ERROR_TIMER_INIT_FAILURE);

  ratp_timer_destroy_fail_after = 0; /* Reset for other tests */

  ratp_timer_init_fail_after = NUM_RATP_TIMER_TYPES;
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);

  ratp_timer_init_fail_after = -1; /* Reset for other tests */

  TEST_END();
}

DECL_TEST(ratp_strerror)
{
  ASSERT_STR_NE(ratp_strerror(RATP_STATUS_OK), "Unknown");
  ASSERT_STR_NE(ratp_strerror(RATP_STATUS_ERROR_BAD_ARGUMENT), "Unknown");
  ASSERT_STR_EQ(ratp_strerror(NUM_RATP_STATUSES), "Unknown");

  TEST_END();
}

DECL_TEST(ratp_strtimer)
{
  ASSERT_STR_NE(ratp_strtimer(RATP_TIMER_TYPE_PACKET_ACK), "Unknown");
  ASSERT_STR_NE(ratp_strtimer(RATP_TIMER_TYPE_TIME_WAIT), "Unknown");
  ASSERT_STR_EQ(ratp_strtimer(NUM_RATP_TIMER_TYPES), "Unknown");

  TEST_END();
}

DECL_TEST(ratp_strstate)
{
  ASSERT_STR_EQ(ratp_strstate(RATP_CON_STATE_LISTEN), "Listen");
  ASSERT_STR_EQ(ratp_strstate(RATP_CON_STATE_CLOSED), "Closed");

  TEST_END();
}

DECL_TEST(ratp_listen)
{
  struct ratp ratp;

  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_listen(NULL), RATP_STATUS_ERROR_BAD_ARGUMENT);
  ASSERT_EQ(ratp_listen(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_LISTEN);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /* RATP already in listening state; cannot call listen again */
  ASSERT_EQ(ratp_listen(&ratp), RATP_STATUS_ERROR_INVALID_STATE);

  TEST_END();
}

DECL_TEST(ratp_connect)
{
  struct ratp ratp;

  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(NULL), RATP_STATUS_ERROR_BAD_ARGUMENT);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /* RATP already in SYN Sent state; cannot call connect again */
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_ERROR_INVALID_STATE);

  TEST_END();
}

DECL_TEST(ratp_send)
{
  struct ratp ratp;
  uint8_t test_msg[] = { 0x00, 0x01, 0x02 };

  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_send(NULL, test_msg, sizeof(test_msg)), RATP_STATUS_ERROR_BAD_ARGUMENT);
  ASSERT_EQ(ratp_send(&ratp, NULL, 1), RATP_STATUS_ERROR_BAD_ARGUMENT);
  ASSERT_EQ(ratp_send(&ratp, test_msg, sizeof(test_msg)), RATP_STATUS_ERROR_INVALID_STATE);

  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT_EQ(ratp_send(&ratp, NULL, 0), RATP_STATUS_OK);
  ASSERT_EQ(ratp_send(&ratp, test_msg, sizeof(test_msg)), RATP_STATUS_OK);

  TEST_END();
}

DECL_TEST(ratp_close)
{
  struct ratp ratp;

  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_close(NULL), RATP_STATUS_ERROR_BAD_ARGUMENT);
  ASSERT_EQ(ratp_close(&ratp), RATP_STATUS_ERROR_INVALID_STATE);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);

  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_close(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_listen)
{
  struct ratp ratp;
  struct ratp_pkt syn_pkt;

  /* Go to the listening state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_listen(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_LISTEN);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /* Bad input checks */
  ratp_rx_packet(NULL, &syn_pkt);
  ratp_rx_packet(&ratp, NULL);

  /*
   * Receive a SYN packet and check that a SYN ACK is sent and we go to SYN
   * Received state
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_pkt);
  ratp_pkt_set_ctrl_flag(&syn_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_sn(&syn_pkt, 0); /* SN = 0 */
  syn_pkt.hdr.len = 100; /* MDL = 100 */
  ratp_rx_packet(&ratp, &syn_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_LISTEN);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_RECEIVED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 100);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_listen_ack)
{
  struct ratp ratp;
  struct ratp_pkt ack_pkt;

  /* Go to the listening state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_listen(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_LISTEN);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive an ACK packet and check we send a reset
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&ack_pkt);
  ratp_pkt_set_ctrl_flag(&ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&ack_pkt, 0); /* SN = 0 */
  ratp_pkt_set_an(&ack_pkt, 0); /* AN = 0 */
  ratp_rx_packet(&ratp, &ack_pkt);

  ASSERT(tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_listen_rst)
{
  struct ratp ratp;
  struct ratp_pkt rst_pkt;

  /* Go to the listening state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_listen(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_LISTEN);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a RST. This should not change alter the connection state.
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&rst_pkt);
  ratp_pkt_set_ctrl_flag(&rst_pkt, RATP_PKT_HDR_CTRL_RST);
  ratp_pkt_set_sn(&rst_pkt, 0);
  ratp_pkt_set_an(&rst_pkt, 0);
  ratp_rx_packet(&ratp, &rst_pkt);

  ASSERT(!tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_listen_fin)
{
  struct ratp ratp;
  struct ratp_pkt fin_pkt;

  /* Go to the listening state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_listen(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_LISTEN);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a FIN. This should not change alter the connection state.
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&fin_pkt);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_FIN);
  ratp_pkt_set_sn(&fin_pkt, 0);
  ratp_pkt_set_an(&fin_pkt, 0);
  ratp_rx_packet(&ratp, &fin_pkt);

  ASSERT(!tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_syn_sent)
{
  struct ratp ratp;
  struct ratp_pkt syn_ack_pkt;

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN ACK packet and check that an ACK is sent
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_ack_pkt);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&syn_ack_pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&syn_ack_pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  syn_ack_pkt.hdr.len = 42; /* MDL = 42 */
  ratp_rx_packet(&ratp, &syn_ack_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 42);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_syn_sent_bad_an)
{
  struct ratp ratp;
  struct ratp_pkt syn_ack_pkt;

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN ACK packet with the wrong AN
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_ack_pkt);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&syn_ack_pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&syn_ack_pkt, !ratp.tcb.sn); /* Wrong AN! */
  syn_ack_pkt.hdr.len = 42; /* MDL = 42 */
  ratp_rx_packet(&ratp, &syn_ack_pkt);

  /* A reset should have been sent */
  ASSERT(tx_called);
  /* ... But we are still in the SYN_SENT state */
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_syn_sent_rst)
{
  struct ratp ratp;
  struct ratp_pkt rst_pkt;

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /* Receive a reset, this would indicate the receiver was not listening */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&rst_pkt);
  ratp_pkt_set_ctrl_flag(&rst_pkt, RATP_PKT_HDR_CTRL_RST);
  ratp_pkt_set_ctrl_flag(&rst_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&rst_pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&rst_pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  ratp_rx_packet(&ratp, &rst_pkt);

  ASSERT(!tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_ERROR_CONNECTION_REFUSED);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_syn_sent_syn)
{
  struct ratp ratp;
  struct ratp_pkt syn_pkt;

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /* Receive a SYN, this would indicate a simultaneous connection attempt */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_pkt);
  ratp_pkt_set_ctrl_flag(&syn_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_sn(&syn_pkt, 0); /* SN = 0 */
  syn_pkt.hdr.len = 100; /* MDL = 100 */
  ratp_rx_packet(&ratp, &syn_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_RECEIVED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.sn, 0);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 100);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_syn_sent_fin)
{
  struct ratp ratp;
  struct ratp_pkt fin_pkt;

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /* Receive a FIN, this is not expected during connection initiation */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&fin_pkt);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_FIN);
  ratp_pkt_set_sn(&fin_pkt, 0); /* SN = 0 */
  ratp_rx_packet(&ratp, &fin_pkt);

  ASSERT(!tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_syn_recvd_close_bad_sn)
{
  struct ratp ratp;
  struct ratp_pkt syn_pkt;
  struct ratp_pkt fin_pkt;

  /* Go to the listening state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_listen(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_LISTEN);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN packet and check that a SYN ACK is sent and we go to SYN
   * Received state
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_pkt);
  ratp_pkt_set_ctrl_flag(&syn_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_sn(&syn_pkt, 0); /* SN = 0 */
  syn_pkt.hdr.len = 100; /* MDL = 100 */
  ratp_rx_packet(&ratp, &syn_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_LISTEN);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_RECEIVED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 100);

  /*
   * Receive a FIN packet with the wrong SN. This should be ignored.
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&fin_pkt);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_FIN);
  ratp_pkt_set_next_sn(&fin_pkt, !ratp.tcb.rn); /* Wrong SN! */
  ratp_rx_packet(&ratp, &fin_pkt);

  ASSERT(!tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}
DECL_TEST(ratp_rx_packet_syn_recvd_no_ack)
{
  struct ratp ratp;
  struct ratp_pkt syn_pkt;
  struct ratp_pkt fin_pkt;

  /* Go to the listening state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_listen(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_LISTEN);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN packet and check that a SYN ACK is sent and we go to SYN
   * Received state
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_pkt);
  ratp_pkt_set_ctrl_flag(&syn_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_sn(&syn_pkt, 0); /* SN = 0 */
  syn_pkt.hdr.len = 100; /* MDL = 100 */
  ratp_rx_packet(&ratp, &syn_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_LISTEN);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_RECEIVED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 100);

  /*
   * Receive a packet with no ACK. This should be ignored.
   */
  tx_called = false;
  on_state_change_called = false;

  ratp_pkt_init(&fin_pkt);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_FIN);
  ratp_pkt_set_next_sn(&fin_pkt, ratp.tcb.rn);
  ratp_rx_packet(&ratp, &fin_pkt);

  ASSERT(!tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_syn_recvd_listen_bad_ack)
{
  struct ratp ratp;
  struct ratp_pkt syn_pkt;
  struct ratp_pkt ack_pkt;

  /* Go to the listening state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_listen(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_LISTEN);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN packet and check that a SYN ACK is sent and we go to SYN
   * Received state
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_pkt);
  ratp_pkt_set_ctrl_flag(&syn_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_sn(&syn_pkt, 0); /* SN = 0 */
  syn_pkt.hdr.len = 100; /* MDL = 100 */
  ratp_rx_packet(&ratp, &syn_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_LISTEN);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_RECEIVED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 100);

  /*
   * Receive an ACK packet with the wrong AN. This triggers a reset.
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&ack_pkt);
  ratp_pkt_set_ctrl_flag(&ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_next_sn(&ack_pkt, ratp.tcb.rn);
  ratp_pkt_set_next_an(&ack_pkt, !ratp.tcb.sn); /* Wrong AN! */
  ratp_rx_packet(&ratp, &ack_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_LISTEN);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_ERROR_CONNECTION_RESET);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_syn_recvd_connect_bad_ack)
{
  struct ratp ratp;
  struct ratp_pkt syn_pkt;
  struct ratp_pkt ack_pkt;

  /* Go to the listening state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN packet and check that a SYN ACK is sent and we go to SYN
   * Received state
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_pkt);
  ratp_pkt_set_ctrl_flag(&syn_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_sn(&syn_pkt, 0); /* SN = 0 */
  syn_pkt.hdr.len = 100; /* MDL = 100 */
  ratp_rx_packet(&ratp, &syn_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_RECEIVED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 100);

  /*
   * Receive an ACK packet with the wrong AN. This triggers a reset.
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&ack_pkt);
  ratp_pkt_set_ctrl_flag(&ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_next_sn(&ack_pkt, ratp.tcb.rn);
  ratp_pkt_set_next_an(&ack_pkt, !ratp.tcb.sn); /* Wrong AN! */
  ratp_rx_packet(&ratp, &ack_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_ERROR_CONNECTION_RESET);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_established_close_bad_sn)
{
  struct ratp ratp;
  struct ratp_pkt syn_ack_pkt;
  struct ratp_pkt fin_pkt;

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN ACK packet and check that an ACK is sent
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_ack_pkt);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&syn_ack_pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&syn_ack_pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  syn_ack_pkt.hdr.len = 42; /* MDL = 42 */
  ratp_rx_packet(&ratp, &syn_ack_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 42);

  /* Receive a FIN with the wrong SN. This should be ignored. */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&fin_pkt);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_FIN);
  ratp_pkt_set_next_sn(&fin_pkt, !ratp.tcb.rn); /* Wrong SN! */
  ratp_rx_packet(&ratp, &fin_pkt);

  ASSERT(!tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_established_no_ack)
{
  struct ratp ratp;
  struct ratp_pkt syn_ack_pkt;
  struct ratp_pkt no_ack_pkt;

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN ACK packet and check that an ACK is sent
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_ack_pkt);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&syn_ack_pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&syn_ack_pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  syn_ack_pkt.hdr.len = 42; /* MDL = 42 */
  ratp_rx_packet(&ratp, &syn_ack_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 42);

  /* Receive a packet with no ACK flag. This should be ignored. */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&no_ack_pkt);
  ratp_pkt_set_next_sn(&no_ack_pkt, ratp.tcb.rn);
  ratp_rx_packet(&ratp, &no_ack_pkt);

  ASSERT(!tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_established_bad_an)
{
  struct ratp ratp;
  struct ratp_pkt syn_ack_pkt;
  struct ratp_pkt bad_an_pkt;
  const uint8_t data[] = { 0x01, 0x02 };
  const struct ratp_ring_buf_idx data_ring_buf_idx =
  {
    .data_base = data,
    .data_start = 0,
    .data_base_len = sizeof(data)
  };

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN ACK packet and check that an ACK is sent
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_ack_pkt);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&syn_ack_pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&syn_ack_pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  syn_ack_pkt.hdr.len = 42; /* MDL = 42 */
  ratp_rx_packet(&ratp, &syn_ack_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 42);

  /* Receive an ACK with the wrong AN. This will still be processed. */
  tx_called = false;
  msg_hdlr_called = false;
  on_state_change_called = false;

  ratp_pkt_init_with_data(&bad_an_pkt, &data_ring_buf_idx);
  ratp_pkt_set_ctrl_flag(&bad_an_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_ctrl_flag(&bad_an_pkt, RATP_PKT_HDR_CTRL_EOR);
  ratp_pkt_set_next_sn(&bad_an_pkt, ratp.tcb.rn);
  ratp_pkt_set_next_an(&bad_an_pkt, !ratp.tcb.sn); /* Wrong AN! */
  bad_an_pkt.hdr.len = sizeof(data);
  ratp_rx_packet(&ratp, &bad_an_pkt);

  ASSERT(tx_called);
  ASSERT(msg_hdlr_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_established_fin_data_pending)
{
  struct ratp ratp;
  struct ratp_pkt syn_ack_pkt;
  struct ratp_pkt fin_pkt;
  const uint8_t data[] = { 0x01, 0x02 };

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN ACK packet and check that an ACK is sent
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_ack_pkt);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&syn_ack_pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&syn_ack_pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  syn_ack_pkt.hdr.len = 42; /* MDL = 42 */
  ratp_rx_packet(&ratp, &syn_ack_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 42);

  /* Send a data packet (this will not be acknowledged) */
  tx_called = false;
  ASSERT_EQ(ratp_send(&ratp, data, sizeof(data)), RATP_STATUS_OK);
  ASSERT(tx_called);

  /* Receive an FIN. This will drop our unacknowledged data. */
  tx_called = false;
  on_state_change_called = false;

  ratp_pkt_init(&fin_pkt);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_FIN);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_next_sn(&fin_pkt, ratp.tcb.rn);
  ratp_pkt_set_next_an(&fin_pkt, !ratp.tcb.sn); /* Don't ACK the data packet! */
  ratp_rx_packet(&ratp, &fin_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_LAST_ACK);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_fin_wait_no_fin)
{
  struct ratp ratp;
  struct ratp_pkt syn_ack_pkt;
  struct ratp_pkt non_fin_pkt;

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN ACK packet and check that an ACK is sent
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_ack_pkt);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&syn_ack_pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&syn_ack_pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  syn_ack_pkt.hdr.len = 42; /* MDL = 42 */
  ratp_rx_packet(&ratp, &syn_ack_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 42);

  /* Close the connection */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  ASSERT_EQ(ratp_close(&ratp), RATP_STATUS_OK);
  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_FIN_WAIT);


  /* Receive an non-FIN packet. This will be ignored. */
  tx_called = false;
  on_state_change_called = false;

  ratp_pkt_init(&non_fin_pkt);
  ratp_pkt_set_ctrl_flag(&non_fin_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_next_sn(&non_fin_pkt, ratp.tcb.rn);
  ratp_pkt_set_next_an(&non_fin_pkt, ratp.tcb.sn);
  ratp_rx_packet(&ratp, &non_fin_pkt);

  ASSERT(!tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_fin_wait_no_ack)
{
  struct ratp ratp;
  struct ratp_pkt syn_ack_pkt;
  struct ratp_pkt non_ack_pkt;

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN ACK packet and check that an ACK is sent
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_ack_pkt);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&syn_ack_pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&syn_ack_pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  syn_ack_pkt.hdr.len = 42; /* MDL = 42 */
  ratp_rx_packet(&ratp, &syn_ack_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 42);

  /* Close the connection */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  ASSERT_EQ(ratp_close(&ratp), RATP_STATUS_OK);
  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_FIN_WAIT);


  /* Receive an non-ACK packet. This will be ignored. */
  tx_called = false;
  on_state_change_called = false;

  ratp_pkt_init(&non_ack_pkt);
  ratp_pkt_set_ctrl_flag(&non_ack_pkt, RATP_PKT_HDR_CTRL_FIN);
  ratp_pkt_set_next_sn(&non_ack_pkt, ratp.tcb.rn);
  ratp_rx_packet(&ratp, &non_ack_pkt);

  ASSERT(!tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_fin_wait_fin_with_data)
{
  struct ratp ratp;
  struct ratp_pkt syn_ack_pkt;
  struct ratp_pkt fin_pkt;
  const uint8_t data[] = { 0x01, 0x02 };
  const struct ratp_ring_buf_idx data_ring_buf_idx =
  {
    .data_base = data,
    .data_start = 0,
    .data_base_len = sizeof(data)
  };

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN ACK packet and check that an ACK is sent
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_ack_pkt);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&syn_ack_pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&syn_ack_pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  syn_ack_pkt.hdr.len = 42; /* MDL = 42 */
  ratp_rx_packet(&ratp, &syn_ack_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 42);

  /* Close the connection */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  ASSERT_EQ(ratp_close(&ratp), RATP_STATUS_OK);
  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_FIN_WAIT);


  /* Receive an FIN ACK with data. This will trigger a reset. */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */

  ratp_pkt_init_with_data(&fin_pkt, &data_ring_buf_idx);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_FIN);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_next_sn(&fin_pkt, ratp.tcb.rn);
  ratp_pkt_set_next_an(&fin_pkt, ratp.tcb.sn);
  fin_pkt.hdr.len = sizeof(data);
  ratp_rx_packet(&ratp, &fin_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_CLOSED);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_last_ack_bad_an)
{
  struct ratp ratp;
  struct ratp_pkt syn_ack_pkt;
  struct ratp_pkt fin_pkt;
  struct ratp_pkt ack_pkt;

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN ACK packet and check that an ACK is sent
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_ack_pkt);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&syn_ack_pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&syn_ack_pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  syn_ack_pkt.hdr.len = 42; /* MDL = 42 */
  ratp_rx_packet(&ratp, &syn_ack_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 42);


  /* Receive a FIN */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */

  ratp_pkt_init(&fin_pkt);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_FIN);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_next_sn(&fin_pkt, ratp.tcb.rn);
  ratp_pkt_set_next_an(&fin_pkt, ratp.tcb.sn);
  ratp_rx_packet(&ratp, &fin_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_LAST_ACK);

  /* Receive an ACK with the wrong AN. This should be ignored. */
  tx_called = false;
  on_state_change_called = false;

  ratp_pkt_init(&ack_pkt);
  ratp_pkt_set_ctrl_flag(&ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_next_sn(&ack_pkt, ratp.tcb.rn);
  ratp_pkt_set_next_an(&ack_pkt, !ratp.tcb.sn); /* Wrong AN! */
  ratp_rx_packet(&ratp, &ack_pkt);

  ASSERT(!tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_closing_bad_an)
{
  struct ratp ratp;
  struct ratp_pkt syn_ack_pkt;
  struct ratp_pkt fin_pkt;
  struct ratp_pkt ack_pkt;

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN ACK packet and check that an ACK is sent
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_ack_pkt);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&syn_ack_pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&syn_ack_pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  syn_ack_pkt.hdr.len = 42; /* MDL = 42 */
  ratp_rx_packet(&ratp, &syn_ack_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 42);

  /* Close the connection */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */

  ASSERT_EQ(ratp_close(&ratp), RATP_STATUS_OK);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_FIN_WAIT);


  /* Receive a FIN */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */

  ratp_pkt_init(&fin_pkt);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_FIN);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_next_sn(&fin_pkt, ratp.tcb.rn);
  ratp_pkt_set_next_an(&fin_pkt, !ratp.tcb.sn); /* Wrong AN => Simultaneous close */
  ratp_rx_packet(&ratp, &fin_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_CLOSING);

  /* Receive an ACK with the wrong AN. This should be ignored. */
  tx_called = false;
  on_state_change_called = false;

  ratp_pkt_init(&ack_pkt);
  ratp_pkt_set_ctrl_flag(&ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_next_sn(&ack_pkt, ratp.tcb.rn);
  ratp_pkt_set_next_an(&ack_pkt, !ratp.tcb.sn); /* Wrong AN! */
  ratp_rx_packet(&ratp, &ack_pkt);

  ASSERT(!tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_time_wait_no_fin)
{
  struct ratp ratp;
  struct ratp_pkt syn_ack_pkt;
  struct ratp_pkt fin_pkt;
  struct ratp_pkt ack_pkt;

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /*
   * Receive a SYN ACK packet and check that an ACK is sent
   */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */

  ratp_pkt_init(&syn_ack_pkt);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&syn_ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&syn_ack_pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&syn_ack_pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  syn_ack_pkt.hdr.len = 42; /* MDL = 42 */
  ratp_rx_packet(&ratp, &syn_ack_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);
  ASSERT_EQ(ratp.tcb.rn, 0);
  ASSERT_EQ(ratp.tcb.mdl, 42);

  /* Close the connection */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */

  ASSERT_EQ(ratp_close(&ratp), RATP_STATUS_OK);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_FIN_WAIT);


  /* Receive a FIN ACK */
  tx_called = false;
  on_state_change_called = false;
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */

  ratp_pkt_init(&fin_pkt);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_FIN);
  ratp_pkt_set_ctrl_flag(&fin_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_next_sn(&fin_pkt, ratp.tcb.rn);
  ratp_pkt_set_next_an(&fin_pkt, ratp.tcb.sn);
  ratp_rx_packet(&ratp, &fin_pkt);

  ASSERT(tx_called);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_TIME_WAIT);

  /* Receive an ACK. This should be ignored. */
  tx_called = false;
  on_state_change_called = false;

  ratp_pkt_init(&ack_pkt);
  ratp_pkt_set_ctrl_flag(&ack_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_next_sn(&ack_pkt, ratp.tcb.rn);
  ratp_pkt_set_next_an(&ack_pkt, ratp.tcb.sn);
  ratp_rx_packet(&ratp, &ack_pkt);

  ASSERT(!tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_closed_reset)
{
  struct ratp ratp;
  struct ratp_pkt rst_pkt;

  /* Initialize to the closed state */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);

  /*
   * Receive a reset packet. This should be ignored.
   */
  tx_called = false;
  on_state_change_called = false;

  ratp_pkt_init(&rst_pkt);
  ratp_pkt_set_ctrl_flag(&rst_pkt, RATP_PKT_HDR_CTRL_RST);
  ratp_pkt_set_sn(&rst_pkt, 0);
  ratp_rx_packet(&ratp, &rst_pkt);

  ASSERT(!tx_called);
  ASSERT(!on_state_change_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_msg_hdlr)
{
  struct ratp ratp;
  struct ratp_pkt pkt;
  const uint8_t test_data[] = {
    0x00, 0x01, 0x02
  };
  const uint8_t test_data2[] = {
    0x03, 0x04
  };
  struct ratp_ring_buf_idx test_data_ring_buf_idx =
  {
    .data_base = test_data,
    .data_start = 0,
    .data_base_len = sizeof(test_data)
  };
  struct ratp_ring_buf_idx test_data2_ring_buf_idx =
  {
    .data_base = test_data2,
    .data_start = 0,
    .data_base_len = sizeof(test_data2)
  };

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /* Receive a SYN-ACK to put us into the ESTABLISHED state */
  ratp_pkt_init(&pkt);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  pkt.hdr.len = 42; /* MDL = 42 */

  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ratp_rx_packet(&ratp, &pkt);

  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /* Receive a data packet without EOR */
  ratp_pkt_init_with_data(&pkt, &test_data_ring_buf_idx);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&pkt, 1); /* SN = 1 */
  ratp_pkt_set_next_an(&pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  pkt.hdr.len = sizeof(test_data);

  msg_hdlr_called = false;
  ratp_rx_packet(&ratp, &pkt);

  ASSERT(!msg_hdlr_called);

  /* Receive a data packet with EOR */
  ratp_pkt_init_with_data(&pkt, &test_data2_ring_buf_idx);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_EOR);
  ratp_pkt_set_sn(&pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  pkt.hdr.len = sizeof(test_data2);

  msg_hdlr_called = false;
  ratp_rx_packet(&ratp, &pkt);

  ASSERT(msg_hdlr_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_msg_hdlr_overflow)
{
  struct ratp ratp;
  struct ratp_pkt pkt;
  uint8_t test_data[RATP_MAXIMUM_DATA_LENGTH];
  memset(test_data, 0, sizeof(test_data));
  const uint8_t test_data2[] = {
    0x01, 0x02
  };
  struct ratp_ring_buf_idx test_data_ring_buf_idx =
  {
    .data_base = test_data,
    .data_start = 0,
    .data_base_len = sizeof(test_data)
  };
  struct ratp_ring_buf_idx test_data2_ring_buf_idx =
  {
    .data_base = test_data2,
    .data_start = 0,
    .data_base_len = sizeof(test_data2)
  };

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /* Receive a SYN-ACK to put us into the ESTABLISHED state */
  ratp_pkt_init(&pkt);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  pkt.hdr.len = 42; /* MDL = 42 */

  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ratp_rx_packet(&ratp, &pkt);

  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /* Receive a data packets without EOR which fill up the receive buffer */
  int sn = 1;
  size_t i;
  for (i = 0; i < ((RATP_RECEIVE_BUFFER_LEN + (RATP_MAXIMUM_DATA_LENGTH - 1)) / RATP_MAXIMUM_DATA_LENGTH); i++)
  {
    ratp_pkt_init_with_data(&pkt, &test_data_ring_buf_idx);
    ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_ACK);
    ratp_pkt_set_sn(&pkt, sn);
    sn = !sn; /* Flip SN for next packet */
    ratp_pkt_set_next_an(&pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
    pkt.hdr.len = RATP_MAXIMUM_DATA_LENGTH;

    msg_hdlr_called = false;
    ratp_rx_packet(&ratp, &pkt);

    ASSERT(!msg_hdlr_called);
  }

  /* Receive a data packet with EOR */
  ratp_pkt_init_with_data(&pkt, &test_data2_ring_buf_idx);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_EOR);
  ratp_pkt_set_sn(&pkt, sn);
  ratp_pkt_set_next_an(&pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  pkt.hdr.len = sizeof(test_data2);

  msg_hdlr_called = false;
  ratp_rx_packet(&ratp, &pkt);

  /* Not called since message did not fit in the receive buffer */
  ASSERT(!msg_hdlr_called);

  TEST_END();
}

DECL_TEST(ratp_rx_packet_msg_hdlr_overflow_so)
{
  struct ratp ratp;
  struct ratp_pkt pkt;
  uint8_t test_data[RATP_MAXIMUM_DATA_LENGTH];
  memset(test_data, 0, sizeof(test_data));
  const uint8_t test_data2[] = {
    0x01
  };
  struct ratp_ring_buf_idx test_data_ring_buf_idx =
  {
    .data_base = test_data,
    .data_start = 0,
    .data_base_len = sizeof(test_data)
  };

  /* Go to the SYN Sent state */
  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);
  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_CLOSED);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /* Receive a SYN-ACK to put us into the ESTABLISHED state */
  ratp_pkt_init(&pkt);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(&pkt, 0); /* SN = 0 */
  ratp_pkt_set_next_an(&pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  pkt.hdr.len = 42; /* MDL = 42 */

  on_state_change_called = false;
  on_state_change_old_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_new_state = RATP_CON_STATE_TIME_WAIT; /* Garbage value */
  on_state_change_status = RATP_STATUS_ERROR_BAD_ARGUMENT; /* Garbage value */
  ratp_rx_packet(&ratp, &pkt);

  ASSERT(on_state_change_called);
  ASSERT_EQ(on_state_change_old_state, RATP_CON_STATE_SYN_SENT);
  ASSERT_EQ(on_state_change_new_state, RATP_CON_STATE_ESTABLISHED);
  ASSERT_EQ(on_state_change_status, RATP_STATUS_OK);

  /* Receive a data packets without EOR which fill up the receive buffer */
  int sn = 1;
  size_t i;
  for (i = 0; i < ((RATP_RECEIVE_BUFFER_LEN + (RATP_MAXIMUM_DATA_LENGTH - 1)) / RATP_MAXIMUM_DATA_LENGTH); i++)
  {
    ratp_pkt_init_with_data(&pkt, &test_data_ring_buf_idx);
    ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_ACK);
    ratp_pkt_set_sn(&pkt, sn);
    sn = !sn; /* Flip SN for next packet */
    ratp_pkt_set_next_an(&pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
    pkt.hdr.len = RATP_MAXIMUM_DATA_LENGTH;

    msg_hdlr_called = false;
    ratp_rx_packet(&ratp, &pkt);

    ASSERT(!msg_hdlr_called);
  }

  /* Receive a data packet with EOR */
  ratp_pkt_init(&pkt);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_SO);
  ratp_pkt_set_ctrl_flag(&pkt, RATP_PKT_HDR_CTRL_EOR);
  ratp_pkt_set_sn(&pkt, sn);
  ratp_pkt_set_next_an(&pkt, ratp.tcb.sn); /* AN = Sent SN + 1 mod 2 */
  pkt.hdr.len = test_data2[0];

  msg_hdlr_called = false;
  ratp_rx_packet(&ratp, &pkt);

  /* Not called since message did not fit in the receive buffer */
  ASSERT(!msg_hdlr_called);

  TEST_END();
}

DECL_TEST(ratp_send_full_buffer)
{
  struct ratp ratp;
  uint8_t send_data = 'x';

  /* Go to the SYN Sent state so we can start to fill the send queue */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);

  ASSERT_EQ(RATP_DATA_QUEUE_MAX_MESSAGES, 8); /* Assumed value for testing */
  ASSERT_EQ(ratp_send(&ratp, &send_data, 1), RATP_STATUS_OK);
  ASSERT_EQ(ratp_send(&ratp, &send_data, 1), RATP_STATUS_OK);
  ASSERT_EQ(ratp_send(&ratp, &send_data, 1), RATP_STATUS_OK);
  ASSERT_EQ(ratp_send(&ratp, &send_data, 1), RATP_STATUS_OK);
  ASSERT_EQ(ratp_send(&ratp, &send_data, 1), RATP_STATUS_OK);
  ASSERT_EQ(ratp_send(&ratp, &send_data, 1), RATP_STATUS_OK);
  ASSERT_EQ(ratp_send(&ratp, &send_data, 1), RATP_STATUS_OK);
  ASSERT_EQ(ratp_send(&ratp, &send_data, 1), RATP_STATUS_OK);

  /* At this point the send queue should be full */

  ASSERT_EQ(ratp_send(&ratp, &send_data, 1), RATP_STATUS_ERROR_BUFFER_FULL);

  TEST_END();
}

DECL_TEST(ratp_send_data_full_buffer)
{
  struct ratp ratp;

  /* Go to the SYN Sent state so we can start to fill the send queue */
  ASSERT_EQ(ratp_init(&ratp, &default_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_connect(&ratp), RATP_STATUS_OK);

  uint8_t *send_data = malloc(RATP_DATA_QUEUE_MAX_DATA);
  ASSERT(send_data != NULL);
  memset(send_data, 'x', RATP_DATA_QUEUE_MAX_DATA);

  ASSERT_EQ(ratp_send(&ratp, send_data, RATP_DATA_QUEUE_MAX_DATA), RATP_STATUS_OK);

  /* At this point the data queue should be full */

  uint8_t more_data[] = { 1, 2 };
  ASSERT_EQ(ratp_send(&ratp, more_data, 2), RATP_STATUS_ERROR_BUFFER_FULL);

  TEST_END();
}
