#include "ratp.h"
#include "ratp_packet_parser.h" /* For RATP_MAXIMUM_DATA_LENGTH */

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#define MSEC_TO_SEC (1e-3)
#define SEC_TO_MSEC (1e3)
#define MAX_BEHAVIORS (7U) /*!< Maximum number of behaviors for a given state */

/******************************************************************************/
/*                             Logging Functions                              */
/******************************************************************************/

/**
 * Log a debugging message
 */
#define LOG_DEBUG(...) ratp_log(ratp, RATP_LOG_LEVEL_DEBUG, __VA_ARGS__)

/**
 * Log an informational message
 */
#define LOG_INFO(...) ratp_log(ratp, RATP_LOG_LEVEL_INFO, __VA_ARGS__)

/**
 * Log a warning message
 */
#define LOG_WARN(...) ratp_log(ratp, RATP_LOG_LEVEL_WARN, __VA_ARGS__)

/**
 * Log an error message
 */
#define LOG_ERROR(...) ratp_log(ratp, RATP_LOG_LEVEL_ERROR, __VA_ARGS__)

/**
 * Log a fatal error message
 */
#define LOG_FATAL(...) ratp_log(ratp, RATP_LOG_LEVEL_FATAL, __VA_ARGS__)

#ifdef RATP_LOGGING
/**
 * Log a message with printf-style formatting
 *
 * \param[in] level The log level of the message
 * \param[in] fmt The printf-style message format string
 */
static void
ratp_log(struct ratp *ratp, ratp_log_level level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
#else
/** Empty macro to disable logging */
#define ratp_log(ratp, level, ...)
#endif

/******************************************************************************/
/*                            Data Queue Functions                            */
/******************************************************************************/

/**
 * Initialize the packet data queue
 *
 * \param[out] data_queue The data queue to initialize
 */
static void
ratp_data_queue_init(struct ratp_data_queue *data_queue);

/**
 * Push a block of data into the back of the data queue
 *
 * \param[in,out] data_queue The data queue to push into
 * \param[in] data The data to push
 * \param[in] data_len The length of the data to push
 * \return true on success, false if there is insufficient space in the queue
 */
static bool
ratp_data_queue_push(struct ratp_data_queue *data_queue, const uint8_t *data, size_t data_len);

/**
 * Peek the first block of data in the data queue
 *
 * \param[in] data_queue The data queue to peek
 * \param[out] ring_buf_idx The index into the data ring buffer
 * \param[out] data_len The length of the block starting at index `data_start`
 * \return true on success, false if there is no data to peek
 */
static bool
ratp_data_queue_peek(struct ratp_data_queue *data_queue,
    struct ratp_ring_buf_idx *ring_buf_idx, size_t *data_len);

/**
 * Pop bytes off the head block of the data queue
 *
 * If the head block has no data after this call, it is removed.
 *
 * \param[in,out] data_queue The data queue from which to pop
 * \param[in] n The number of bytes to pop, must be less than or equal to the
 *              number of bytes remaining in the head block.
 */
static void
ratp_data_queue_pop(struct ratp_data_queue *data_queue, size_t n);

/**
 * Clear all data in the data queue
 *
 * \param[in,out] data_queue The data queue to clear
 */
static void
ratp_data_queue_clear(struct ratp_data_queue *data_queue);

/**
 * Initialize the user data receive buffer
 *
 * \param[out] ratp The RATP context who's receive buffer should be initialized
 */
static void
ratp_rx_buffer_init(struct ratp *ratp);

/**
 * Push data into the receive buffer
 *
 * \note If there is not enough space to store the data in the receive buffer,
 *       the buffer will be in an indeterminate state until the next
 *       ratp_rx_buffer_clear call and ratp_rx_buffer_would_overflow will return
 *       true.
 *
 * \param[in,out] ratp The RATP context
 * \param[in] pkt The data packet to push
 */
static void
ratp_rx_buffer_push(struct ratp *ratp, const struct ratp_pkt *pkt);

/**
 * Did the receive buffer not have the capacity to store the entire message?
 *
 * \param[in] ratp The RATP context
 * \return true if the received data would have overflowed the receive buffer
 */
static bool
ratp_rx_buffer_would_overflow(const struct ratp *ratp);

/**
 * Is the receive buffer currently empty?
 *
 * \param[in] ratp The RATP context
 * \return true if the receive buffer is empty, false otherwise
 */
static bool
ratp_rx_buffer_is_empty(const struct ratp *ratp);

/**
 * Clear the receive buffer
 *
 * \param[out] ratp The RATP context
 */
static void
ratp_rx_buffer_clear(struct ratp *ratp);

/******************************************************************************/
/*                           Packet creation helpers                          */
/******************************************************************************/

/**
 * Construct an ACK packet in response to a received packet
 *
 * \param[out] res_pkt The ACK response to the received packet
 * \param[in] tcb The current transmission control block
 * \param[in] pkt The received packet
 */
static void
make_ack(struct ratp_pkt *res_pkt, const struct ratp_tcb *tcb,
    const struct ratp_pkt *pkt);

/**
 * Construct a data packet
 *
 * \param[out] pkt The constructed data packet
 * \param[in] tcb The current transmission control block
 * \param[in] data The data to send with the packet
 * \param[in] data_len The length of data
 * \param[in] eor End of record flag
 */
static void
make_data_pkt(struct ratp_pkt *pkt, const struct ratp_tcb *tcb,
    const uint8_t *data, uint8_t data_len, bool eor);

/**
 * Construct a data packet from a ring buffer data source
 *
 * \param[out] pkt The constructed data packet
 * \param[in] tcb The current transmission control block
 * \param[in] ring_buf_idx The index into the data ring buffer
 * \param[in] data_len The length of data
 * \param[in] eor End of record flag
 */
static void
make_ring_data_pkt(struct ratp_pkt *pkt, const struct ratp_tcb *tcb,
    const struct ratp_ring_buf_idx *ring_buf_idx, uint8_t data_len, bool eor);

/**
 * Construct a data packet in response to a received packet
 *
 * \param[out] res_pkt The constructed data packet
 * \param[in] pkt The packet to which we are responding
 * \param[in] ring_buf_idx The index into the data ring buffer
 * \param[in] data_len The length of data
 * \param[in] eor End of record flag
 */
static void
make_ring_data_pkt_and_ack(struct ratp_pkt *res_pkt, const struct ratp_pkt *pkt,
    const struct ratp_ring_buf_idx *ring_buf_idx, uint8_t data_len, bool eor);

/**
 * Construct a SYN packet
 *
 * \param[out] pkt The constructed SYN packet
 * \param[in] tcb The current transmission control block
 */
static void
make_syn_pkt(struct ratp_pkt *pkt, const struct ratp_tcb *tcb);

/**
 * Construct a SYN-ACK packet in response to a received packet
 *
 * \param[out] res_pkt The SYN-ACK response to the received packet
 * \param[in] tcb The current transmission control block
 * \param[in] pkt The received packet
 */
static void
make_syn_pkt_and_ack(struct ratp_pkt *res_pkt, const struct ratp_tcb *tcb,
    const struct ratp_pkt *pkt);

/**
 * Construct a FIN packet
 *
 * \param[out] pkt The constructed FIN packet
 * \param[in] tcb The current transmission control block
 */
static void
make_fin_pkt(struct ratp_pkt *pkt, const struct ratp_tcb *tcb);

/**
 * Construct a FIN-ACK packet in response to a received packet
 *
 * \param[out] res_pkt The FIN-ACK response to the received packet
 * \param[in] tcb The current transmission control block
 * \param[in] pkt The received packet
 */
static void
make_fin_pkt_and_ack(struct ratp_pkt *res_pkt, const struct ratp_pkt *pkt);

/**
 * Construct a reset packet in response to a received packet
 *
 * \param[out] res_pkt The reset response to the received packet
 * \param[in] pkt The received packet
 */
static void
make_rst_pkt(struct ratp_pkt *res_pkt, const struct ratp_pkt *pkt);

/******************************************************************************/
/*                       Packet Transmission Functions                        */
/******************************************************************************/

/**
 * Try to transmit the next data packet, if available
 *
 * \param[in,out] ratp The RATP object
 * \param[in] pkt The packet we are responding to
 * \return true on successful transmission of a data packet, false otherwise
 */
static bool
tx_next_data_pkt(struct ratp *ratp, const struct ratp_pkt *pkt);

/**
 * Transmit a data packet
 *
 * \param[in,out] ratp The RATP object
 * \param[in,out] pkt The packet to transmit
 */
static void
tx_data_pkt(struct ratp *ratp, struct ratp_pkt *pkt);

/**
 * Transmit the next data packet, if available or send an empty ACK
 *
 * \param[in,out] ratp The RATP object
 * \param[in] pkt The packet we are responding to
 */
static void
tx_next_data_pkt_or_ack(struct ratp *ratp, const struct ratp_pkt *pkt);

/**
 * Transmit a packet which must be acknowledged
 *
 * \param[in,out] ratp The RATP object
 * \param[in] pkt The packet to send
 */
static void
tx_reliable_pkt(struct ratp *ratp, const struct ratp_pkt *pkt);

/**
 * Transmit a packet which may not be acknowledged
 *
 * \param[in,out] ratp The RATP object
 * \param[in] pkt The packet to send
 */
static void
tx_unreliable_pkt(struct ratp *ratp, const struct ratp_pkt *pkt);

/**
 * Serialize a packet to the on-wire format
 *
 * \param[out] buf The buffer to write the packet to
 * \param[in] buf_len The length of the buffer
 * \param[in] pkt The packet to serialize
 * \return The number of bytes written to the buffer or zero on error
 */
static size_t
serialize_pkt(uint8_t *buf, size_t buf_len, const struct ratp_pkt *pkt);

/******************************************************************************/
/*                      Packet Retransmission Functions                       */
/******************************************************************************/

/**
 * Retransmit the retransmit buffer
 *
 * \param[in,out] ctx The RATP object
 */
static void
rtx_timeout_hdlr(void *ctx);

/**
 * Check if we are currently retransmitting a packet
 *
 * \param[in] ratp The RATP object
 * \return true if we are retransmitting an unacknowledged packet, false otherwise
 */
static bool
rtx_in_progress(const struct ratp *ratp);

/**
 * Flush the retransmission packet
 *
 * \param[in,out] ratp The RATP object
 * \param[in] reason The reason the retransmission buffer is being flushed
 */
static void
flush_rtx_pkt(struct ratp *ratp, ratp_status reason);

/**
 * Flush the entire retransmission queue
 *
 * \param[in,out] ratp The RATP object
 * \param[in] reason The reason the retransmission queue is being flushed
 */
static void
flush_rtx_queue(struct ratp *ratp, ratp_status reason);

/**
 * Calculate the retransmit timeout given the smoothed round trip time (SRTT)
 *
 * \param[in] srtt The smoothed round trip time
 * \return The number of milliseconds for the retransmit timeout
 */
static uint32_t
calc_rtx_timeout(double srtt);

/******************************************************************************/
/*                         Time-Wait State Functions                          */
/******************************************************************************/

/**
 * Close the connection after the wait time expires
 *
 * \param[in,out] ctx The RATP object
 */
static void
time_wait_timeout_hdlr(void *ctx);

/**
 * Calculate the time-wait timeout given the smoothed round trip time (SRTT)
 *
 * \param[in] srtt The smoothed round trip time
 * \return The number of milliseconds for the time-wait state timeout
 */
static uint32_t
calc_time_wait_timeout(double srtt);

/******************************************************************************/
/*                          State Handling Functions                          */
/******************************************************************************/

/**
 * Update the connection state
 *
 * \param[in,out] ratp The RATP object
 * \param[in] new_state The new state to transition to
 * \param[in] reason The reason for the state transition
 */
static void
update_state(struct ratp *ratp, ratp_con_state new_state, ratp_status reason);

/**
 * Does some generic behavior for a given packet (e.g. validates sequence number
 * is as expected).
 *
 * A behavior function will be part of a chain of behaviors run for an incoming
 * packet depending on the current connection state.
 *
 * \param[in,out] ratp The RATP object
 * \param[in] pkt The incoming packet
 * \return true to continue with further packet processing behaviors, false to
 *         return without any further processing for the current packet
 */
typedef bool (*bhvr_fn)(struct ratp *ratp, const struct ratp_pkt *pkt);

static bool bhvr_a(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_b(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_c1(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_c2(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_d1(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_d2(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_d3(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_e(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_f1(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_f2(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_f3(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_h1(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_h2(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_h3(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_h4(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_h5(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_h6(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_i1(struct ratp *ratp, const struct ratp_pkt *pkt);
static bool bhvr_g(struct ratp *ratp, const struct ratp_pkt *pkt);

/**
 * Packet processing behavior chains for every possible connection state
 */
static const bhvr_fn bhvrs[][MAX_BEHAVIORS] =
{
  [RATP_CON_STATE_LISTEN]       = { bhvr_a,                                                                      NULL },
  [RATP_CON_STATE_SYN_SENT]     = {         bhvr_b,                                                              NULL },
  [RATP_CON_STATE_SYN_RECEIVED] = {                 bhvr_c1, bhvr_d1, bhvr_e, bhvr_f1, bhvr_h1,                  NULL },
  [RATP_CON_STATE_ESTABLISHED]  = {                 bhvr_c2, bhvr_d2, bhvr_e, bhvr_f2, bhvr_h2, bhvr_i1,         NULL },
  [RATP_CON_STATE_FIN_WAIT]     = {                 bhvr_c2, bhvr_d2, bhvr_e, bhvr_f3, bhvr_h3,                  NULL },
  [RATP_CON_STATE_LAST_ACK]     = {                 bhvr_c2, bhvr_d3, bhvr_e, bhvr_f3, bhvr_h4,                  NULL },
  [RATP_CON_STATE_CLOSING]      = {                 bhvr_c2, bhvr_d3, bhvr_e, bhvr_f3, bhvr_h5,                  NULL },
  [RATP_CON_STATE_TIME_WAIT]    = {                          bhvr_d3, bhvr_e, bhvr_f3, bhvr_h6,                  NULL },
  [RATP_CON_STATE_CLOSED]       = {                                                                      bhvr_g, NULL }
};

static const char * const strerror_map[NUM_RATP_STATUSES] =
{
  [RATP_STATUS_OK]                       = "OK",
  [RATP_STATUS_ERROR_BAD_ARGUMENT]       = "Bad argument",
  [RATP_STATUS_ERROR_CONNECTION_REFUSED] = "Connection refused",
  [RATP_STATUS_ERROR_CONNECTION_RESET]   = "Connection reset",
  [RATP_STATUS_ERROR_CONNECTION_CLOSING] = "Connection closing",
  [RATP_STATUS_ERROR_PACKET_TIMEOUT]     = "Packet retransmission limit reached",
  [RATP_STATUS_ERROR_INVALID_STATE]      = "Invalid state",
  [RATP_STATUS_ERROR_TIMER_INIT_FAILURE] = "Timer initialization failed",
  [RATP_STATUS_ERROR_BUFFER_FULL]        = "Internal buffer full",
};

static const char * const strstate_map[] =
{
  [RATP_CON_STATE_LISTEN]       = "Listen",
  [RATP_CON_STATE_SYN_SENT]     = "SYN Sent",
  [RATP_CON_STATE_SYN_RECEIVED] = "SYN Received",
  [RATP_CON_STATE_ESTABLISHED]  = "Established",
  [RATP_CON_STATE_FIN_WAIT]     = "FIN Wait",
  [RATP_CON_STATE_LAST_ACK]     = "Last ACK",
  [RATP_CON_STATE_CLOSING]      = "Closing",
  [RATP_CON_STATE_TIME_WAIT]    = "Time Wait",
  [RATP_CON_STATE_CLOSED]       = "Closed",
};

static const char * const strtimer_map[] =
{
  [RATP_TIMER_TYPE_PACKET_ACK] = "Packet acknowledgement timer",
  [RATP_TIMER_TYPE_TIME_WAIT]  = "Time wait state timer",
};

ratp_status
ratp_init(struct ratp *ratp, const struct ratp_callbacks *callbacks)
{
  struct ratp_timeout_callback packet_timeout_cb =
  {
    .ctx = ratp,
    .timeout = rtx_timeout_hdlr
  };

  struct ratp_timeout_callback time_wait_timeout_cb =
  {
    .ctx = ratp,
    .timeout = time_wait_timeout_hdlr
  };

  if (ratp == NULL ||
      callbacks == NULL ||
      callbacks->tx_cb.tx == NULL ||
      callbacks->msg_hdlr_cb.msg_hdlr == NULL ||
      callbacks->timer_cbs.init == NULL ||
      callbacks->timer_cbs.start == NULL ||
      callbacks->timer_cbs.stop == NULL ||
      callbacks->timer_cbs.elapsed_ms == NULL ||
      callbacks->timer_cbs.destroy == NULL)
  {
    return RATP_STATUS_ERROR_BAD_ARGUMENT;
  }

  ratp->cbs = *callbacks;

  ratp_data_queue_init(&ratp->data_queue);
  ratp_rx_buffer_init(ratp);

  ratp->state = RATP_CON_STATE_CLOSED;

  if (!ratp->cbs.timer_cbs.init(ratp->cbs.timer_cbs.ctx, &ratp->time_wait_timer,
        RATP_TIMER_TYPE_TIME_WAIT, time_wait_timeout_cb))
  {
    LOG_ERROR("timer [%s]: initialization failed", ratp_strtimer(RATP_TIMER_TYPE_TIME_WAIT));
    return RATP_STATUS_ERROR_TIMER_INIT_FAILURE;
  }

  if (!ratp->cbs.timer_cbs.init(ratp->cbs.timer_cbs.ctx, &ratp->rtx_pkt_timer,
        RATP_TIMER_TYPE_PACKET_ACK, packet_timeout_cb))
  {
    LOG_ERROR("timer [%s]: initialization failed", ratp_strtimer(RATP_TIMER_TYPE_PACKET_ACK));

    /* Free Time Wait timer's resources */
    if (!ratp->cbs.timer_cbs.destroy(ratp->cbs.timer_cbs.ctx, ratp->time_wait_timer))
    {
      LOG_ERROR("timer [%s]: destruction failed", ratp_strtimer(RATP_TIMER_TYPE_TIME_WAIT));
    }
    return RATP_STATUS_ERROR_TIMER_INIT_FAILURE;
  }

  ratp->srtt = RATP_RETRANSMIT_TIMEOUT_UBOUND_MS * MSEC_TO_SEC; /* Start at upper bound */
  ratp->rtx_buf_len = 0; /* no packet currently being retransmitted */

  LOG_DEBUG("RATP initialized to %s state", strstate_map[ratp->state]);

  return RATP_STATUS_OK;
}

ratp_status
ratp_listen(struct ratp *ratp)
{
  if (ratp == NULL)
  {
    return RATP_STATUS_ERROR_BAD_ARGUMENT;
  }

  if (ratp->state != RATP_CON_STATE_CLOSED)
  {
    return RATP_STATUS_ERROR_INVALID_STATE;
  }

  ratp->tcb.active_open = false;

  update_state(ratp, RATP_CON_STATE_LISTEN, RATP_STATUS_OK);

  return RATP_STATUS_OK;
}

ratp_status
ratp_connect(struct ratp *ratp)
{
  struct ratp_pkt syn_pkt;

  if (ratp == NULL)
  {
    return RATP_STATUS_ERROR_BAD_ARGUMENT;
  }

  if (ratp->state != RATP_CON_STATE_CLOSED)
  {
    return RATP_STATUS_ERROR_INVALID_STATE;
  }

  ratp->tcb.active_open = true;
  ratp->tcb.sn = 0;

  make_syn_pkt(&syn_pkt, &ratp->tcb);
  tx_reliable_pkt(ratp, &syn_pkt);

  update_state(ratp, RATP_CON_STATE_SYN_SENT, RATP_STATUS_OK);

  return RATP_STATUS_OK;
}

ratp_status
ratp_send(struct ratp *ratp, const uint8_t *data, size_t data_len)
{
  struct ratp_pkt data_pkt;

  if (ratp == NULL || (data == NULL && data_len > 0))
  {
    return RATP_STATUS_ERROR_BAD_ARGUMENT;
  }

  if (ratp->state != RATP_CON_STATE_ESTABLISHED
      && ratp->state != RATP_CON_STATE_SYN_SENT
      && ratp->state != RATP_CON_STATE_SYN_RECEIVED
      && ratp->state != RATP_CON_STATE_LISTEN)
  {
    return RATP_STATUS_ERROR_INVALID_STATE;
  }

  if (data_len == 0)
  {
    /* Zero size message => Nothing to send! */
    return RATP_STATUS_OK;
  }

  if (ratp->state == RATP_CON_STATE_ESTABLISHED
      && !rtx_in_progress(ratp)
      && data_len <= ratp->tcb.mdl)
  {
    /*
     * Optimization: If we can send the entire message now, don't copy into the
     * data queue. Send it immediately and return.
     */
    assert(ratp->data_queue.msg_lens_size == 0);

    make_data_pkt(&data_pkt, &ratp->tcb, data, (uint8_t)data_len, true);
    tx_data_pkt(ratp, &data_pkt);

    return RATP_STATUS_OK;
  }

  if (!ratp_data_queue_push(&ratp->data_queue, data, data_len))
  {
    LOG_ERROR("No space for message in data queue");
    return RATP_STATUS_ERROR_BUFFER_FULL;
  }

  if (ratp->state == RATP_CON_STATE_ESTABLISHED && !rtx_in_progress(ratp))
  {
    assert(ratp->data_queue.msg_lens_size == 1);

    /*
     * We would have sent the packet immediately if the data_len was less than
     * or equal to the MDL. Therefore, the data_len is more than the current
     * MDL. As a result, we can now send the first MDL bytes and pop them off
     * the data queue.
     */
    make_data_pkt(&data_pkt, &ratp->tcb, data, ratp->tcb.mdl, false);
    tx_data_pkt(ratp, &data_pkt);
    ratp_data_queue_pop(&ratp->data_queue, ratp->tcb.mdl);
  }

  return RATP_STATUS_OK;
}

ratp_status
ratp_close(struct ratp *ratp)
{
  struct ratp_pkt fin_pkt;
  ratp_status rv;

  if (ratp == NULL)
  {
    return RATP_STATUS_ERROR_BAD_ARGUMENT;
  }

  switch (ratp->state)
  {
    case RATP_CON_STATE_LISTEN:
    case RATP_CON_STATE_SYN_SENT:
      flush_rtx_queue(ratp, RATP_STATUS_ERROR_CONNECTION_CLOSING);
      update_state(ratp, RATP_CON_STATE_CLOSED, RATP_STATUS_OK);

      rv = RATP_STATUS_OK;
      break;
    case RATP_CON_STATE_SYN_RECEIVED:
    case RATP_CON_STATE_ESTABLISHED:
      flush_rtx_queue(ratp, RATP_STATUS_ERROR_CONNECTION_CLOSING);

      make_fin_pkt(&fin_pkt, &ratp->tcb);
      tx_reliable_pkt(ratp, &fin_pkt);

      update_state(ratp, RATP_CON_STATE_FIN_WAIT, RATP_STATUS_OK);

      rv = RATP_STATUS_OK;
      break;
    case RATP_CON_STATE_FIN_WAIT:
    case RATP_CON_STATE_LAST_ACK:
    case RATP_CON_STATE_CLOSING:
    case RATP_CON_STATE_TIME_WAIT:
    case RATP_CON_STATE_CLOSED:
    default:
      /* Connection is closed or is being closed */
      rv = RATP_STATUS_ERROR_INVALID_STATE;
      break;
  }

  return rv;
}

void
ratp_rx_packet(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  size_t i;
  size_t data_i;

  /* For printing packet data */
  static const char hextab[] =
  {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  };
  char hex_pkt[RATP_MAXIMUM_DATA_LENGTH * 2 + 1];

  if (ratp == NULL || pkt == NULL)
  {
    return;
  }

  /* Print packet data as hex */
  if (ratp_pkt_has_data(pkt))
  {
    data_i = pkt->data.data_start;
    for (i = 0; i < pkt->hdr.len; i++)
    {
      hex_pkt[i * 2] = hextab[pkt->data.data_base[data_i] >> 4U];
      hex_pkt[i * 2 + 1] = hextab[pkt->data.data_base[data_i] & 0x0fU];

      data_i++;
      data_i %= pkt->data.data_base_len;
    }
    hex_pkt[i * 2] = '\0';
  }
  else
  {
    hex_pkt[0] = '\0';
  }

  LOG_DEBUG("Processing packet: [%s %s %s %s SN=%" PRIu8 " AN=%" PRIu8 " %s %s] [len: %03" PRIu8 "] %s",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SYN) ? "SYN" : "---",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_ACK) ? "ACK" : "---",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_FIN) ? "FIN" : "---",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_RST) ? "RST" : "---",
      ratp_pkt_get_sn(pkt),
      ratp_pkt_get_an(pkt),
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_EOR) ? "EOR" : "---",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SO) ? "SO" : "--",
      pkt->hdr.len,
      hex_pkt);

  /* Perform each behavior for the current state */
  const ratp_con_state cur_state = ratp->state;
  for (i = 0; bhvrs[cur_state][i] != NULL; i++)
  {
    if (!bhvrs[cur_state][i](ratp, pkt))
    {
      /* Behavior returned false => stop processing the packet */
      break;
    }
  }

  LOG_DEBUG("Packet processing complete");
}

const char *
ratp_strerror(ratp_status status)
{
  return status < NUM_RATP_STATUSES ? strerror_map[status] : "Unknown";
}

const char *
ratp_strstate(ratp_con_state state)
{
  return strstate_map[state];
}

const char *
ratp_strtimer(ratp_timer_type timer)
{
  return timer < NUM_RATP_TIMER_TYPES ? strtimer_map[timer] : "Unknown";
}

#ifdef RATP_LOGGING
static void
ratp_log(struct ratp *ratp, ratp_log_level level, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  if (ratp->cbs.log_cb.log != NULL)
  {
    ratp->cbs.log_cb.log(ratp->cbs.log_cb.ctx, level, fmt, args);
  }

  va_end(args);
}
#endif

static void
ratp_data_queue_init(struct ratp_data_queue *data_queue)
{
  data_queue->msg_lens_head = 0;
  data_queue->msg_lens_tail = 0;
  data_queue->msg_lens_size = 0;

  data_queue->msg_data_head = 0;
  data_queue->msg_data_tail = 0;
  data_queue->msg_data_size = 0;
}

static bool
ratp_data_queue_push(struct ratp_data_queue *data_queue, const uint8_t *data, size_t data_len)
{
  size_t i;

  if (data_queue->msg_lens_size < RATP_DATA_QUEUE_MAX_MESSAGES
      && data_queue->msg_data_size + data_len <= RATP_DATA_QUEUE_MAX_DATA)
  {
    /* Add message length to the msg_lens queue */
    data_queue->msg_lens[data_queue->msg_lens_tail++] = data_len;
    data_queue->msg_lens_tail %= RATP_DATA_QUEUE_MAX_MESSAGES;
    data_queue->msg_lens_size++;

    /* Append message data to the msg_data queue */
    for (i = 0; i < data_len; i++)
    {
      data_queue->msg_data[data_queue->msg_data_tail++] = data[i];
      data_queue->msg_data_tail %= RATP_DATA_QUEUE_MAX_DATA;
    }
    data_queue->msg_data_size += data_len;

    return true;
  }

  return false;
}

static bool
ratp_data_queue_peek(struct ratp_data_queue *data_queue,
    struct ratp_ring_buf_idx *ring_buf_idx, size_t *data_len)
{
  if (data_queue->msg_lens_size > 0)
  {
    ring_buf_idx->data_base = &data_queue->msg_data[0];
    ring_buf_idx->data_start = data_queue->msg_data_head;
    ring_buf_idx->data_base_len = RATP_DATA_QUEUE_MAX_DATA;
    *data_len = data_queue->msg_lens[data_queue->msg_lens_head];
    return true;
  }

  return false;
}

static void
ratp_data_queue_pop(struct ratp_data_queue *data_queue, size_t n)
{
  assert(data_queue->msg_lens_size > 0);
  assert(n <= data_queue->msg_lens[data_queue->msg_lens_head]);

  /* Update msg_lens queue */
  data_queue->msg_lens[data_queue->msg_lens_head] -= n;

  if (data_queue->msg_lens[data_queue->msg_lens_head] == 0)
  {
    /* The entire message has been popped, remove it from the queue */
    data_queue->msg_lens_head++;
    data_queue->msg_lens_head %= RATP_DATA_QUEUE_MAX_MESSAGES;
    data_queue->msg_lens_size--;
  }

  /* Update msg_data queue */
  data_queue->msg_data_head += n;
  data_queue->msg_data_head %= RATP_DATA_QUEUE_MAX_DATA;
  data_queue->msg_data_size -= n;
}

static void
ratp_data_queue_clear(struct ratp_data_queue *data_queue)
{
  data_queue->msg_lens_head = 0;
  data_queue->msg_lens_tail = 0;
  data_queue->msg_lens_size = 0;

  data_queue->msg_data_head = 0;
  data_queue->msg_data_tail = 0;
  data_queue->msg_data_size = 0;
}

static void
ratp_rx_buffer_init(struct ratp *ratp)
{
  ratp->rx_buffer_len = 0;
}

static void
ratp_rx_buffer_push(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  const uint8_t *data_base;
  size_t data_start;
  size_t data_base_len;
  uint8_t data_len;
  size_t i;
  size_t data_i;

  assert(ratp_pkt_has_user_data(pkt));

  if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SO))
  {
    /* Single data byte stored in len */
    data_base = &pkt->hdr.len;
    data_start = 0;
    data_base_len = 1;
    data_len = 1;
  }
  else
  {
    data_base = pkt->data.data_base;
    data_start = pkt->data.data_start;
    data_base_len = pkt->data.data_base_len;
    data_len = pkt->hdr.len;
  }

  assert(RATP_RECEIVE_BUFFER_LEN >= RATP_MAXIMUM_DATA_LENGTH);
  if (ratp->rx_buffer_len < RATP_RECEIVE_BUFFER_LEN - data_len)
  {
    data_i = data_start;
    for (i = 0; i < data_len; i++)
    {
      ratp->rx_buffer[ratp->rx_buffer_len++] = data_base[data_i];
      data_i++;
      data_i %= data_base_len;
    }
  }
  else
  {
    /* Sentinel value to indicate receive buffer would overflow */
    ratp->rx_buffer_len = SIZE_MAX;
  }
}

static bool
ratp_rx_buffer_would_overflow(const struct ratp *ratp)
{
  return ratp->rx_buffer_len == SIZE_MAX;
}

static bool
ratp_rx_buffer_is_empty(const struct ratp *ratp)
{
  return ratp->rx_buffer_len == 0;
}

static void
ratp_rx_buffer_clear(struct ratp *ratp)
{
  ratp->rx_buffer_len = 0;
}

static void
make_ack(struct ratp_pkt *res_pkt, const struct ratp_tcb *tcb,
    const struct ratp_pkt *pkt)
{
  (void)tcb;
  ratp_pkt_init(res_pkt);
  ratp_pkt_set_ctrl_flag(res_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(res_pkt, ratp_pkt_get_an(pkt));
  ratp_pkt_set_next_an(res_pkt, ratp_pkt_get_sn(pkt));
}

static void
make_data_pkt(struct ratp_pkt *pkt, const struct ratp_tcb *tcb,
    const uint8_t *data, uint8_t data_len, bool eor)
{
  struct ratp_ring_buf_idx ring_buf_idx =
  {
    .data_base = data,
    .data_start = 0,
    .data_base_len = data_len
  };
  make_ring_data_pkt(pkt, tcb, &ring_buf_idx, data_len, eor);
}

static void
make_ring_data_pkt(struct ratp_pkt *pkt, const struct ratp_tcb *tcb,
    const struct ratp_ring_buf_idx *ring_buf_idx, uint8_t data_len, bool eor)
{
    ratp_pkt_init_with_data(pkt, ring_buf_idx);
    pkt->hdr.len = data_len;

    /* Configure the control bits */
    ratp_pkt_set_next_sn(pkt, tcb->sn);
    ratp_pkt_set_next_an(pkt, tcb->rn);
    /* Data must have ACK, otherwise the packet will be dropped in behavior f2 */
    ratp_pkt_set_ctrl_flag(pkt, RATP_PKT_HDR_CTRL_ACK);
    if (eor)
    {
      ratp_pkt_set_ctrl_flag(pkt, RATP_PKT_HDR_CTRL_EOR);
    }
}

static void
make_ring_data_pkt_and_ack(struct ratp_pkt *res_pkt, const struct ratp_pkt *pkt,
    const struct ratp_ring_buf_idx *ring_buf_idx, uint8_t data_len, bool eor)
{
    ratp_pkt_init_with_data(res_pkt, ring_buf_idx);
    res_pkt->hdr.len = data_len;

    /* Configure the control bits */
    ratp_pkt_set_sn(res_pkt, ratp_pkt_get_an(pkt));
    if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SYN) || ratp_pkt_has_user_data(pkt))
    {
      /* ACK reliable packet */
      ratp_pkt_set_next_an(res_pkt, ratp_pkt_get_sn(pkt));
    }
    else
    {
      /* Don't ACK an empty ACK */
      ratp_pkt_set_an(res_pkt, ratp_pkt_get_sn(pkt));
    }
    /* Data must have ACK, otherwise the packet will be dropped in behavior f2 */
    ratp_pkt_set_ctrl_flag(res_pkt, RATP_PKT_HDR_CTRL_ACK);
    if (eor)
    {
      ratp_pkt_set_ctrl_flag(res_pkt, RATP_PKT_HDR_CTRL_EOR);
    }
}

static void
make_syn_pkt(struct ratp_pkt *pkt, const struct ratp_tcb *tcb)
{
  ratp_pkt_init(pkt);
  pkt->hdr.len = RATP_MAXIMUM_DATA_LENGTH;
  ratp_pkt_set_ctrl_flag(pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_sn(pkt, tcb->sn);
  /* AN is not significant */
}

static void
make_syn_pkt_and_ack(struct ratp_pkt *res_pkt, const struct ratp_tcb *tcb,
    const struct ratp_pkt *pkt)
{
  ratp_pkt_init(res_pkt);
  res_pkt->hdr.len = RATP_MAXIMUM_DATA_LENGTH;
  ratp_pkt_set_ctrl_flag(res_pkt, RATP_PKT_HDR_CTRL_SYN);
  ratp_pkt_set_ctrl_flag(res_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(res_pkt, tcb->sn);
  ratp_pkt_set_next_an(res_pkt, ratp_pkt_get_sn(pkt));
}

static void
make_fin_pkt(struct ratp_pkt *pkt, const struct ratp_tcb *tcb)
{
  ratp_pkt_init(pkt);
  ratp_pkt_set_ctrl_flag(pkt, RATP_PKT_HDR_CTRL_FIN);
  /* FIN must have ACK, otherwise the packet will be dropped in behavior f2 */
  ratp_pkt_set_ctrl_flag(pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_next_sn(pkt, tcb->sn);
  ratp_pkt_set_next_an(pkt, tcb->rn);
}

static void
make_fin_pkt_and_ack(struct ratp_pkt *res_pkt, const struct ratp_pkt *pkt)
{
  ratp_pkt_init(res_pkt);
  ratp_pkt_set_ctrl_flag(res_pkt, RATP_PKT_HDR_CTRL_FIN);
  ratp_pkt_set_ctrl_flag(res_pkt, RATP_PKT_HDR_CTRL_ACK);
  ratp_pkt_set_sn(res_pkt, ratp_pkt_get_an(pkt));
  ratp_pkt_set_next_an(res_pkt, ratp_pkt_get_sn(pkt));
}

static void
make_rst_pkt(struct ratp_pkt *res_pkt, const struct ratp_pkt *pkt)
{
  ratp_pkt_init(res_pkt);
  ratp_pkt_set_ctrl_flag(res_pkt, RATP_PKT_HDR_CTRL_RST);
  if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_ACK))
  {
    ratp_pkt_set_sn(res_pkt, ratp_pkt_get_an(pkt));
    /* AN is not significant */
  }
  else
  {
    ratp_pkt_set_ctrl_flag(res_pkt, RATP_PKT_HDR_CTRL_ACK);
    ratp_pkt_set_sn(res_pkt, 0);
    ratp_pkt_set_next_an(res_pkt, ratp_pkt_get_sn(pkt));
  }
}

static void
update_state(struct ratp *ratp, ratp_con_state new_state, ratp_status reason)
{
  LOG_DEBUG("State change [%s]: %s -> %s", ratp_strerror(reason),
      ratp_strstate(ratp->state), ratp_strstate(new_state));

  ratp_con_state old_state = ratp->state;
  ratp->state = new_state;
  if (ratp->cbs.on_state_change_cb.on_state_change != NULL)
  {
    ratp->cbs.on_state_change_cb.on_state_change(
        ratp->cbs.on_state_change_cb.ctx, old_state, new_state, reason);
  }
}

static void
tx_reliable_pkt(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  uint32_t rtx_timeout_ms;

  assert(!rtx_in_progress(ratp));

  ratp->rtx_buf_len = serialize_pkt(ratp->rtx_buf, sizeof(ratp->rtx_buf), pkt);

  ratp->tcb.sn = ratp_pkt_get_sn(pkt);
  ratp->cur_retransmit_num = 0;

  LOG_DEBUG("Sending reliable packet: [%s %s %s %s SN=%" PRIu8 " AN=%" PRIu8 " %s %s] [len: %03" PRIu8 "]",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SYN) ? "SYN" : "---",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_ACK) ? "ACK" : "---",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_FIN) ? "FIN" : "---",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_RST) ? "RST" : "---",
      ratp_pkt_get_sn(pkt),
      ratp_pkt_get_an(pkt),
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_EOR) ? "EOR" : "---",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SO) ? "SO" : "--",
      pkt->hdr.len);

  /* Transmit the packet */
  ratp->cbs.tx_cb.tx(ratp->cbs.tx_cb.ctx, ratp->rtx_buf, ratp->rtx_buf_len);

  /* Start the retransmit timer */
  rtx_timeout_ms = calc_rtx_timeout(ratp->srtt);
  LOG_DEBUG("Starting retransmit timer for %" PRIu32 "ms", rtx_timeout_ms);
  ratp->cbs.timer_cbs.start(ratp->cbs.timer_cbs.ctx, ratp->rtx_pkt_timer, rtx_timeout_ms);
}

static void
tx_unreliable_pkt(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  uint8_t pkt_buf[RATP_MAX_PACKET_LENGTH];
  size_t pkt_len = serialize_pkt(pkt_buf, sizeof(pkt_buf), pkt);

  LOG_DEBUG("Sending unreliable packet: [%s %s %s %s SN=%" PRIu8 " AN=%" PRIu8 " %s %s] [len: %03" PRIu8 "]",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SYN) ? "SYN" : "---",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_ACK) ? "ACK" : "---",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_FIN) ? "FIN" : "---",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_RST) ? "RST" : "---",
      ratp_pkt_get_sn(pkt),
      ratp_pkt_get_an(pkt),
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_EOR) ? "EOR" : "---",
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SO) ? "SO" : "--",
      pkt->hdr.len);

  /* Transmit the packet */
  ratp->cbs.tx_cb.tx(ratp->cbs.tx_cb.ctx, pkt_buf, pkt_len);
}

static size_t
serialize_pkt(uint8_t *buf, size_t buf_len, const struct ratp_pkt *pkt)
{
  size_t bytes_written = 0;
  const bool has_data = ratp_pkt_has_data(pkt);
  const size_t data_size = has_data ?  pkt->hdr.len + 2 /* Data checksum */ : 0;
  const size_t bytes_required = 4 /* Packet header */ + data_size;
  uint8_t header_checksum;
  uint16_t data_checksum;
  size_t i;
  size_t data_i;

  (void)buf_len;
  (void)bytes_required;
  assert(buf_len >= bytes_required);

  buf[bytes_written++] = 0x01; /* SYNCH byte */
  buf[bytes_written++] = pkt->hdr.ctrl;
  buf[bytes_written++] = pkt->hdr.len;
  header_checksum = 0x00;
  header_checksum = hdr_chksum_step(header_checksum, pkt->hdr.ctrl);
  header_checksum = hdr_chksum_step(header_checksum, pkt->hdr.len);
  buf[bytes_written++] = ~header_checksum;

  if (has_data)
  {
    data_i = pkt->data.data_start;
    for (i = 0; i < pkt->hdr.len; i++)
    {
      buf[bytes_written++] = pkt->data.data_base[data_i];

      data_i++;
      data_i %= pkt->data.data_base_len;
    }

    data_checksum = ~data_chksum(&pkt->data, pkt->hdr.len);
    buf[bytes_written++] = (uint8_t)((data_checksum >> 8U) & 0xffU);
    buf[bytes_written++] = (uint8_t)(data_checksum & 0xffU);
  }

  return bytes_written;
}

static void
flush_rtx_pkt(struct ratp *ratp, ratp_status reason)
{
  uint32_t rtt_ms;
  double last_srtt;

  if (rtx_in_progress(ratp) && reason == RATP_STATUS_OK)
  {
    /* Last packet was ACK'd => Record round trip time and update SRTT */
    rtt_ms = ratp->cbs.timer_cbs.elapsed_ms(ratp->cbs.timer_cbs.ctx, ratp->rtx_pkt_timer);
    LOG_DEBUG("Packet acknowledged after %" PRIu32 "ms", rtt_ms);
    last_srtt = ratp->srtt;
    ratp->srtt = last_srtt * RATP_RETRANSMIT_TIMEOUT_SMOOTHING_FACTOR +
      (1.0 - RATP_RETRANSMIT_TIMEOUT_SMOOTHING_FACTOR) * (rtt_ms * MSEC_TO_SEC);
    LOG_DEBUG("SRTT updated %fs -> %fs", last_srtt, ratp->srtt);
  }

  ratp->rtx_buf_len = 0;
  ratp->cbs.timer_cbs.stop(ratp->cbs.timer_cbs.ctx, ratp->rtx_pkt_timer);
}

static void
flush_rtx_queue(struct ratp *ratp, ratp_status reason)
{
  (void)reason;
  ratp_data_queue_clear(&ratp->data_queue);
  ratp->rtx_buf_len = 0;
  ratp->cbs.timer_cbs.stop(ratp->cbs.timer_cbs.ctx, ratp->rtx_pkt_timer);
}

static uint32_t
calc_rtx_timeout(double srtt)
{
  double rto = RATP_RETRANSMIT_TIMEOUT_DELAY_VAR_FACTOR * srtt;

  if (rto > RATP_RETRANSMIT_TIMEOUT_UBOUND_MS * MSEC_TO_SEC)
  {
    rto = RATP_RETRANSMIT_TIMEOUT_UBOUND_MS * MSEC_TO_SEC;
  }
  else if (rto < RATP_RETRANSMIT_TIMEOUT_LBOUND_MS * MSEC_TO_SEC)
  {
    rto = RATP_RETRANSMIT_TIMEOUT_LBOUND_MS * MSEC_TO_SEC;
  }

  return (uint32_t)(rto * SEC_TO_MSEC);
}

static uint32_t
calc_time_wait_timeout(double srtt)
{
  /*
   * Spec says this should be at least 2 * srtt.
   *
   * We use a longer timeout period. If the peer did not send many reliable
   * packets it's srtt will still be very high. This will result in a long
   * packet retransmission timeout. We need to give it enough time to
   * retransmit it's FIN ACK in the case that our ACK is dropped. Therefore, we
   * give the round trip time a lower bound and scale it by a variance factor
   * before multiplying by 2.
   */

  double rto = RATP_RETRANSMIT_TIMEOUT_DELAY_VAR_FACTOR * srtt;

  if (rto < RATP_RETRANSMIT_TIMEOUT_LBOUND_MS * MSEC_TO_SEC)
  {
    rto = RATP_RETRANSMIT_TIMEOUT_LBOUND_MS * MSEC_TO_SEC;
  }

  return 2 * (uint32_t)(rto * SEC_TO_MSEC);
}

static void
rtx_timeout_hdlr(void *ctx)
{
  struct ratp *ratp = (struct ratp *)ctx;
  uint32_t rtx_timeout_ms;
#ifdef RATP_LOGGING
  const char *ordinal_suffix;
#endif

  if (ratp->cur_retransmit_num < RATP_MAX_RETRANSMITS)
  {
    ratp->cur_retransmit_num++;

#ifdef RATP_LOGGING
    switch (ratp->cur_retransmit_num % 10)
    {
      case 1:
        ordinal_suffix = "st";
        break;
      case 2:
        ordinal_suffix = "nd";
        break;
      case 3:
        ordinal_suffix = "rd";
        break;
      default:
        ordinal_suffix = "th";
        break;
    }
#endif

    LOG_DEBUG("Sending %" PRIu8 "%s packet retransmission", ratp->cur_retransmit_num,
        ordinal_suffix);
    ratp->cbs.tx_cb.tx(ratp->cbs.tx_cb.ctx, ratp->rtx_buf, ratp->rtx_buf_len);

    /* Restart retransmission timer */
    rtx_timeout_ms = calc_rtx_timeout(ratp->srtt);
    LOG_DEBUG("Restarting retransmit timer for %" PRIu32 "ms", rtx_timeout_ms);
    ratp->cbs.timer_cbs.start(ratp->cbs.timer_cbs.ctx, ratp->rtx_pkt_timer, rtx_timeout_ms);
  }
  else
  {
    LOG_ERROR("Connection aborted due to retransmission failure");
    flush_rtx_queue(ratp, RATP_STATUS_ERROR_PACKET_TIMEOUT);
    update_state(ratp, RATP_CON_STATE_CLOSED, RATP_STATUS_ERROR_PACKET_TIMEOUT);
  }
}

static bool
rtx_in_progress(const struct ratp *ratp)
{
  return ratp->rtx_buf_len != 0;
}

static void
time_wait_timeout_hdlr(void *ctx)
{
  struct ratp *ratp = (struct ratp *)ctx;

  update_state(ratp, RATP_CON_STATE_CLOSED, RATP_STATUS_OK);
}

static bool
tx_next_data_pkt(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  struct ratp_pkt res_pkt;
  struct ratp_ring_buf_idx ring_buf_idx;
  size_t data_len;
  uint8_t bytes_sent;

  if (ratp_data_queue_peek(&ratp->data_queue, &ring_buf_idx, &data_len))
  {
    if (data_len <= ratp->tcb.mdl)
    {
      bytes_sent = (uint8_t)data_len;
      make_ring_data_pkt_and_ack(&res_pkt, pkt, &ring_buf_idx, bytes_sent, true);
    }
    else
    {
      bytes_sent = ratp->tcb.mdl;
      make_ring_data_pkt_and_ack(&res_pkt, pkt, &ring_buf_idx, bytes_sent, false);
    }
    tx_data_pkt(ratp, &res_pkt);

    ratp_data_queue_pop(&ratp->data_queue, bytes_sent);

    return true;
  }
  else
  {
    /* Nothing to send */
    return false;
  }
}

static void
tx_data_pkt(struct ratp *ratp, struct ratp_pkt *pkt)
{
  if (pkt->hdr.len == 1)
  {
    /* Data packet of size one (1) => Use SO flag and store data in len */
    ratp_pkt_set_ctrl_flag(pkt, RATP_PKT_HDR_CTRL_SO);
    pkt->hdr.len = pkt->data.data_base[pkt->data.data_start];
    pkt->data.data_base = NULL;
  }

  tx_reliable_pkt(ratp, pkt);
}

static void
tx_next_data_pkt_or_ack(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  struct ratp_pkt res_pkt;

  if (rtx_in_progress(ratp) || !tx_next_data_pkt(ratp, pkt))
  {
    /* Data pending retransmit or no data in queue => Send an empty ACK */
    make_ack(&res_pkt, &ratp->tcb, pkt);
    tx_unreliable_pkt(ratp, &res_pkt);
  }
}

/*******************************/
/* Packet Processing Behaviors */
/*******************************/

static bool bhvr_a(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  struct ratp_pkt res_pkt;

  if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_RST))
  {
    /* RST flag set => return w/o further processing */
    LOG_DEBUG("Reset ignored");
    return false;
  }

  if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_ACK))
  {
    /* ACK flag set => Send reset and return w/o further processing */
    LOG_DEBUG("Unexpected ACK");

    make_rst_pkt(&res_pkt, pkt);
    tx_unreliable_pkt(ratp, &res_pkt);

    return false;
  }

  if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SYN))
  {
    /*
     * SYN flag set =>
     *  - Create TCB
     *  - Send SYN ACK
     *  - Go to SYN Received
     *  - Return w/o further processing
     */
    ratp->tcb.active_open = false;
    ratp->tcb.sn = 0;
    ratp->tcb.rn = ratp_pkt_get_sn(pkt);
    ratp->tcb.mdl = pkt->hdr.len;

    make_syn_pkt_and_ack(&res_pkt, &ratp->tcb, pkt);
    tx_reliable_pkt(ratp, &res_pkt);

    update_state(ratp, RATP_CON_STATE_SYN_RECEIVED, RATP_STATUS_OK);

    return false;
  }

  /* No RST, ACK, or SYN flag => Discard and return w/o further processing */
  return false;
}

static bool bhvr_b(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  struct ratp_pkt res_pkt;

  if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_ACK))
  {
    if (!ratp_pkt_validate_an(pkt, ratp->tcb.sn))
    {
      /* ACK set and AN was unexpected */
      LOG_DEBUG("Unexpected AN");
      if (!ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_RST))
      {
        /* RST flag not set => Send a reset */
        make_rst_pkt(&res_pkt, pkt);
        tx_unreliable_pkt(ratp, &res_pkt);
      }

      /* Discard and return w/o further processing */
      return false;
    }
  }

  if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_RST))
  {
    if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_ACK))
    {
      /*
       * RST ACK =>
       *  - Discard
       *  - Flush retransmission buffer
       *  - Inform the user "Error: Connection Refused"
       *  - Delete TCB
       *  - Go to Closed state
       */
      flush_rtx_queue(ratp, RATP_STATUS_ERROR_CONNECTION_REFUSED);
      LOG_ERROR("Connection Refused");
      update_state(ratp, RATP_CON_STATE_CLOSED, RATP_STATUS_ERROR_CONNECTION_REFUSED);
    }

    /* Discard and return w/o further processing */
    return false;
  }

  if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SYN))
  {
    if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_ACK))
    {
      /*
       * SYN ACK =>
       *  - Store MDL
       *  - Mark our SYN as acknowledged
       *  - Send an ACK with any initial data
       *  - Go to Established state w/o further processing
       */
      ratp->tcb.rn = ratp_pkt_get_sn(pkt);
      ratp->tcb.mdl = pkt->hdr.len;

      flush_rtx_pkt(ratp, RATP_STATUS_OK);

      tx_next_data_pkt_or_ack(ratp, pkt);

      update_state(ratp, RATP_CON_STATE_ESTABLISHED, RATP_STATUS_OK);

      return false;
    }

    /*
     * SYN => Simultaneous connection attempt
     *  - Save MDL
     *  - Stop retransmission of our previous SYN
     *  - Send SYN ACK w/ MDL
     *  - Go to SYN Received w/o further processing
     */
    ratp->tcb.sn = 0;
    ratp->tcb.rn = ratp_pkt_get_sn(pkt);
    ratp->tcb.mdl = pkt->hdr.len;

    /* Flush the SYN from the retransmit buffer */
    flush_rtx_pkt(ratp, RATP_STATUS_ERROR_CONNECTION_REFUSED);

    make_syn_pkt_and_ack(&res_pkt, &ratp->tcb, pkt);
    tx_reliable_pkt(ratp, &res_pkt);

    update_state(ratp, RATP_CON_STATE_SYN_RECEIVED, RATP_STATUS_OK);

    return false;
  }

  /* Discard and return w/o further processing */
  return false;
}

static bool bhvr_c1(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  struct ratp_pkt ack_pkt;

  if (ratp_pkt_validate_sn(pkt, ratp->tcb.rn))
  {
    /* Expected SN => Continue processing associated with this state */
    return true;
  }

  if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_RST) ||
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_FIN))
  {
    /* Return w/o further processing */
    LOG_DEBUG("Unexpected SN for FIN or RST");
    return false;
  }

  /* Assumed to be a duplicate of an already received packet */
  /* Send an ACK and discard the duplicate packet */
  LOG_DEBUG("Received duplicate packet");

  make_ack(&ack_pkt, &ratp->tcb, pkt);
  tx_unreliable_pkt(ratp, &ack_pkt);

  return false;
}

static bool bhvr_c2(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  struct ratp_pkt res_pkt;

  if (ratp_pkt_validate_sn(pkt, ratp->tcb.rn))
  {
    /* Expected SN => Continue processing associated with this state */
    return true;
  }

  if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_RST) ||
      ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_FIN))
  {
    /* Return w/o further processing */
    LOG_DEBUG("Unexpected SN for FIN or RST");
    return false;
  }

  if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SYN))
  {
    /*
     * Assume sender crashed and attempted a new connection =>
     *  - Send a reset
     *  - Flush the retransmission queue
     *  - Report the error
     *  - Discard the packet
     *  - Delete the TCB
     *  - Go to the Closed state w/o further processing
     */
    make_rst_pkt(&res_pkt, pkt);
    tx_unreliable_pkt(ratp, &res_pkt);

    flush_rtx_queue(ratp, RATP_STATUS_ERROR_CONNECTION_RESET);

    LOG_ERROR("Connection reset");

    update_state(ratp, RATP_CON_STATE_CLOSED, RATP_STATUS_ERROR_CONNECTION_RESET);

    return false;
  }

  /* Assumed to be a duplicate of an already received packet */
  /* Send an ACK and discard the duplicate packet */
  LOG_DEBUG("Received duplicate packet");

  make_ack(&res_pkt, &ratp->tcb, pkt);
  tx_unreliable_pkt(ratp, &res_pkt);

  return false;
}

static bool bhvr_d1(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  if (!ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_RST))
  {
    /* Reset not set => Return and continue processing */
    return true;
  }

  /* Reset was set, new state is determined by how the connection was opened */
  if (!ratp->tcb.active_open)
  {
    /*
     * Passive open (listen) =>
     *  - Flush retransmission queue
     *  - Go to the Listen state
     */
    flush_rtx_queue(ratp, RATP_STATUS_ERROR_CONNECTION_RESET);
    update_state(ratp, RATP_CON_STATE_LISTEN, RATP_STATUS_ERROR_CONNECTION_RESET);
  }
  else
  {
    /*
     * Active open (connect) =>
     *  - Flush retransmission queue
     *  - Inform the user the connection was reset
     *  - Delete the TCB
     *  - Go to the Closed state
     */
    flush_rtx_queue(ratp, RATP_STATUS_ERROR_CONNECTION_REFUSED);
    LOG_ERROR("Connection refused");
    update_state(ratp, RATP_CON_STATE_CLOSED, RATP_STATUS_ERROR_CONNECTION_REFUSED);
  }

  /* Return w/o further processing */
  return false;
}

static bool bhvr_d2(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  if (!ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_RST))
  {
    /* Reset not set => Return and continue processing */
    return true;
  }

  /*
   * Reset set =>
   *  - Flush the retransmission queue
   *  - Inform the user the connection was reset
   *  - Delete the TCB
   *  - Go to the Closed state w/o further processing
   */

  flush_rtx_queue(ratp, RATP_STATUS_ERROR_CONNECTION_RESET);
  LOG_ERROR("Connection reset");
  update_state(ratp, RATP_CON_STATE_CLOSED, RATP_STATUS_ERROR_CONNECTION_RESET);

  return false;
}

static bool bhvr_d3(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  if (!ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_RST))
  {
    /* Reset not set => Return and continue processing */
    return true;
  }

  /*
   * Reset set =>
   *  - Delete the TCB
   *  - Go to the Closed state w/o further processing
   */

  update_state(ratp, RATP_CON_STATE_CLOSED, RATP_STATUS_ERROR_CONNECTION_RESET);

  return false;
}

static bool bhvr_e(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  struct ratp_pkt res_pkt;

  if (!ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SYN))
  {
    /* SYN not set => Return and continue processing */
    return true;
  }

  /*
   * SYN set =>
   *  - Flush the retransmission queue
   *  - Send a legal reset packet
   *  - Inform the user the connection was reset
   *  - Delete the TCB
   *  - Go to the Closed state w/o further processing
   */

  flush_rtx_queue(ratp, RATP_STATUS_ERROR_CONNECTION_RESET);

  make_rst_pkt(&res_pkt, pkt);
  tx_unreliable_pkt(ratp, &res_pkt);

  LOG_ERROR("Connection reset");
  update_state(ratp, RATP_CON_STATE_CLOSED, RATP_STATUS_ERROR_CONNECTION_RESET);

  return false;
}

static bool bhvr_f1(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  struct ratp_pkt res_pkt;

  if (!ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_ACK))
  {
    /* No ACK => Discard w/o further processing */
    LOG_DEBUG("Expected ACK");
    return false;
  }

  if (ratp_pkt_validate_an(pkt, ratp->tcb.rn))
  {
    /* AN is expected => Return and continue processing */
    return true;
  }

  /* ACK with Unexpected AN */
  LOG_DEBUG("Unexpected AN");
  if (!ratp->tcb.active_open)
  {
    /*
     * Passive open (listen) =>
     *  - Flush the retransmission queue
     *  - Discard the packet
     *  - Send a reset
     *  - Delete the TCB
     *  - Go to the Listen state
     */
    flush_rtx_queue(ratp, RATP_STATUS_ERROR_CONNECTION_RESET);

    make_rst_pkt(&res_pkt, pkt);
    tx_unreliable_pkt(ratp, &res_pkt);

    update_state(ratp, RATP_CON_STATE_LISTEN, RATP_STATUS_ERROR_CONNECTION_RESET);
  }
  else
  {
    /*
     * Active open (connect) =>
     *  - Inform the user that the connection was reset
     *  - Flush the retransmission queue
     *  - Discard the packet
     *  - Send a reset
     *  - Delete the TCB
     *  - Go to the Closed state
     */
    LOG_ERROR("Connection reset");
    flush_rtx_queue(ratp, RATP_STATUS_ERROR_CONNECTION_RESET);

    make_rst_pkt(&res_pkt, pkt);
    tx_unreliable_pkt(ratp, &res_pkt);

    update_state(ratp, RATP_CON_STATE_CLOSED, RATP_STATUS_ERROR_CONNECTION_RESET);
  }

  /* Return w/o further processing */
  return false;
}

static bool bhvr_f2(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  if (!ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_ACK))
  {
    /* No ACK => Discard w/o further processing */
    LOG_DEBUG("Expected ACK");
    return false;
  }

  if (ratp_pkt_validate_an(pkt, ratp->tcb.sn))
  {
    /*
     * AN is expected => Our packet was acknowledged!
     *  - Flush the retransmission packet
     *  - Inform the user that the message was received
     *  - Return and continue processing
     */

    flush_rtx_pkt(ratp, RATP_STATUS_OK);

    if (!ratp_pkt_has_user_data(pkt))
    {
      /* The packet doesn't have data, send any pending data now */
      tx_next_data_pkt(ratp, pkt);
    }

    /* Return and continue processing */
    return true;
  }

  /* ACK with Unexpected AN => Duplicate ACK */
  LOG_DEBUG("Unexpected AN... continuing");

  /* Return and continue processing */
  return true;
}

static bool bhvr_f3(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  (void)ratp;

  if (!ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_ACK))
  {
    /* No ACK => Discard w/o further processing */
    LOG_DEBUG("Expected ACK");
    return false;
  }

  /* Doesn't matter if the AN is expected, return and continue processing */
  return true;
}

static bool bhvr_h1(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  /*
   * SYN was acknowledged =>
   *  - Flush the retransmission packet
   *  - Send any initial data (if the packet has no data!)
   *  - Go to the Established state
   *  - Execute behavior I1 to process any data
   *  - Return w/o further processing
   */

  flush_rtx_pkt(ratp, RATP_STATUS_OK);

  update_state(ratp, RATP_CON_STATE_ESTABLISHED, RATP_STATUS_OK);

  if (!ratp_pkt_has_user_data(pkt))
  {
    /* The packet doesn't have data, send any pending data now */
    /* NOTE: The case where the packet has data is handled in behavior I1 */
    (void)tx_next_data_pkt(ratp, pkt);
  }

  (void)bhvr_i1(ratp, pkt);

  return false;
}

static bool bhvr_h2(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  struct ratp_pkt res_pkt;

  if (!ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_FIN))
  {
    /* FIN not set => Continue processing */
    return true;
  }

  /*
   * FIN set => Connection is closing
   *  - Warn the user if there is unsent data in the retransmission queue
   *  - Inform the user the connection is closing
   *  - Send a FIN ACK
   *  - Go to Last-ACK w/o further processing
   */

  if (rtx_in_progress(ratp))
  {
    LOG_WARN("Data left unsent");
  }
  flush_rtx_queue(ratp, RATP_STATUS_ERROR_CONNECTION_CLOSING);
  LOG_INFO("Connection closing");

  ratp->tcb.rn = ratp_pkt_get_sn(pkt);

  make_fin_pkt_and_ack(&res_pkt, pkt);
  tx_reliable_pkt(ratp, &res_pkt);

  update_state(ratp, RATP_CON_STATE_LAST_ACK, RATP_STATUS_OK);

  return false;
}

static bool bhvr_h3(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  struct ratp_pkt res_pkt;
  uint32_t time_wait_timeout_ms;

  if (!ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_FIN))
  {
    /* FIN not set => Duplicate packet where sender hasn't seen our FIN */
    LOG_DEBUG("Expected FIN");
    return false;
  }

  if (ratp_pkt_has_user_data(pkt))
  {
    /*
     * FIN cannot have data =>
     *  - Send reset
     *  - Flush retransmission queue
     *  - Inform the user the connection was reset
     *  - Delete the TCB
     *  - Go to the Closed state w/o further processing
     */
    LOG_DEBUG("FIN cannot contain data");

    make_rst_pkt(&res_pkt, pkt);
    tx_unreliable_pkt(ratp, &res_pkt);

    flush_rtx_queue(ratp, RATP_STATUS_ERROR_CONNECTION_RESET);

    LOG_ERROR("Connection reset");

    update_state(ratp, RATP_CON_STATE_CLOSED, RATP_STATUS_ERROR_CONNECTION_RESET);

    return false;
  }

  if (ratp_pkt_validate_an(pkt, ratp->tcb.sn))
  {
    /*
     * Other side acknowledged our FIN =>
     *  - Flush FIN from retransmit queue
     *  - Send ACK for other side's FIN
     *  - Start the 2*SRTT Time-Wait timer
     *  - Go to Time-Wait state w/o further processing
     */
    flush_rtx_pkt(ratp, RATP_STATUS_OK);

    make_ack(&res_pkt, &ratp->tcb, pkt);
    tx_unreliable_pkt(ratp, &res_pkt);

    /* Start Time Wait timer */
    time_wait_timeout_ms = calc_time_wait_timeout(ratp->srtt);
    LOG_DEBUG("Setting %s for %" PRIu32 "ms", ratp_strtimer(RATP_TIMER_TYPE_TIME_WAIT), time_wait_timeout_ms);
    ratp->cbs.timer_cbs.start(ratp->cbs.timer_cbs.ctx, ratp->time_wait_timer, time_wait_timeout_ms);

    update_state(ratp, RATP_CON_STATE_TIME_WAIT, RATP_STATUS_OK);

    return false;
  }

  /*
   * Unexpected AN => Simultaneous close
   *  - Send an ACK
   *  - Discard the packet
   *  - Go to the Closing state w/o further processing
   */
  LOG_DEBUG("Unexpected AN... simultaneous close attempt");

  make_ack(&res_pkt, &ratp->tcb, pkt);
  tx_unreliable_pkt(ratp, &res_pkt);

  update_state(ratp, RATP_CON_STATE_CLOSING, RATP_STATUS_OK);

  return false;
}

static bool bhvr_h4(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  if (ratp_pkt_validate_an(pkt, ratp->tcb.sn))
  {
    /* FIN ACK was acknowledged => Go to Closed state w/o further processing */
    /* Flush FIN ACK from retransmission queue */
    flush_rtx_pkt(ratp, RATP_STATUS_OK);
    update_state(ratp, RATP_CON_STATE_CLOSED, RATP_STATUS_OK);
    return false;
  }

  /* Unexpected AN => Discard packet w/o further processing */
  LOG_DEBUG("Unexptected AN");
  return false;
}

static bool bhvr_h5(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  uint32_t time_wait_timeout_ms;

  if (ratp_pkt_validate_an(pkt, ratp->tcb.sn))
  {
    /* FIN was acknowledged => Go to Time-Wait state w/o further processing */
    /* Flush FIN from retransmission queue */
    flush_rtx_pkt(ratp, RATP_STATUS_OK);

    /* Start Time Wait timer */
    time_wait_timeout_ms = calc_time_wait_timeout(ratp->srtt);
    LOG_DEBUG("Setting %s for %" PRIu32 "ms", ratp_strtimer(RATP_TIMER_TYPE_TIME_WAIT), time_wait_timeout_ms);
    ratp->cbs.timer_cbs.start(ratp->cbs.timer_cbs.ctx, ratp->time_wait_timer, time_wait_timeout_ms);

    update_state(ratp, RATP_CON_STATE_TIME_WAIT, RATP_STATUS_OK);
    return false;
  }

  /* Unexpected AN => Discard packet w/o further processing */

  return false;
}

static bool bhvr_h6(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  struct ratp_pkt res_pkt;
  uint32_t time_wait_timeout_ms;

  if (!(ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_FIN)
      && ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_ACK)))
  {
    /* FIN ACK not set => Discard w/o further processing */
    return false;
  }

  /* Last ACK was dropped => Resend the ACK and restart the timer */

  make_ack(&res_pkt, &ratp->tcb, pkt);
  tx_unreliable_pkt(ratp, &res_pkt);

  /* Restart the time wait timer */
  time_wait_timeout_ms = calc_time_wait_timeout(ratp->srtt);
  LOG_DEBUG("Resetting %s to %" PRIu32 "ms", ratp_strtimer(RATP_TIMER_TYPE_TIME_WAIT), time_wait_timeout_ms);
  ratp->cbs.timer_cbs.start(ratp->cbs.timer_cbs.ctx, ratp->time_wait_timer, time_wait_timeout_ms);

  /* Return w/o further processing */
  return false;
}

static bool bhvr_i1(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  if (!ratp_pkt_has_user_data(pkt))
  {
    /* Packet doesn't contain data => Return w/o further processing */
    return false;
  }

  /*
   * Packet contains data =>
   *  - Append the data to the receive buffer
   *  - If EOR is set, the entire message has been received => Pass data to user
   *  - Send ACK (potentially with any queued data)
   *  - Return w/o further processing
   */

  /*
   * Optimization: If (1) there is currently nothing in the receive buffer, (2)
   * the packet has the EOR bit set, and (3) the packet data is contiguous,
   * don't copy into the receive buffer and immediately pass it to user
   */
  if (ratp_rx_buffer_is_empty(ratp)
      && ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_EOR) /* EOR bit is set */
      && (                                                     /* Either ... */
        ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SO)      /* A single byte message */
        || pkt->data.data_start <= pkt->data.data_base_len - pkt->hdr.len)) /* The packet data is contiguous */
  {
    if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SO))
    {
      /* Pass the single byte stored in the length field of the header */
      ratp->cbs.msg_hdlr_cb.msg_hdlr(ratp->cbs.msg_hdlr_cb.ctx,
          &pkt->hdr.len, 1);
    }
    else
    {
      ratp->cbs.msg_hdlr_cb.msg_hdlr(ratp->cbs.msg_hdlr_cb.ctx,
          &pkt->data.data_base[pkt->data.data_start], pkt->hdr.len);
    }
  }
  else
  {
    /* Push packet data into the receive buffer */
    ratp_rx_buffer_push(ratp, pkt);

    /* Is this the last packet in the message? */
    if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_EOR))
    {
      if (!ratp_rx_buffer_would_overflow(ratp))
      {
        /* Success: The receive buffer was able to hold the entire message */
        ratp->cbs.msg_hdlr_cb.msg_hdlr(ratp->cbs.msg_hdlr_cb.ctx, ratp->rx_buffer,
            ratp->rx_buffer_len);
      }
      else
      {
        /* The receive buffer filled up at some point */
        LOG_ERROR("Receive buffer full: message dropped");
      }

      /* Clear the receive buffer */
      ratp_rx_buffer_clear(ratp);
    }
  }

  /* Update our last received sequence number */
  ratp->tcb.rn = ratp_pkt_get_sn(pkt);

  /* Acknowledge the packet and send any pending data */
  tx_next_data_pkt_or_ack(ratp, pkt);

  return false;
}

static bool bhvr_g(struct ratp *ratp, const struct ratp_pkt *pkt)
{
  struct ratp_pkt res_pkt;

  if (ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_RST))
  {
    /* Reset set => Return w/o further processing */
    return false;
  }

  /* Reset not set => Send a reset */

  make_rst_pkt(&res_pkt, pkt);
  tx_unreliable_pkt(ratp, &res_pkt);

  /* Return w/o further processing */
  return false;
}
