#ifndef RATP_H
#define RATP_H

#include "ratp_packet.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * SYNCH (1) + HEADER (1) + Data Checksum (4) + 255
 */
#define RATP_MAX_PACKET_LENGTH (261U)

/**
 * Maximum retransmit attempts before aborting the connection
 */
#define RATP_MAX_RETRANSMITS (5U)

/**
 * Maximum retransmit timeout
 */
#define RATP_RETRANSMIT_TIMEOUT_UBOUND_MS (64U)

/**
 * Minimum retransmit timeout
 */
#define RATP_RETRANSMIT_TIMEOUT_LBOUND_MS (5U)

/**
 * Retransmit timeout smoothing factor
 */
#define RATP_RETRANSMIT_TIMEOUT_SMOOTHING_FACTOR (0.85)

/**
 * Retransmit timeout delay variance factor
 */
#define RATP_RETRANSMIT_TIMEOUT_DELAY_VAR_FACTOR (1.5)

/**
 * Message receiver buffer length
 *
 * NOTE: If a peer sends a message larger than this length, the receiver will
 *       log an error and the message will be dropped
 */
#define RATP_RECEIVE_BUFFER_LEN (1024U)

/**
 * Maximum number of messages to buffer in the transmit queue
 */
#define RATP_DATA_QUEUE_MAX_MESSAGES (8U)

/**
 * Maximum number of message data bytes to buffer in the transmit queue
 */
#define RATP_DATA_QUEUE_MAX_DATA (1024U)

/**
 * Status reason
 */
typedef enum ratp_status_e
{
  RATP_STATUS_OK,                       /*!< OK */
  RATP_STATUS_ERROR_BAD_ARGUMENT,       /*!< Bad argument passed to function */
  RATP_STATUS_ERROR_CONNECTION_REFUSED, /*!< Connection attempt refused */
  RATP_STATUS_ERROR_CONNECTION_RESET,   /*!< Connection reset */
  RATP_STATUS_ERROR_CONNECTION_CLOSING, /*!< Connection closing */
  RATP_STATUS_ERROR_PACKET_TIMEOUT,     /*!< Packet retransmission limit reached */
  RATP_STATUS_ERROR_INVALID_STATE,      /*!< Invalid state transition requested */
  RATP_STATUS_ERROR_TIMER_INIT_FAILURE, /*!< Timer initialization failed */
  RATP_STATUS_ERROR_BUFFER_FULL,        /*!< Internal buffer full */

  NUM_RATP_STATUSES                     /*!< Number of RATP statuses */
} ratp_status;

/**
 * Connection state
 */
typedef enum ratp_con_state_e
{
  RATP_CON_STATE_LISTEN,       /*!< Listening for incoming connection requests */
  RATP_CON_STATE_SYN_SENT,     /*!< User initiated connection (SYN packet sent) */
  RATP_CON_STATE_SYN_RECEIVED, /*!< Received SYN packet and sent SYN ACK */
  RATP_CON_STATE_ESTABLISHED,  /*!< Connection established */
  RATP_CON_STATE_FIN_WAIT,     /*!< User closed connection (FIN sent) */
  RATP_CON_STATE_LAST_ACK,     /*!< Other side closed connection (FIN ACK sent) */
  RATP_CON_STATE_CLOSING,      /*!< Both sides closed at the same time (ACK sent) */
  RATP_CON_STATE_TIME_WAIT,    /*!< Wait before allowing a new connection to be made */
  RATP_CON_STATE_CLOSED        /*!< Connection closed */
} ratp_con_state;

/**
 * Timer type
 */
typedef enum ratp_timer_type_e
{
  RATP_TIMER_TYPE_PACKET_ACK, /*!< Packet acknowledgement timer */
  RATP_TIMER_TYPE_TIME_WAIT,  /*!< Closing connection linger timer */

  NUM_RATP_TIMER_TYPES
} ratp_timer_type;

/**
 * Log levels
 */
typedef enum ratp_log_level_e
{
  RATP_LOG_LEVEL_DEBUG, /*!< Low level logging; helpful for debugging */
  RATP_LOG_LEVEL_INFO,  /*!< Informational logs; common in normal operation */
  RATP_LOG_LEVEL_WARN,  /*!< Warnings of abnormal (but recoverable) issues */
  RATP_LOG_LEVEL_ERROR, /*!< Errors that impact reliable transmission */
  RATP_LOG_LEVEL_FATAL  /*!< Fatal errors that impact RATP functionality */
} ratp_log_level;

/*************/
/* Callbacks */
/*************/

/**
 * Transmit function callback
 *
 * \param[in,out] ctx User provided callback context
 * \param[in] data The data to transmit
 * \param[in] data_len The number of data bytes to transmit
 */
typedef void (*ratp_tx_fn)(void *ctx, const uint8_t *data, size_t data_len);

/**
 * Received message handler callback
 *
 * \param[in,out] ctx User provided callback context
 * \param[in] data The message data
 * \param[in] data_len The number data bytes
 */
typedef void (*ratp_msg_hdlr_fn)(void *ctx, const uint8_t *data, size_t data_len);

/**
 * On connection state change callback
 *
 * \param[in,out] ctx User provided callback context
 * \param[in] old_state Old connection state
 * \param[in] new_state The new connection state
 * \param[in] status The connection status
 */
typedef void (*ratp_on_state_change_fn)(void *ctx, ratp_con_state old_state, ratp_con_state new_state, ratp_status status);

/**
 * Timeout callback for the timer object to call on timer expiration
 *
 * \param[in,out] ctx RATP provided callback context
 */
typedef void (*ratp_timeout_fn)(void *ctx);

/**
 * Timeout callback and context
 */
struct ratp_timeout_callback
{
  void *ctx;               /*!< RATP provided context */
  ratp_timeout_fn timeout; /*!< Timeout function callback */
};

/**
 * Timer initialization callback
 *
 * Used by RATP to create timers which trigger actions after a period of time
 *
 * \note Timer should be initialized to "stopped" state
 *
 * \sa ratp_timer_start_fn
 * \sa ratp_timer_stop_fn
 * \sa ratp_timer_elapsed_ms_fn
 * \sa ratp_timer_destroy_fn
 *
 * \param[in,out] ctx User provided callback context
 * \param[out] timer A pointer to the initialized timer object
 * \param[in] timer_type The type of timer which is being initialized
 * \param[in] timeout_cb The callback to call after the timer expires
 * \return true on successful initialization false on failure
 */
typedef bool (*ratp_timer_init_fn)(void *ctx, void **timer, ratp_timer_type timer_type, struct ratp_timeout_callback timeout_cb);

/**
 * Start timer callback
 *
 * Used by RATP to start the timer. If the timer expires before the timer is
 * stopped, the timeout callback passed in the timer initialization function
 * should be called.
 *
 * \param[in,out] ctx User provided callback context
 * \param[in,out] timer The timer object to start
 * \param[in] timeout_ms The number of milliseconds before the timer expires
 */
typedef void (*ratp_timer_start_fn)(void *ctx, void *timer, uint32_t timeout_ms);

/**
 * Stop timer callback
 *
 * Used by RATP to stop the timer
 *
 * \param[in,out] ctx User provided callback context
 * \param[in,out] timer The timer object to stop
 */
typedef void (*ratp_timer_stop_fn)(void *ctx, void *timer);

/**
 * Get the number of milliseconds since the start time
 *
 * \param[in,out] ctx User provided callback context
 * \param[in,out] timer The timer object from which to get the elapsed time
 * \return The number of milliseconds since the timer started
 */
typedef uint32_t (*ratp_timer_elapsed_ms_fn)(void *ctx, void *timer);

/**
 * Timer destructor callback
 *
 * Used by RATP to clean up timer resources
 *
 * \param[in,out] ctx User provided callback context
 * \param[in] timer The timer object to destruct
 *
 * \note The timer object will not be used by RATP after calling this function
 */
typedef bool (*ratp_timer_destroy_fn)(void *ctx, void *timer);

/**
 * Log function Callback
 *
 * \param[in,out] ctx User provided callback context
 * \param[in] log_level The log level for this log message
 * \param[in] fmt The format for the message
 * \param[in] args The arguments to populate the format string
 */
typedef void (*ratp_log_fn)(void *ctx, ratp_log_level log_level, const char *fmt, va_list args);

/**
 * Data transmit function callback and context
 */
struct ratp_tx_callback
{
  void *ctx;     /*!< User callback context */
  ratp_tx_fn tx; /*!< Transmit function callback */
};

/**
 * Message handler callback and context
 */
struct ratp_msg_hdlr_callback
{
  void *ctx;                 /*!< User callback context */
  ratp_msg_hdlr_fn msg_hdlr; /*!< Message handler callback */
};

/**
 * State change handler callback and context
 */
struct ratp_on_state_change_callback
{
  void *ctx;                               /*!< User callback context */
  ratp_on_state_change_fn on_state_change; /*!< On state change callback */
};

/**
 * Log function callback and context
 */
struct ratp_log_callback
{
  void *ctx;       /*!< User callback context */
  ratp_log_fn log; /*!< Logger callback */
};

/**
 * Timer functions and context
 */
struct ratp_timer_callbacks
{
  void *ctx;
  ratp_timer_init_fn init;             /*!< Timer initialization function */
  ratp_timer_start_fn start;           /*!< Timer start function */
  ratp_timer_stop_fn stop;             /*!< Timer stop function */
  ratp_timer_elapsed_ms_fn elapsed_ms; /*!< Elapsed time function */
  ratp_timer_destroy_fn destroy;       /*!< Timer destruction function */
};

/**
 * RATP callbacks
 */
struct ratp_callbacks
{
  struct ratp_tx_callback tx_cb;                           /*!< Transmission callback and context */
  struct ratp_msg_hdlr_callback msg_hdlr_cb;               /*!< Message handler callback and context */
  struct ratp_on_state_change_callback on_state_change_cb; /*!< State change callback and context (nullable) */
  struct ratp_log_callback log_cb;                         /*!< Logging callback and context (nullable) */
  struct ratp_timer_callbacks timer_cbs;                   /*!< Timer implementation callbacks and context */
};

/**
 * RATP Transmission Control Block (TCB)
 */
struct ratp_tcb
{
  bool active_open; /*!< true => ratp_connect open; false => ratp_listen open */
  uint8_t sn;       /*!< Current sending sequence number (0 or 1) */
  uint8_t rn;       /*!< Current receiving sequence number (0 or 1) */
  uint8_t mdl;      /*!< Maximum data length of the receiver */
};

/**
 * User transmit data queue
 */
struct ratp_data_queue
{
  size_t msg_lens_head;                          /*!< Message length head index */
  size_t msg_lens_tail;                          /*!< Message length tail index */
  size_t msg_lens_size;                          /*!< Message length size */
  size_t msg_lens[RATP_DATA_QUEUE_MAX_MESSAGES]; /*!< Message lengths */

  size_t msg_data_head;                          /*!< Message data head index */
  size_t msg_data_tail;                          /*!< Message data tail index */
  size_t msg_data_size;                          /*!< Message data size */
  uint8_t msg_data[RATP_DATA_QUEUE_MAX_DATA];    /*!< Message data */
};

/**
 * Main RATP context
 */
struct ratp
{
  struct ratp_callbacks cbs;                  /*!< RATP callbacks */

  /* User data buffering */
  struct ratp_data_queue data_queue;          /*!< RATP user data queue */
  uint8_t rx_buffer[RATP_RECEIVE_BUFFER_LEN]; /*!< User data receive buffer */
  size_t rx_buffer_len;                       /*!< Bytes currently in the receive buffer */

  /* Connection state */
  struct ratp_tcb tcb;                        /*!< RATP TCB */
  void *time_wait_timer;                      /*!< Time Wait state timer */
  ratp_con_state state;                       /*!< RATP connection state */

  /* Packet retransmission */
  void *rtx_pkt_timer;                        /*!< Packet retransmission and acknowledgement timer */
  double srtt;                                /*!< Smoothed round trip time in seconds (TODO[deatho]: don't use FP)*/
  uint8_t cur_retransmit_num;                 /*!< Current retransmit counter */
  uint8_t rtx_buf[RATP_MAX_PACKET_LENGTH];    /*!< Serialized packet buffer */
  size_t rtx_buf_len;                         /*!< Number of bytes in the rtx_buf; 0 => no packet */
};

/**
 * Initialize the main RATP context
 *
 * \param[out] ratp The RATP context
 * \param[in] callbacks The user callbacks
 * \return RATP_STATUS_OK on success
 */
ratp_status
ratp_init(struct ratp *ratp, const struct ratp_callbacks *callbacks);

/**
 * Start listening for an incoming connection
 *
 * \param[in,out] ratp The RATP context
 * \return \ref RATP_STATUS_OK on successful transition to listening state,
 *         \ref RATP_STATUS_ERROR_INVALID_STATE if there is already a connection
 */
ratp_status
ratp_listen(struct ratp *ratp);

/**
 * Attempt to connect to a receiver
 *
 * \param[in,out] ratp The RATP context
 * \return \ref RATP_STATUS_OK on successful transition to SYN Sent state,
 *         \ref RAT_STATUS_ERROR_INVALID_STATE if there is already a connection
 */
ratp_status
ratp_connect(struct ratp *ratp);

/**
 * Send a message to the receiver
 *
 * \param[in,out] ratp The RATP context
 * \param[in] data The message data
 * \param[in] data_len The length of data for the message
 * \return \ref RATP_STATUS_OK on successful message transmission
 *         \ref RATP_STATUS_ERROR_INVALID_STATE if the connection is closing or
 *                                              closed
 *         \ref RATP_STATUS_ERROR_BUFFER_FULL if the internal buffer could not
 *                                            store the message
 */
ratp_status
ratp_send(struct ratp *ratp, const uint8_t *data, size_t data_len);

/**
 * Close an active connection
 *
 * \param[in,out] ratp The RATP context
 * \return \ref RATP_STATUS_OK on successful transition to SYN Sent state,
 *         \ref RAT_STATUS_ERROR_INVALID_STATE if there is no active connection
 */
ratp_status
ratp_close(struct ratp *ratp);

/**
 * Process a received packet
 *
 * \param[in,out] ratp The RATP context
 * \param[in] pkt The packet to process
 */
void
ratp_rx_packet(struct ratp *ratp, const struct ratp_pkt *pkt);

/**
 * Get a human readable error string from a RATP status code
 *
 * \param[in] status The RATP status code
 * \return Human readable error string for the provided status
 */
const char *
ratp_strerror(ratp_status status);

/**
 * Get a human readable string from a RATP connection state code
 *
 * \param[in] state The RATP state code
 * \return Human readable string for the provided state
 */
const char *
ratp_strstate(ratp_con_state state);

/**
 * Get a human readable string from a RATP timer type code
 *
 * \param[in] timer The timer type code
 * \return Human readable string for the provided timer
 */
const char *
ratp_strtimer(ratp_timer_type timer);

#endif /* RATP_H */
