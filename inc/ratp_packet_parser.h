#ifndef RATP_PACKET_PARSER_H
#define RATP_PACKET_PARSER_H

#include "ratp.h"
#include "ratp_packet.h"

#include <stddef.h>
#include <stdint.h>

#ifndef RATP_MAXIMUM_DATA_LENGTH
/**
 * Maximum number of data bytes per RATP packet
 *
 * Must be a valid uint8_t value (0..=255)
 */
#define RATP_MAXIMUM_DATA_LENGTH (255U)
#endif

/**
 * Packet parser state
 */
typedef enum ratp_rx_pkt_state_e
{
  RATP_RX_PKT_SFH,          /*!< Searching for SYNCH (start of packet header) */
  RATP_RX_PKT_HDR_CTRL,     /*!< Reading header byte 1 (control) */
  RATP_RX_PKT_HDR_DLEN,     /*!< Reading header byte 2 (data length) */
  RATP_RX_PKT_HDR_CHKSUM,   /*!< Reading header byte 3 (header checksum) */
  RATP_RX_PKT_DATA,         /*!< Reader packet data */
  RATP_RX_PKT_DATA_CHKSUM1, /*!< Reading data packet checksum byte 1 (high byte) */
  RATP_RX_PKT_DATA_CHKSUM2  /*!< Reading data packet checksum byte 2 (low byte) */
} ratp_rx_pkt_state;

/**
 * Receive packet callback
 *
 * \param[in,out] ctx User provided callback context
 * \param[in] pkt The received packet
 */
typedef void (*ratp_rx_pkt_fn)(void *ctx, const struct ratp_pkt *pkt);

/**
 * Maximum data length (MDL) error callback
 *
 * Called when the data length for an incomming packet would exceed the maximum
 * data length of this receiver
 *
 * \param[in,out] ctx User provided callback context
 * \param[in] pkt_data_len The data length of the offending packet
 * \param[in] mdl The current maximum data length
 */
typedef void (*ratp_mdl_err_hdlr_fn)(void *ctx, uint8_t pkt_data_len, uint8_t mdl);

/**
 * Packet parser callbacks
 *
 * If RATP is used in a single execution context environment, \ref
 * ratp_pkt_parser_callbacks.ctx should be set to an instance of a \ref ratp and
 * \ref ratp_pkt_parser_callbacks.rx_pkt set to \ref ratp_rx_packet. Otherwise,
 * the packet parser may execute in a separate execution environment (e.g. a
 * background thread or the interrupt context) and the user would then provide
 * the appropriate \ref ratp_pkt_parser_callbacks.ctx and \ref
 * ratp_pkt_parser_callbacks.pkt to buffer parsed packets for another execution
 * context to pass them to \ref ratp_rx_packet.
 */
struct ratp_pkt_parser_callbacks
{
  void *ctx;                         /*!< User callback context */
  ratp_rx_pkt_fn rx_pkt;             /*!< Receive packet callback */
  ratp_mdl_err_hdlr_fn mdl_err_hdlr; /*!< MDL error handler */
};

/**
 * Packet parser context
 */
struct ratp_pkt_parser
{
  struct ratp_pkt_parser_callbacks cbs;            /*!< Packet parser callbacks */
  struct ratp_pkt receiving_pkt;                   /*!< Packet currently being received */
  uint8_t recv_pkt_data[RATP_MAXIMUM_DATA_LENGTH]; /*!< Received packet data buffer */
  ratp_rx_pkt_state state;                         /*!< Current parser state */
  uint16_t data_chksum;                            /*!< Packet data checksum */
  uint8_t data_bytes_read;                         /*!< Current data length */
};

/**
 * Initialize a packet parser
 *
 * \param[out] pkt_parser The packet parser context
 * \param[in] callbacks The packet parser user callbacks
 * \return RATP_STATUS_OK on successful initialization
 */
ratp_status
ratp_pkt_parser_init(struct ratp_pkt_parser *pkt_parser,
    const struct ratp_pkt_parser_callbacks *callbacks);

/**
 * Parse received bytes
 *
 * \param[in,out] pkt_parser The packet parser context
 * \param[in] data The bytes to parse
 * \param[in] data_len The number of bytes to parse
 * \return RATP_STATUS_OK
 */
ratp_status
ratp_pkt_parser_rx_bytes(struct ratp_pkt_parser *pkt_parser, const uint8_t *data, size_t data_len);

#endif /* RATP_PACKET_PARSER_H */
