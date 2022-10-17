#include "ratp_packet_parser.h"

#include "ratp_packet.h"

#include <stdbool.h>

/**
 * Packet parser special byte values
 */
enum
{
  SYNCH = 0x01 /*!< Start of header byte */
};

/*******************************/
/* Local Function Declarations */
/*******************************/

/**
 * Parse a single byte
 *
 * \param[in,out] pkt_parser The packet parser context
 * \param[in] byte The byte to parse
 */
static void
rx_byte(struct ratp_pkt_parser *pkt_parser, uint8_t byte);

/*******************************/
/* Global Function Definitions */
/*******************************/

ratp_status
ratp_pkt_parser_init(struct ratp_pkt_parser *pkt_parser,
    const struct ratp_pkt_parser_callbacks *callbacks)
{
  if (pkt_parser == NULL ||
      callbacks == NULL ||
      callbacks->rx_pkt == NULL ||
      callbacks->mdl_err_hdlr == NULL)
  {
    return RATP_STATUS_ERROR_BAD_ARGUMENT;
  }

  pkt_parser->cbs = *callbacks;
  pkt_parser->state = RATP_RX_PKT_SFH;
  /* Other fields will be set before use */

  return RATP_STATUS_OK;
}

ratp_status
ratp_pkt_parser_rx_bytes(struct ratp_pkt_parser *pkt_parser, const uint8_t *data, size_t data_len)
{
  size_t i;

  if (pkt_parser == NULL || (data_len > 0 && data == NULL))
  {
    return RATP_STATUS_ERROR_BAD_ARGUMENT;
  }

  for (i = 0; i < data_len; i++)
  {
    rx_byte(pkt_parser, data[i]);
  }

  return RATP_STATUS_OK;
}

/******************************/
/* Local Function Definitions */
/******************************/

static void
rx_byte(struct ratp_pkt_parser *pkt_parser, uint8_t byte)
{
  uint16_t chksum;
  uint8_t hdr_chksum;

  switch (pkt_parser->state)
  {
    case RATP_RX_PKT_SFH:
      if (byte == SYNCH)
      {
        pkt_parser->receiving_pkt.data.data_base = NULL;
        pkt_parser->state = RATP_RX_PKT_HDR_CTRL;
      }
      break;
    case RATP_RX_PKT_HDR_CTRL:
      pkt_parser->receiving_pkt.hdr.ctrl = byte;
      pkt_parser->state = RATP_RX_PKT_HDR_DLEN;
      break;
    case RATP_RX_PKT_HDR_DLEN:
      pkt_parser->receiving_pkt.hdr.len = byte;
      pkt_parser->state = RATP_RX_PKT_HDR_CHKSUM;
      break;
    case RATP_RX_PKT_HDR_CHKSUM:
      hdr_chksum = 0x00;
      hdr_chksum = hdr_chksum_step(hdr_chksum, pkt_parser->receiving_pkt.hdr.ctrl);
      hdr_chksum = hdr_chksum_step(hdr_chksum, pkt_parser->receiving_pkt.hdr.len);
      hdr_chksum = hdr_chksum_step(hdr_chksum, byte);
      if (hdr_chksum == 0xff)
      {
        /* Checksum is correct => The header is valid */
        if (ratp_pkt_expects_data(&pkt_parser->receiving_pkt))
        {
          /* The packet has an associated data packet */
          if (pkt_parser->receiving_pkt.hdr.len > RATP_MAXIMUM_DATA_LENGTH)
          {
            /* The data length is too large => Trigger the MDL error handler */
            pkt_parser->cbs.mdl_err_hdlr(pkt_parser->cbs.ctx,
                pkt_parser->receiving_pkt.hdr.len, RATP_MAXIMUM_DATA_LENGTH);
          }
          else
          {
            /* The data length is appropriate => Start receiving the data */
            pkt_parser->receiving_pkt.data.data_base = pkt_parser->recv_pkt_data;
            pkt_parser->receiving_pkt.data.data_base_len = sizeof(pkt_parser->recv_pkt_data);
            pkt_parser->receiving_pkt.data.data_start = 0;
            pkt_parser->data_bytes_read = 0;
            pkt_parser->state = RATP_RX_PKT_DATA;
          }
        }
        else
        {
          /* There is no associated data => Packet is ready to be processed */
          pkt_parser->cbs.rx_pkt(pkt_parser->cbs.ctx, &pkt_parser->receiving_pkt);

          /* Packet received => Start looking for next SYNCH */
          pkt_parser->state = RATP_RX_PKT_SFH;
        }
      }
      else
      {
        /*
         * Header checksum is invalid => Restart at SYNCH and reprocess the
         * bytes we've received so far
         */
        pkt_parser->state = RATP_RX_PKT_SFH;

        /*
         * Note: Recursion depth is 1 here because we will not pass enough bytes
         * to rx_byte on this call to reach this code again.
         */
        rx_byte(pkt_parser, pkt_parser->receiving_pkt.hdr.ctrl);
        rx_byte(pkt_parser, pkt_parser->receiving_pkt.hdr.len);
        rx_byte(pkt_parser, byte);
      }
      break;
    case RATP_RX_PKT_DATA:
      pkt_parser->recv_pkt_data[pkt_parser->data_bytes_read++] = byte;
      if (pkt_parser->data_bytes_read == pkt_parser->receiving_pkt.hdr.len)
      {
        pkt_parser->state = RATP_RX_PKT_DATA_CHKSUM1;
      }
      break;
    case RATP_RX_PKT_DATA_CHKSUM1:
      pkt_parser->data_chksum = byte;
      pkt_parser->state = RATP_RX_PKT_DATA_CHKSUM2;
      break;
    case RATP_RX_PKT_DATA_CHKSUM2:
      pkt_parser->data_chksum <<= 8U;
      pkt_parser->data_chksum |= byte;
      chksum = data_chksum(&pkt_parser->receiving_pkt.data,
          pkt_parser->data_bytes_read);
      chksum = data_chksum_step(chksum, pkt_parser->data_chksum);
      if (chksum == 0xffff)
      {
        /* Data checksum is correct => Packet is ready to be processed */
        pkt_parser->cbs.rx_pkt(pkt_parser->cbs.ctx, &pkt_parser->receiving_pkt);
      }
      pkt_parser->state = RATP_RX_PKT_SFH;
      break;
    default:
      break;
  }
}
