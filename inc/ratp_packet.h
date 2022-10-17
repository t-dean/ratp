#ifndef RATP_PACKET_H
#define RATP_PACKET_H

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * Control field bits
 */
typedef enum ratp_packet_header_ctrl_e
{
  RATP_PKT_HDR_CTRL_SO  = 1U << 0U, /*!< Single octet */
  RATP_PKT_HDR_CTRL_EOR = 1U << 1U, /*!< End of record */
  RATP_PKT_HDR_CTRL_AN  = 1U << 2U, /*!< Acknowledge number */
  RATP_PKT_HDR_CTRL_SN  = 1U << 3U, /*!< Sequence number */
  RATP_PKT_HDR_CTRL_RST = 1U << 4U, /*!< Reset */
  RATP_PKT_HDR_CTRL_FIN = 1U << 5U, /*!< Finish */
  RATP_PKT_HDR_CTRL_ACK = 1U << 6U, /*!< Acknowledgement */
  RATP_PKT_HDR_CTRL_SYN = 1U << 7U, /*!< Synchronize */
} ratp_pkt_hdr_ctrl;

/**
 * Index into a ring buffer (for iterating through a portion of a ring buffer)
 */
struct ratp_ring_buf_idx
{
  const uint8_t *data_base; /*!< Base of the ring buffer */
  size_t data_start;        /*!< Starting index into the ring buffer */
  size_t data_base_len;     /*!< Size of the underlying ring buffer */
};

/**
 * RATP packet header
 */
struct ratp_pkt_hdr
{
  uint8_t ctrl; /*!< Control byte */
  uint8_t len;  /*!< Length */
};

/**
 * RATP packet
 */
struct ratp_pkt
{
  struct ratp_pkt_hdr hdr;       /*!< Header */
  struct ratp_ring_buf_idx data; /*!< Associated data packet */
};

/**
 * Increment the sequence number
 *
 * \param[in] seq The current sequence number
 * \return The next sequence number
 */
static inline uint8_t
ratp_next_sn(uint8_t seq)
{
  assert(seq == 0 || seq == 1);
  return !seq;
}

/**
 * Initialize a packet with some associated data
 *
 * \param[out] pkt The packet to initialize
 * \param[in] ring_buf_idx The ring buffer index of the data
 */
static inline void
ratp_pkt_init_with_data(struct ratp_pkt *pkt, const struct ratp_ring_buf_idx *ring_buf_idx)
{
  pkt->hdr.ctrl = 0;
  pkt->hdr.len = 0;
  pkt->data = *ring_buf_idx;
}

/**
 * Initialize a packet
 *
 * \param[out] pkt The packet to initialize
 */
static inline void
ratp_pkt_init(struct ratp_pkt *pkt)
{
  const struct ratp_ring_buf_idx ring_buf_idx =
  {
    .data_base = NULL,
    .data_start = 0,
    .data_base_len = 0
  };
  ratp_pkt_init_with_data(pkt, &ring_buf_idx);
}

/**
 * Check if a control flag is set
 *
 * \param[in] pkt The packet
 * \param[in] ctrl_flag The control flag to check
 * \return true if the flag is set, false otherwise
 */
static inline bool
ratp_pkt_is_ctrl_flag_set(const struct ratp_pkt *pkt, ratp_pkt_hdr_ctrl ctrl_flag)
{
  return (pkt->hdr.ctrl & ctrl_flag) != 0;
}

/**
 * Set a control flag for a packet
 *
 * \param[in,out] pkt The packet
 * \param[in] ctrl_flag The control flag to set
 */
static inline void
ratp_pkt_set_ctrl_flag(struct ratp_pkt *pkt, ratp_pkt_hdr_ctrl ctrl_flag)
{
  pkt->hdr.ctrl |= ctrl_flag;
}

/**
 * Clear a control flag for a packet
 *
 * \param[in,out] pkt The packet
 * \param[in] ctrl_flag The control flag to clear
 */
static inline void
ratp_pkt_clear_ctrl_flag(struct ratp_pkt *pkt, ratp_pkt_hdr_ctrl ctrl_flag)
{
  pkt->hdr.ctrl &= ~ctrl_flag;
}

/**
 * Get the acknowledgement number of the packet
 *
 * \param[in] pkt The packet
 * \return The acknowledgement number for the packet
 */
static inline uint8_t
ratp_pkt_get_an(const struct ratp_pkt *pkt)
{
  return ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_AN) ? 1 : 0;
}

/**
 * Validate the acknowledge number of the packet is expected
 *
 * \param[in] pkt The packet
 * \param[in] sn The current sequence number
 * \return true if the packet's AN ACKs the current sequence number, false
 *         otherwise
 */
static inline bool
ratp_pkt_validate_an(const struct ratp_pkt *pkt, uint8_t sn)
{
  return ratp_pkt_get_an(pkt) == ratp_next_sn(sn);
}

/**
 * Set a packet's acknowledgement number
 *
 * \param[in,out] pkt The packet
 * \param[in] an The new AN
 */
static inline void
ratp_pkt_set_an(struct ratp_pkt *pkt, uint8_t an)
{
  assert(an == 0 || an == 1);
  if (an != 0)
  {
    ratp_pkt_set_ctrl_flag(pkt, RATP_PKT_HDR_CTRL_AN);
  }
  else
  {
    ratp_pkt_clear_ctrl_flag(pkt, RATP_PKT_HDR_CTRL_AN);
  }
}

/**
 * Set a packet's acknowledgement number to the next sequence number
 *
 * \param[in,out] pkt The packet
 * \param[in] an The AN
 */
static inline void
ratp_pkt_set_next_an(struct ratp_pkt *pkt, uint8_t an)
{
  assert(an == 0 || an == 1);
  ratp_pkt_set_an(pkt, ratp_next_sn(an));
}

/**
 * Gets a packet's sequence number
 *
 * \param[in] pkt The packet
 * return The packet's sequence number
 */
static inline uint8_t
ratp_pkt_get_sn(const struct ratp_pkt *pkt)
{
  return ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SN) ? 1 : 0;
}

/**
 * Validate the sequence number of the packet is expected
 *
 * \param[in] pkt The packet
 * \param[in] sn The current receiving sequence number
 * \return true if the packet's SN matches the current receiving sequence
 *         number, false otherwise
 */
static inline bool
ratp_pkt_validate_sn(const struct ratp_pkt *pkt, uint8_t rn)
{
  return ratp_pkt_get_sn(pkt) == ratp_next_sn(rn);
}

/**
 * Set a packet's sequence number
 *
 * \param[in,out] pkt The packet
 * \param[in] sn The new SN
 */
static inline void
ratp_pkt_set_sn(struct ratp_pkt *pkt, uint8_t sn)
{
  assert(sn == 0 || sn == 1);
  if (sn != 0)
  {
    ratp_pkt_set_ctrl_flag(pkt, RATP_PKT_HDR_CTRL_SN);
  }
  else
  {
    ratp_pkt_clear_ctrl_flag(pkt, RATP_PKT_HDR_CTRL_SN);
  }
}

/**
 * Set a packet's sequence number to the next sequence number
 *
 * \param[in,out] pkt The packet
 * \param[in] sn The sn
 */
static inline void
ratp_pkt_set_next_sn(struct ratp_pkt *pkt, uint8_t sn)
{
  assert(sn == 0 || sn == 1);
  ratp_pkt_set_sn(pkt, ratp_next_sn(sn));
}

/**
 * Checks if a packet should be followed by a data packet
 *
 * \param[in] pkt The packet to check
 * \return true if the packet should be followed by a data packet, false if the
 *         packet is just the header
 */
static inline bool
ratp_pkt_expects_data(const struct ratp_pkt *pkt)
{
  return !ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SYN)
    &&   !ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_RST)
    &&   !ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_FIN)
    &&   !ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SO)
    &&   pkt->hdr.len > 0;
}

/**
 * Check if a packet has an associated data packet
 *
 * \param[in] pkt The packet
 * \return true if the packet has an associated data packet
 */
static inline bool
ratp_pkt_has_data(const struct ratp_pkt *pkt)
{
  return pkt->data.data_base != NULL;
}

/**
 * Check if a packet has user data
 *
 * \param[in] pkt The packet
 * \return true if the packet has user data
 */
static inline bool
ratp_pkt_has_user_data(const struct ratp_pkt *pkt)
{
  return ratp_pkt_is_ctrl_flag_set(pkt, RATP_PKT_HDR_CTRL_SO) ||
         ratp_pkt_has_data(pkt);
}

/**
 * Header checksum step function
 *
 * \param[in] chksum The current checksum
 * \param[in] byte The byte to add to the checksum
 * \return The new checksum
 */
static inline uint8_t
hdr_chksum_step(uint8_t chksum, uint8_t byte)
{
  uint8_t new_chksum;

  new_chksum = chksum + byte;
  if (new_chksum < chksum)
  {
    new_chksum++;
  }

  return new_chksum;
}

/**
 * Data checksum step function
 *
 * \param[in] chksum The current checksum
 * \param[in] word The word to add to the checksum
 * \return The new checksum
 */
static inline uint16_t
data_chksum_step(uint16_t chksum, uint16_t word)
{
  uint16_t new_chksum;

  new_chksum = chksum + word;
  if (new_chksum < chksum)
  {
    new_chksum++;
  }

  return new_chksum;
}

/**
 * Data checksum function
 *
 * \param[in] ring_buf_idx The starting index into the data ring buffer
 * \param[in] data_len The length of data to checksum
 * \return The data's checksum
 */
static inline uint16_t
data_chksum(const struct ratp_ring_buf_idx *ring_buf_idx, size_t data_len)
{
  size_t i;
  size_t data_i;
  uint16_t word;
  uint16_t chksum = 0;

  data_i = ring_buf_idx->data_start;
  for (i = 0; i < data_len - 1; i += 2)
  {
    word = ring_buf_idx->data_base[data_i];
    word <<= 8U;
    word |= ring_buf_idx->data_base[(data_i + 1) % ring_buf_idx->data_base_len];
    chksum = data_chksum_step(chksum, word);

    data_i += 2;
    data_i %= ring_buf_idx->data_base_len;
  }

  if (i == data_len - 1)
  {
    word = ring_buf_idx->data_base[data_i];
    word <<= 8U;
    chksum = data_chksum_step(chksum, word);
  }

  return chksum;
}

#endif /* RATP_PACKET_H */
