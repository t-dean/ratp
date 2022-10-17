#include "test_ratp_packet.h"

#include "unit_test.h"

#include "ratp_packet.h"

DECL_TEST(ratp_next_sn)
{
  ASSERT_EQ(ratp_next_sn(0), 1);
  ASSERT_EQ(ratp_next_sn(1), 0);

  TEST_END();
}

DECL_TEST(ratp_pkt_is_ctrl_flag_set)
{
  struct ratp_pkt test_packet;

  /* Set some bits in the control byte */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_SYN | RATP_PKT_HDR_CTRL_ACK;

  /* Check that the bits are set using ratp_pkt_is_ctrl_flag_set */
  ASSERT(ratp_pkt_is_ctrl_flag_set(&test_packet, RATP_PKT_HDR_CTRL_SYN));
  ASSERT(ratp_pkt_is_ctrl_flag_set(&test_packet, RATP_PKT_HDR_CTRL_ACK));

  /* Check that ratp_pkt_is_ctrl_flag_set doesn't report unset bits as set */
  ASSERT(!ratp_pkt_is_ctrl_flag_set(&test_packet, RATP_PKT_HDR_CTRL_RST));
  ASSERT(!ratp_pkt_is_ctrl_flag_set(&test_packet, RATP_PKT_HDR_CTRL_FIN));

  TEST_END();
}

DECL_TEST(ratp_pkt_get_an)
{
  struct ratp_pkt test_packet;

  /* Set the AN flag to indicate AN is one (1) */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_AN;

  /* Check that ratp_pkt_get_an returns an AN of one (1) */
  ASSERT_EQ(ratp_pkt_get_an(&test_packet), 1);

  /* Set the AN flag to indicate AN is zero (0) */
  test_packet.hdr.ctrl = 0;

  /* Check that ratp_pkt_get_an returns an AN of zero (0) */
  ASSERT_EQ(ratp_pkt_get_an(&test_packet), 0);

  TEST_END();
}

DECL_TEST(ratp_pkt_validate_an)
{
  struct ratp_pkt test_packet;

  /* Set the AN flag to indicate AN is one (1) */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_AN | RATP_PKT_HDR_CTRL_ACK;

  /* Check that it returns true for a packet with AN == sn + 1 (mod 2) */
  ASSERT(ratp_pkt_validate_an(&test_packet, 0));
  /* Check that it returns false for a packet with AN != sn + 1 (mod 2) */
  ASSERT(!ratp_pkt_validate_an(&test_packet, 1));

  /* Clear the AN flag to indicate AN is zero (0) */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_ACK;

  /* Check that it returns true for a packet with AN == sn + 1 (mod 2) */
  ASSERT(ratp_pkt_validate_an(&test_packet, 1));
  /* Check that it returns false for a packet with AN != sn + 1 (mod 2) */
  ASSERT(!ratp_pkt_validate_an(&test_packet, 0));

  TEST_END();
}

DECL_TEST(ratp_pkt_set_an)
{
  struct ratp_pkt test_packet;

  /* Set the control byte to some initial value without setting AN */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_RST;
  /* Set the AN to 1 */
  ratp_pkt_set_an(&test_packet, 1);
  /* Check that the AN flag was set */
  ASSERT(test_packet.hdr.ctrl & RATP_PKT_HDR_CTRL_AN);

  /* Set the control byte to some initial value without setting AN */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_RST;
  /* Set the AN to 0 */
  ratp_pkt_set_an(&test_packet, 0);
  /* Check that the AN flag was not set */
  ASSERT(!(test_packet.hdr.ctrl & RATP_PKT_HDR_CTRL_AN));

  TEST_END();
}

DECL_TEST(ratp_pkt_set_next_an)
{
  struct ratp_pkt test_packet;
  struct ratp_pkt test_packet2;

  /* Set the control byte to some initial value without setting AN */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_RST;
  /* Set AN to the AN after 1 (0) */
  ratp_pkt_set_next_an(&test_packet, 1);
  /* Check that the AN flag was not set */
  ASSERT(!(test_packet.hdr.ctrl & RATP_PKT_HDR_CTRL_AN));

  /* Set the control byte to some initial value without setting AN */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_RST;
  /* Set AN to the AN after 0 (1) */
  ratp_pkt_set_next_an(&test_packet, 0);
  /* Check that the AN flag was set */
  ASSERT(test_packet.hdr.ctrl & RATP_PKT_HDR_CTRL_AN);

  ratp_pkt_set_sn(&test_packet, 1);
  ratp_pkt_set_next_an(&test_packet2, ratp_pkt_get_sn(&test_packet));
  ASSERT_EQ(ratp_pkt_get_an(&test_packet2), 0);

  ratp_pkt_set_sn(&test_packet, 0);
  ratp_pkt_set_next_an(&test_packet2, ratp_pkt_get_sn(&test_packet));
  ASSERT_EQ(ratp_pkt_get_an(&test_packet2), 1);

  TEST_END();
}

DECL_TEST(ratp_pkt_get_sn)
{
  struct ratp_pkt test_packet;

  /* Set the SN flag to indicate SN is one (1) */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_SN;

  /* Check that ratp_pkt_get_an returns an SN of one (1) */
  ASSERT_EQ(ratp_pkt_get_sn(&test_packet), 1);

  /* Set the SN flag to indicate SN is zero (0) */
  test_packet.hdr.ctrl = 0;

  /* Check that ratp_pkt_get_an returns an SN of zero (0) */
  ASSERT_EQ(ratp_pkt_get_sn(&test_packet), 0);

  TEST_END();
}

DECL_TEST(ratp_pkt_validate_sn)
{
  struct ratp_pkt test_packet;

  /* Set the SN flag to indicate SN is one (1) */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_SN | RATP_PKT_HDR_CTRL_ACK;

  /* Check that it returns true for a packet with SN == rn + 1 (mod 2) */
  ASSERT(ratp_pkt_validate_sn(&test_packet, 0));
  /* Check that it returns false for a packet with SN != rn + 1 (mod 2) */
  ASSERT(!ratp_pkt_validate_sn(&test_packet, 1));

  /* Clear the SN flag to indicate SN is zero (0) */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_ACK;

  /* Check that it returns true for a packet with SN == rn + 1 (mod 2) */
  ASSERT(ratp_pkt_validate_sn(&test_packet, 1));
  /* Check that it returns false for a packet with SN != rn + 1 (mod 2) */
  ASSERT(!ratp_pkt_validate_sn(&test_packet, 0));
  TEST_END();
}

DECL_TEST(ratp_pkt_set_sn)
{
  struct ratp_pkt test_packet;

  /* Set the control byte to some initial value without setting SN */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_RST;
  /* Set the SN to 1 */
  ratp_pkt_set_sn(&test_packet, 1);
  /* Check that the SN flag was set */
  ASSERT(test_packet.hdr.ctrl & RATP_PKT_HDR_CTRL_SN);

  /* Set the control byte to some initial value without setting SN */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_RST;
  /* Set the SN to 0 */
  ratp_pkt_set_sn(&test_packet, 0);
  /* Check that the SN flag was not set */
  ASSERT(!(test_packet.hdr.ctrl & RATP_PKT_HDR_CTRL_SN));

  TEST_END();
}

DECL_TEST(ratp_pkt_set_next_sn)
{
  struct ratp_pkt test_packet;

  /* Set the control byte to some initial value without setting SN */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_RST;
  /* Set SN to the SN after 1 (0) */
  ratp_pkt_set_next_sn(&test_packet, 1);
  /* Check that the SN flag was not set */
  ASSERT(!(test_packet.hdr.ctrl & RATP_PKT_HDR_CTRL_SN));

  /* Set the control byte to some initial value without setting SN */
  test_packet.hdr.ctrl = RATP_PKT_HDR_CTRL_RST;
  /* Set SN to the SN after 0 (1) */
  ratp_pkt_set_next_sn(&test_packet, 0);
  /* Check that the SN flag was set */
  ASSERT(test_packet.hdr.ctrl & RATP_PKT_HDR_CTRL_SN);

  TEST_END();
}

DECL_TEST(hdr_chksum_step)
{
  ASSERT_EQ(hdr_chksum_step(10, 10), 10 + 10);
  ASSERT_EQ(hdr_chksum_step(200, 100), (uint8_t)(200 + 100 + 1));
  ASSERT_EQ(hdr_chksum_step(0xff, 0x01), 0x01);
  TEST_END();
}

DECL_TEST(data_chksum_step)
{
  ASSERT_EQ(data_chksum_step(10, 10), 10 + 10);
  ASSERT_EQ(data_chksum_step(65000, 1000), (uint16_t)(65000 + 1000 + 1));
  ASSERT_EQ(data_chksum_step(0xffff, 0x0001), 0x0001);
  TEST_END();
}

DECL_TEST(data_chksum)
{
  const uint8_t data[] = {
/*     0     1     2     3 */
    0x11, 0x22, 0x33, 0x44
  };
  const struct ratp_ring_buf_idx data_ring_buf_idx =
  {
    .data_base = data,
    .data_start = 0,
    .data_base_len = sizeof(data)
  };

  const uint8_t wrapping_data[] = {
/*     0     1     2     3 */
    0xff, 0x11, 0x11, 0x22
  };
  const struct ratp_ring_buf_idx wrapping_data_ring_buf_idx =
  {
    .data_base = wrapping_data,
    .data_start = 0,
    .data_base_len = sizeof(wrapping_data)
  };

  const uint8_t padded_data[] = {
/*     0     1     2     3     4 */
    0x22, 0x11, 0x44, 0x33, 0x55
  };
  const struct ratp_ring_buf_idx padded_data_ring_buf_idx =
  {
    .data_base = padded_data,
    .data_start = 0,
    .data_base_len = sizeof(padded_data)
  };

  ASSERT_EQ(data_chksum(&data_ring_buf_idx, sizeof(data)), 0x1122 + 0x3344);
  ASSERT_EQ(data_chksum(&wrapping_data_ring_buf_idx, sizeof(wrapping_data)), (uint16_t)(0xff11 + 0x1122 + 0x0001));
  ASSERT_EQ(data_chksum(&padded_data_ring_buf_idx, sizeof(padded_data)), 0x2211 + 0x4433 + 0x5500);

  TEST_END();
}
