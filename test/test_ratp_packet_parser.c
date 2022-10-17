#include "test_ratp_packet_parser.h"
#include "unit_test.h"

#include "ratp_packet_parser.h"

#include <stddef.h>
#include <stdio.h>

#define MAX_PACKETS (10U)

struct pkt_buf
{
  size_t head;
  size_t tail;
  size_t len;
  struct ratp_pkt buf[MAX_PACKETS];
};

struct test_ctx
{
  struct pkt_buf packets;
  bool mdl_error;
};

static void
test_rx_packet_fn(void *ctx, const struct ratp_pkt *pkt)
{
  struct test_ctx *test_ctx = (struct test_ctx *)ctx;
  struct pkt_buf *packet_buffer = &test_ctx->packets;
  if (packet_buffer->len < MAX_PACKETS)
  {
    packet_buffer->buf[packet_buffer->tail++] = *pkt;
    packet_buffer->tail %= MAX_PACKETS;
    packet_buffer->len++;
  }
  else
  {
    fprintf(stderr, "%s: %s: Packet buffer full!\n", __FILE__, __func__);
  }
}

static void
test_mdl_err_hdlr_fn(void *ctx, uint8_t pkt_data_len, uint8_t mdl)
{
  struct test_ctx *test_ctx = (struct test_ctx *)ctx;

  (void)pkt_data_len;
  (void)mdl;

  test_ctx->mdl_error = true;
}

DECL_TEST(ratp_pkt_parser_init)
{
  struct ratp_pkt_parser pkt_parser;

  struct ratp_pkt_parser_callbacks good_cbs =
  {
    .ctx = NULL,
    .rx_pkt = test_rx_packet_fn,
    .mdl_err_hdlr = test_mdl_err_hdlr_fn
  };

  struct ratp_pkt_parser_callbacks bad_cbs =
  {
    .ctx = NULL,
    .rx_pkt = NULL,
    .mdl_err_hdlr = NULL
  };

  ASSERT_EQ(ratp_pkt_parser_init(&pkt_parser, &good_cbs), RATP_STATUS_OK);
  ASSERT_EQ(ratp_pkt_parser_init(&pkt_parser, &bad_cbs), RATP_STATUS_ERROR_BAD_ARGUMENT);
  ASSERT_EQ(ratp_pkt_parser_init(NULL, &good_cbs), RATP_STATUS_ERROR_BAD_ARGUMENT);

  TEST_END();
}

DECL_TEST(ratp_pkt_parser_rx_bytes)
{
  struct ratp_pkt_parser pkt_parser;
  const struct ratp_pkt *cur_pkt;
  struct test_ctx ctx =
  {
    .packets =
    {
      .head = 0,
      .tail = 0,
      .len = 0
    },
    .mdl_error = false
  };

  struct ratp_pkt_parser_callbacks cbs =
  {
    .ctx = &ctx,
    .rx_pkt = test_rx_packet_fn,
    .mdl_err_hdlr = test_mdl_err_hdlr_fn
  };

  uint8_t empty_packet_bytes[] =
  {
/*     1     2     3     4 */
    0x01, 0xc8, 0x00, 0x37
  };

  uint8_t partial_packet_bytes[] =
  {
/*     1     2     3     4                                  5 */
    0x01, 0x01, 0x80, 0x12, /* Wrong header checksum! */ 0x6d
       /* ^^^^^^^^^^^^^^^^^       Received Packet        ^^^^ */
  };

  uint8_t data_packet_bytes[] =
  {
/*     1     2     3     4 */
    0x01, 0x46, 0x03, 0xb6,
/*     5     6     7     8     9 */
    0xab, 0xcd, 0xef, 0x65, 0x31
  };

  ASSERT_EQ(ratp_pkt_parser_init(&pkt_parser, &cbs), RATP_STATUS_OK);

  /* Test out parameter validation */
  ASSERT_EQ(ratp_pkt_parser_rx_bytes(&pkt_parser, NULL, 0), RATP_STATUS_OK);
  ASSERT_EQ(ratp_pkt_parser_rx_bytes(&pkt_parser, NULL, 1), RATP_STATUS_ERROR_BAD_ARGUMENT);
  ASSERT_EQ(ratp_pkt_parser_rx_bytes(NULL, NULL, 0), RATP_STATUS_ERROR_BAD_ARGUMENT);

  /***************************************************/
  /* Receive bytes which should form an empty packet */
  /***************************************************/

  /* Check that we are starting with no packets in the queue */
  ASSERT_EQ(ctx.packets.len, 0);

  ASSERT_EQ(ratp_pkt_parser_rx_bytes(&pkt_parser, empty_packet_bytes, sizeof(empty_packet_bytes)), RATP_STATUS_OK);

  /* Check that a packet was received */
  ASSERT_EQ(ctx.packets.len, 1);

  /* Get the packet out of the queue */
  cur_pkt = &ctx.packets.buf[ctx.packets.head++];
  ctx.packets.head %= MAX_PACKETS;
  ctx.packets.len--;

  /* Check the packet contents */
  ASSERT_EQ(cur_pkt->hdr.ctrl, 0xc8);
  ASSERT_EQ(cur_pkt->hdr.len, 0x00);

  /***************************************************************************/
  /* Receive bytes which should trigger the header to be rescanned for SYNCH */
  /***************************************************************************/

  /* Check that we are starting with no packets in the queue */
  ASSERT_EQ(ctx.packets.len, 0);

  ASSERT_EQ(ratp_pkt_parser_rx_bytes(&pkt_parser, partial_packet_bytes, sizeof(partial_packet_bytes)), RATP_STATUS_OK);

  /* Check that a packet was received */
  ASSERT_EQ(ctx.packets.len, 1);

  /* Get the packet out of the queue */
  cur_pkt = &ctx.packets.buf[ctx.packets.head++];
  ctx.packets.head %= MAX_PACKETS;
  ctx.packets.len--;

  /* Check the packet contents */
  ASSERT_EQ(cur_pkt->hdr.ctrl, 0x80);
  ASSERT_EQ(cur_pkt->hdr.len, 0x12);

  /******************************************************/
  /* Receive bytes which should form a packet with data */
  /******************************************************/

  /* Check that we are starting with no packets in the queue */
  ASSERT_EQ(ctx.packets.len, 0);

  ASSERT_EQ(ratp_pkt_parser_rx_bytes(&pkt_parser, data_packet_bytes, sizeof(data_packet_bytes)), RATP_STATUS_OK);

  /* Check that a packet was received */
  ASSERT_EQ(ctx.packets.len, 1);

  /* Get the packet out of the queue */
  cur_pkt = &ctx.packets.buf[ctx.packets.head++];
  ctx.packets.head %= MAX_PACKETS;
  ctx.packets.len--;

  /* Check the packet contents */
  ASSERT_EQ(cur_pkt->hdr.ctrl, 0x46);
  ASSERT_EQ(cur_pkt->hdr.len, 0x03);
  ASSERT_EQ(cur_pkt->data.data_start, 0);
  ASSERT(cur_pkt->data.data_base_len >= cur_pkt->hdr.len);
  ASSERT_EQ(memcmp(cur_pkt->data.data_base, &data_packet_bytes[4], cur_pkt->hdr.len), 0);

  TEST_END();
}
