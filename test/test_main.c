#include "test_ratp.h"
#include "test_ratp_packet.h"
#include "test_ratp_packet_parser.h"

#include "schema_tester.h"

int main(void)
{
  TEST_MAIN_START();

  RUN_TEST(ratp_init);
  RUN_TEST(ratp_init_failed_timer_init);
  RUN_TEST(ratp_strerror);
  RUN_TEST(ratp_strtimer);
  RUN_TEST(ratp_strstate);
  RUN_TEST(ratp_listen);
  RUN_TEST(ratp_connect);
  RUN_TEST(ratp_send);
  RUN_TEST(ratp_close);
  RUN_TEST(ratp_rx_packet_listen);
  RUN_TEST(ratp_rx_packet_listen_ack);
  RUN_TEST(ratp_rx_packet_listen_rst);
  RUN_TEST(ratp_rx_packet_listen_fin);
  RUN_TEST(ratp_rx_packet_syn_sent);
  RUN_TEST(ratp_rx_packet_syn_sent_bad_an);
  RUN_TEST(ratp_rx_packet_syn_sent_rst);
  RUN_TEST(ratp_rx_packet_syn_sent_syn);
  RUN_TEST(ratp_rx_packet_syn_sent_fin);
  RUN_TEST(ratp_rx_packet_syn_recvd_close_bad_sn);
  RUN_TEST(ratp_rx_packet_syn_recvd_no_ack);
  RUN_TEST(ratp_rx_packet_syn_recvd_listen_bad_ack);
  RUN_TEST(ratp_rx_packet_syn_recvd_connect_bad_ack);
  RUN_TEST(ratp_rx_packet_established_close_bad_sn);
  RUN_TEST(ratp_rx_packet_established_no_ack);
  RUN_TEST(ratp_rx_packet_established_bad_an);
  RUN_TEST(ratp_rx_packet_established_fin_data_pending);
  RUN_TEST(ratp_rx_packet_fin_wait_no_fin);
  RUN_TEST(ratp_rx_packet_fin_wait_no_ack);
  RUN_TEST(ratp_rx_packet_fin_wait_fin_with_data);
  RUN_TEST(ratp_rx_packet_last_ack_bad_an);
  RUN_TEST(ratp_rx_packet_closing_bad_an);
  RUN_TEST(ratp_rx_packet_time_wait_no_fin);
  RUN_TEST(ratp_rx_packet_closed_reset);
  RUN_TEST(ratp_rx_packet_msg_hdlr);
  RUN_TEST(ratp_rx_packet_msg_hdlr_overflow);
  RUN_TEST(ratp_rx_packet_msg_hdlr_overflow_so);
  RUN_TEST(ratp_send_full_buffer);
  RUN_TEST(ratp_send_data_full_buffer);

  RUN_TEST(ratp_next_sn);
  RUN_TEST(ratp_pkt_is_ctrl_flag_set);
  RUN_TEST(ratp_pkt_get_an);
  RUN_TEST(ratp_pkt_validate_an);
  RUN_TEST(ratp_pkt_set_an);
  RUN_TEST(ratp_pkt_set_next_an);
  RUN_TEST(ratp_pkt_get_sn);
  RUN_TEST(ratp_pkt_validate_sn);
  RUN_TEST(ratp_pkt_set_sn);
  RUN_TEST(ratp_pkt_set_next_sn);
  RUN_TEST(hdr_chksum_step);
  RUN_TEST(data_chksum_step);
  RUN_TEST(data_chksum);

  RUN_TEST(ratp_pkt_parser_init);
  RUN_TEST(ratp_pkt_parser_rx_bytes);

  RUN_SCHEMA_TEST("test/schemas/basic_connection.schema");
  RUN_SCHEMA_TEST("test/schemas/dropped_ack.schema");
  RUN_SCHEMA_TEST("test/schemas/duplicate_data_packet.schema");
  RUN_SCHEMA_TEST("test/schemas/closing_connection.schema");
  RUN_SCHEMA_TEST("test/schemas/retransmit_packet.schema");
  RUN_SCHEMA_TEST("test/schemas/simultaneous_close.schema");
  RUN_SCHEMA_TEST("test/schemas/multipart_message.schema");
  RUN_SCHEMA_TEST("test/schemas/queued_message.schema");
  RUN_SCHEMA_TEST("test/schemas/simultaneous_connect.schema");
  RUN_SCHEMA_TEST("test/schemas/large_data_packet.schema");
  RUN_SCHEMA_TEST("test/schemas/dropped_final_ack.schema");
  RUN_SCHEMA_TEST("test/schemas/single_octet.schema");
  RUN_SCHEMA_TEST("test/schemas/retransmission_failure.schema");
  RUN_SCHEMA_TEST("test/schemas/minimum_timeout.schema");
  RUN_SCHEMA_TEST("test/schemas/reconnection.schema");
  RUN_SCHEMA_TEST("test/schemas/failed_connection.schema");
  RUN_SCHEMA_TEST("test/schemas/failed_simultaneous_connection.schema");
  RUN_SCHEMA_TEST("test/schemas/failed_close.schema");
  RUN_SCHEMA_TEST("test/schemas/failed_close_reopen.schema");
  RUN_SCHEMA_TEST("test/schemas/simultaneous_send.schema");

  TEST_MAIN_END();
}
