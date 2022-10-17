#ifndef TEST_RATP_H
#define TEST_RATP_H

#include "unit_test.h"

DECL_TEST(ratp_init);
DECL_TEST(ratp_init_failed_timer_init);
DECL_TEST(ratp_strerror);
DECL_TEST(ratp_strtimer);
DECL_TEST(ratp_strstate);
DECL_TEST(ratp_listen);
DECL_TEST(ratp_connect);
DECL_TEST(ratp_send);
DECL_TEST(ratp_close);

DECL_TEST(ratp_rx_packet_listen);
DECL_TEST(ratp_rx_packet_listen_ack);
DECL_TEST(ratp_rx_packet_listen_rst);
DECL_TEST(ratp_rx_packet_listen_fin);
DECL_TEST(ratp_rx_packet_syn_sent);
DECL_TEST(ratp_rx_packet_syn_sent_bad_an);
DECL_TEST(ratp_rx_packet_syn_sent_rst);
DECL_TEST(ratp_rx_packet_syn_sent_syn);
DECL_TEST(ratp_rx_packet_syn_sent_fin);
DECL_TEST(ratp_rx_packet_syn_recvd_close_bad_sn);
DECL_TEST(ratp_rx_packet_syn_recvd_no_ack);
DECL_TEST(ratp_rx_packet_syn_recvd_listen_bad_ack);
DECL_TEST(ratp_rx_packet_syn_recvd_connect_bad_ack);
DECL_TEST(ratp_rx_packet_established_close_bad_sn);
DECL_TEST(ratp_rx_packet_established_no_ack);
DECL_TEST(ratp_rx_packet_established_bad_an);
DECL_TEST(ratp_rx_packet_established_fin_data_pending);
DECL_TEST(ratp_rx_packet_fin_wait_no_fin);
DECL_TEST(ratp_rx_packet_fin_wait_no_ack);
DECL_TEST(ratp_rx_packet_fin_wait_fin_with_data);
DECL_TEST(ratp_rx_packet_last_ack_bad_an);
DECL_TEST(ratp_rx_packet_closing_bad_an);
DECL_TEST(ratp_rx_packet_time_wait_no_fin);
DECL_TEST(ratp_rx_packet_closed_reset);
DECL_TEST(ratp_rx_packet_msg_hdlr);
DECL_TEST(ratp_rx_packet_msg_hdlr_overflow);
DECL_TEST(ratp_rx_packet_msg_hdlr_overflow_so);
DECL_TEST(ratp_send_full_buffer);
DECL_TEST(ratp_send_data_full_buffer);

#endif /* TEST_RATP_H */
