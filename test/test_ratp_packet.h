#ifndef TEST_RATP_PACKET_H
#define TEST_RATP_PACKET_H

#include "unit_test.h"

DECL_TEST(ratp_next_sn);
DECL_TEST(ratp_pkt_is_ctrl_flag_set);
DECL_TEST(ratp_pkt_get_an);
DECL_TEST(ratp_pkt_validate_an);
DECL_TEST(ratp_pkt_set_an);
DECL_TEST(ratp_pkt_set_next_an);
DECL_TEST(ratp_pkt_get_sn);
DECL_TEST(ratp_pkt_validate_sn);
DECL_TEST(ratp_pkt_set_sn);
DECL_TEST(ratp_pkt_set_next_sn);
DECL_TEST(hdr_chksum_step);
DECL_TEST(data_chksum_step);
DECL_TEST(data_chksum);

#endif /* TEST_RATP_PACKET_H */
