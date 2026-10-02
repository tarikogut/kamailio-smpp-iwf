/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Multi-Protocol Interworking & 3GPP IMS IP-SM-GW Header
*/

#ifndef _SMPP_INTERWORK_H_
#define _SMPP_INTERWORK_H_

#include <stdint.h>
#include <stddef.h>
#include "smpp_pdu.h"

/* 1. SMPP <-> HTTP REST Interworking */
int smpp_to_http_json(const smpp_msg_t *msg, const char *msg_id, const char *b_code,
                      char *out_json, size_t max_out);

int http_json_to_smpp(const char *in_json, smpp_msg_t *msg);

int http_response_to_smpp_status(int http_code);

/* 2. 3GPP IMS IP-SM-GW Interworking (3GPP TS 23.204 / TS 24.341) */
/* RP-DATA Types */
#define RP_DATA_MO  0x00 /* Mobile Originated */
#define RP_DATA_MT  0x01 /* Mobile Terminated */
#define RP_ACK_MO   0x02
#define RP_ACK_MT   0x03
#define RP_ERROR_MO 0x04
#define RP_ERROR_MT 0x05

/* Decapsulate 3GPP RP-DATA binary payload into SMPP msg */
int smpp_ims_rp_data_unpack(const uint8_t *rp_buf, size_t rp_len,
                            char *src_msisdn, char *dst_msisdn,
                            char *text_utf8, size_t max_text, uint8_t *data_coding);

/* Encapsulate SMPP msg into 3GPP RP-DATA binary payload for SIP MESSAGE */
int smpp_ims_rp_data_pack(const char *src_msisdn, const char *dst_msisdn,
                          const char *text_utf8, uint8_t *out_rp_buf,
                          size_t max_out, size_t *out_len);

#endif /* _SMPP_INTERWORK_H_ */
