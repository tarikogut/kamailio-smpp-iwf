/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - TLV (Tag-Length-Value) Engine
# Compliant with SMPP v3.4 & SMPP v5.0 Specifications
*/

#ifndef _SMPP_TLV_H_
#define _SMPP_TLV_H_

#include <stdint.h>
#include <stddef.h>

/* SMPP v3.4 & v5.0 Tag Definitions */
#define SMPP_TLV_DEST_ADDR_SUBUNIT          0x0005
#define SMPP_TLV_DEST_NETWORK_TYPE          0x0006
#define SMPP_TLV_DEST_BEARER_TYPE           0x0007
#define SMPP_TLV_RECEIPTED_MSG_ID           0x001E
#define SMPP_TLV_MS_MSG_WAIT_FACILITIES     0x0030
#define SMPP_TLV_SOURCE_SUBADDRESS          0x0202
#define SMPP_TLV_DEST_SUBADDRESS            0x0203
#define SMPP_TLV_SAR_MSG_REF_NUM            0x020C
#define SMPP_TLV_SAR_TOTAL_SEGMENTS         0x020E
#define SMPP_TLV_SAR_SEGMENT_SEQNUM         0x020F
#define SMPP_TLV_MORE_MSGS_TO_FOLLOW        0x0420
#define SMPP_TLV_MSG_PAYLOAD                0x0424
#define SMPP_TLV_MSG_STATE                  0x0427
#define SMPP_TLV_CONGESTION_STATE           0x0428 /* SMPP v5.0 */
#define SMPP_TLV_BILLING_IDENTIFICATION     0x060B /* SMPP v5.0 */
#define SMPP_TLV_SOURCE_NETWORK_TYPE        0x060D
#define SMPP_TLV_SOURCE_BEARER_TYPE         0x060E

/* Message States (for SMPP_TLV_MSG_STATE) */
#define SMPP_MSG_STATE_ENROUTE              1
#define SMPP_MSG_STATE_DELIVERED            2
#define SMPP_MSG_STATE_EXPIRED              3
#define SMPP_MSG_STATE_DELETED              4
#define SMPP_MSG_STATE_UNDELIVERABLE        5
#define SMPP_MSG_STATE_ACCEPTED             6
#define SMPP_MSG_STATE_UNKNOWN              7
#define SMPP_MSG_STATE_REJECTED             8

/* TLV Node */
typedef struct smpp_tlv {
    uint16_t tag;
    uint16_t length;
    uint8_t *value;
    struct smpp_tlv *next;
} smpp_tlv_t;

/* Function prototypes */
smpp_tlv_t *smpp_tlv_create(uint16_t tag, uint16_t length, const uint8_t *val);
int smpp_tlv_add(smpp_tlv_t **head, uint16_t tag, uint16_t length, const uint8_t *val);
smpp_tlv_t *smpp_tlv_find(const smpp_tlv_t *head, uint16_t tag);
void smpp_tlv_free_list(smpp_tlv_t *head);
size_t smpp_tlv_calc_size(const smpp_tlv_t *head);
int smpp_tlv_serialize(const smpp_tlv_t *head, uint8_t *buf, size_t buf_len, size_t *out_len);
int smpp_tlv_parse(const uint8_t *buf, size_t buf_len, smpp_tlv_t **out_head);

#endif /* _SMPP_TLV_H_ */
