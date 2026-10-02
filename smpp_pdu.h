/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - PDU Header & Structures
# Compliant with SMPP v3.4 & SMPP v5.0 Specifications
*/

#ifndef _SMPP_PDU_H_
#define _SMPP_PDU_H_

#include <stdint.h>
#include <stddef.h>
#include "smpp_tlv.h"

/* Command IDs */
#define SMPP_CMD_GENERIC_NACK           0x80000000
#define SMPP_CMD_BIND_RECEIVER          0x00000001
#define SMPP_CMD_BIND_RECEIVER_RESP     0x80000001
#define SMPP_CMD_BIND_TRANSMITTER       0x00000002
#define SMPP_CMD_BIND_TRANSMITTER_RESP  0x80000002
#define SMPP_CMD_QUERY_SM               0x00000003
#define SMPP_CMD_QUERY_SM_RESP          0x80000003
#define SMPP_CMD_SUBMIT_SM              0x00000004
#define SMPP_CMD_SUBMIT_SM_RESP         0x80000004
#define SMPP_CMD_DELIVER_SM             0x00000005
#define SMPP_CMD_DELIVER_SM_RESP        0x80000005
#define SMPP_CMD_UNBIND                 0x00000006
#define SMPP_CMD_UNBIND_RESP            0x80000006
#define SMPP_CMD_CANCEL_SM              0x00000008
#define SMPP_CMD_CANCEL_SM_RESP         0x80000008
#define SMPP_CMD_BIND_TRANSCEIVER       0x00000009
#define SMPP_CMD_BIND_TRANSCEIVER_RESP  0x80000009
#define SMPP_CMD_ENQUIRE_LINK           0x00000015
#define SMPP_CMD_ENQUIRE_LINK_RESP      0x80000015
#define SMPP_CMD_SUBMIT_MULTI           0x00000021
#define SMPP_CMD_SUBMIT_MULTI_RESP      0x80000021
#define SMPP_CMD_DATA_SM                0x00000103
#define SMPP_CMD_DATA_SM_RESP           0x80000103

/* Command Status Codes */
#define ESME_ROK                        0x00000000
#define ESME_RINVMSGLEN                 0x00000001
#define ESME_RINVCMDLEN                 0x00000002
#define ESME_RINVCMDID                  0x00000003
#define ESME_RINVBNDSTS                 0x00000004
#define ESME_RALYBND                    0x00000005
#define ESME_RINVPRTFLG                 0x00000006
#define ESME_RINVREGDLVFLG              0x00000007
#define ESME_RSYSERR                    0x00000008
#define ESME_RINVSRCADR                 0x0000000A
#define ESME_RINVDSTADR                 0x0000000B
#define ESME_RINVMSGID                  0x0000000C
#define ESME_RBINDFAIL                  0x0000000D
#define ESME_RINVPASWD                  0x0000000E
#define ESME_RINVSYSID                  0x0000000F
#define ESME_RSUBMITFAIL                0x00000045
#define ESME_RINVREPFLAG                0x00000050
#define ESME_RINVDESTFLAG               0x00000051
#define ESME_RTHROTTLED                 0x00000058
#define ESME_RMSGBLOCKED                0x00000067
#define ESME_RINVCREDIT                 0x00000068

/* SMPP Interface Versions */
#define SMPP_VERSION_33                 0x33
#define SMPP_VERSION_34                 0x34
#define SMPP_VERSION_50                 0x50

/* Data Coding Schemes */
#define SMPP_ENCODING_DEFAULT           0x00 /* GSM 7-bit default / NLI */
#define SMPP_ENCODING_IA5               0x01 /* ASCII */
#define SMPP_ENCODING_LATIN1            0x03 /* ISO-8859-1 */
#define SMPP_ENCODING_BINARY            0x04 /* 8-bit octet stream */
#define SMPP_ENCODING_UCS2              0x08 /* UTF-16BE / UCS-2 */

/* TON (Type of Number) */
#define SMPP_TON_UNKNOWN                0
#define SMPP_TON_INTERNATIONAL          1
#define SMPP_TON_NATIONAL               2
#define SMPP_TON_NETWORK_SPECIFIC       3
#define SMPP_TON_SUBSCRIBER             4
#define SMPP_TON_ALPHANUMERIC           5
#define SMPP_TON_ABBREVIATED            6

/* NPI (Numbering Plan Indicator) */
#define SMPP_NPI_UNKNOWN                0
#define SMPP_NPI_ISDN                   1 /* E.164 */
#define SMPP_NPI_DATA                   3
#define SMPP_NPI_TELEX                  4
#define SMPP_NPI_LAND_MOBILE            6
#define SMPP_NPI_NATIONAL               8
#define SMPP_NPI_PRIVATE                9
#define SMPP_NPI_ERMES                  10
#define SMPP_NPI_IP                     14

#define SMPP_HEADER_LEN                 16
#define SMPP_MAX_ADDR_LEN               65
#define SMPP_MAX_SHORT_MSG_LEN          256
#define SMPP_MAX_PDU_LEN                65536

/* 16-Byte Standard PDU Header */
typedef struct smpp_header {
    uint32_t command_length;
    uint32_t command_id;
    uint32_t command_status;
    uint32_t sequence_number;
} smpp_header_t;

/* Bind Request */
typedef struct smpp_bind_req {
    char system_id[16];
    char password[16];
    char system_type[13];
    uint8_t interface_version;
    uint8_t addr_ton;
    uint8_t addr_npi;
    char address_range[41];
} smpp_bind_req_t;

/* Bind Response */
typedef struct smpp_bind_resp {
    char system_id[16];
    smpp_tlv_t *tlvs;
} smpp_bind_resp_t;

/* Submit SM / Deliver SM Body */
typedef struct smpp_msg {
    char service_type[6];
    uint8_t source_addr_ton;
    uint8_t source_addr_npi;
    char source_addr[SMPP_MAX_ADDR_LEN];
    uint8_t dest_addr_ton;
    uint8_t dest_addr_npi;
    char destination_addr[SMPP_MAX_ADDR_LEN];
    uint8_t esm_class;
    uint8_t protocol_id;
    uint8_t priority_flag;
    char schedule_delivery_time[17];
    char validity_period[17];
    uint8_t registered_delivery;
    uint8_t replace_if_present_flag;
    uint8_t data_coding;
    uint8_t sm_default_msg_id;
    uint8_t sm_length;
    uint8_t short_message[SMPP_MAX_SHORT_MSG_LEN];
    smpp_tlv_t *tlvs;
} smpp_msg_t;

/* Submit SM Resp / Deliver SM Resp */
typedef struct smpp_msg_resp {
    char message_id[65];
    smpp_tlv_t *tlvs;
} smpp_msg_resp_t;

/* Generic Container for Any Parsed PDU */
typedef struct smpp_pdu {
    smpp_header_t header;
    union {
        smpp_bind_req_t bind_req;
        smpp_bind_resp_t bind_resp;
        smpp_msg_t msg;
        smpp_msg_resp_t msg_resp;
    } body;
} smpp_pdu_t;

/* PDU Packing & Unpacking Prototypes */
int smpp_pdu_unpack_header(const uint8_t *buf, size_t len, smpp_header_t *hdr);
int smpp_pdu_pack_header(const smpp_header_t *hdr, uint8_t *buf, size_t len);

int smpp_pdu_unpack(const uint8_t *buf, size_t len, smpp_pdu_t *pdu);
int smpp_pdu_pack(const smpp_pdu_t *pdu, uint8_t *buf, size_t buf_len, size_t *out_len);

void smpp_pdu_free(smpp_pdu_t *pdu);

/* Helper Constructors */
void smpp_header_init(smpp_header_t *hdr, uint32_t cmd_id, uint32_t cmd_status, uint32_t seq);
int smpp_make_enquire_link(smpp_pdu_t *pdu, uint32_t seq);
int smpp_make_enquire_link_resp(smpp_pdu_t *pdu, uint32_t seq);
int smpp_make_generic_nack(smpp_pdu_t *pdu, uint32_t seq, uint32_t status);
int smpp_make_unbind(smpp_pdu_t *pdu, uint32_t seq);
int smpp_make_unbind_resp(smpp_pdu_t *pdu, uint32_t seq);

#endif /* _SMPP_PDU_H_ */
