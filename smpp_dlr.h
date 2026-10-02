/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Unified DLR Normalization Engine Header
*/

#ifndef _SMPP_DLR_H_
#define _SMPP_DLR_H_

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include "smpp_pdu.h"
#include "smpp_tlv.h"

/* Standard SMPP Message States */
#define SMPP_STATE_ENROUTE      1
#define SMPP_STATE_DELIVRD      2
#define SMPP_STATE_EXPIRED      3
#define SMPP_STATE_DELETED      4
#define SMPP_STATE_UNDELIV      5
#define SMPP_STATE_ACCEPTD      6
#define SMPP_STATE_UNKNOWN      7
#define SMPP_STATE_REJECTD      8

typedef struct smpp_dlr_info {
    char message_id[65];
    uint8_t message_state;      /* 1..8 */
    uint32_t network_error;     /* Extracted error code */
    char stat_str[16];          /* "DELIVRD", "UNDELIV", "REJECTD", etc. */
    char submit_date[16];       /* YYMMDDhhmm */
    char done_date[16];         /* YYMMDDhhmm */
    int was_tlv_only;           /* 1 if recovered from vendor/SMPP TLVs */
} smpp_dlr_info_t;

/* Parse & normalize incoming DLR from body string OR TLVs (0x001E, 0x0427, 0x0423) */
int smpp_dlr_normalize(const smpp_msg_t *msg, smpp_dlr_info_t *out_dlr);

/* Reconstruct standard SMPP Appendix B format into short_message buffer if empty */
int smpp_dlr_reconstruct_body(const smpp_dlr_info_t *dlr, char *out_buf, size_t max_out);

#endif /* _SMPP_DLR_H_ */
