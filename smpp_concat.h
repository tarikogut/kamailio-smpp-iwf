/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Multipart / Concatenated SMS (UDH & SAR) Engine Header
# Compliant with 3GPP TS 23.040 & SMPP v3.4 / v5.0 Specifications
*/

#ifndef _SMPP_CONCAT_H_
#define _SMPP_CONCAT_H_

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include "smpp_pdu.h"
#include "smpp_tlv.h"

#define SMPP_CONCAT_MAX_PARTS           256
#define SMPP_CONCAT_DEFAULT_TTL_SEC     60
#define SMPP_CONCAT_UDH_LEN             6
#define SMPP_CONCAT_GSM_MAX_SINGLE      160
#define SMPP_CONCAT_GSM_MAX_CONCAT      153
#define SMPP_CONCAT_UCS2_MAX_SINGLE     140 /* 70 UCS-2 chars * 2 */
#define SMPP_CONCAT_UCS2_MAX_CONCAT     134 /* 67 UCS-2 chars * 2 */
#define SMPP_CONCAT_SAR_MAX_CHUNK       254

/* Reassembly Fragment */
typedef struct smpp_reassembly_part {
    uint8_t *data;
    size_t len;
    int received;
} smpp_reassembly_part_t;

/* Pending Multi-Part Message Entry */
typedef struct smpp_reassembly_entry {
    uint16_t ref_num;
    uint8_t total_parts;
    uint8_t received_count;
    time_t created_at;
    time_t last_updated;
    smpp_reassembly_part_t parts[SMPP_CONCAT_MAX_PARTS];
    struct smpp_reassembly_entry *next;
} smpp_reassembly_entry_t;

/* Reassembly Context */
typedef struct smpp_reassembly_ctx {
    int ttl_seconds;
    smpp_reassembly_entry_t *entries;
    pthread_mutex_t lock;
} smpp_reassembly_ctx_t;

/* Segmentation API */
int smpp_split_message(const uint8_t *full_msg, size_t full_len, uint8_t data_coding,
                       int use_udh, uint16_t ref_num, smpp_msg_t segments[], size_t max_segments);

void smpp_free_segments(smpp_msg_t segments[], size_t count);

/* Reassembly Context API */
smpp_reassembly_ctx_t *smpp_reassembly_ctx_create(int ttl_seconds);
void smpp_reassembly_ctx_destroy(smpp_reassembly_ctx_t *ctx);
void smpp_reassembly_ctx_cleanup(smpp_reassembly_ctx_t *ctx);
int smpp_reassembly_ctx_add_part(smpp_reassembly_ctx_t *ctx, uint16_t ref_num, uint8_t total, uint8_t seq,
                                const uint8_t *part, size_t part_len,
                                uint8_t *assembled_out, size_t max_out, size_t *assembled_len);

/* Global Reassembly Singleton */
int smpp_reassembly_init(int ttl_seconds);
void smpp_reassembly_destroy(void);
int smpp_reassembly_add_part(uint16_t ref_num, uint8_t total, uint8_t seq,
                             const uint8_t *part, size_t part_len,
                             uint8_t *assembled_out, size_t max_out, size_t *assembled_len);

/* Detection & PDU Reassembly Helpers */
int smpp_msg_is_concat(const smpp_msg_t *msg);
int smpp_msg_get_concat_info(const smpp_msg_t *msg, uint16_t *out_ref, uint8_t *out_total,
                             uint8_t *out_seq, const uint8_t **out_payload, size_t *out_payload_len);
int smpp_reassemble_msg(const smpp_msg_t *msg, uint8_t *assembled_out, size_t max_out, size_t *assembled_len);

#endif /* _SMPP_CONCAT_H_ */
