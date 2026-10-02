/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Multipart / Concatenated SMS (UDH & SAR) Engine
# Compliant with 3GPP TS 23.040 & SMPP v3.4 / v5.0 Specifications
*/

#include "smpp_concat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static smpp_reassembly_ctx_t *global_reasm_ctx = NULL;

/* -------------------------------------------------------------------------
 * Segmentation Engine
 * ------------------------------------------------------------------------- */

int smpp_split_message(const uint8_t *full_msg, size_t full_len, uint8_t data_coding,
                       int use_udh, uint16_t ref_num, smpp_msg_t segments[], size_t max_segments)
{
    if (!full_msg || !segments || max_segments == 0) return -1;
    if (full_len == 0) return 0;

    /* Check single message thresholds: 70 UCS-2 characters (140 bytes) or 160 GSM characters */
    size_t single_threshold = (data_coding == SMPP_ENCODING_UCS2) ? SMPP_CONCAT_UCS2_MAX_SINGLE : SMPP_CONCAT_GSM_MAX_SINGLE;

    if (full_len <= single_threshold) {
        /* Single segment message - no concatenation needed */
        memset(&segments[0], 0, sizeof(smpp_msg_t));
        segments[0].data_coding = data_coding;
        segments[0].esm_class = 0;
        segments[0].sm_length = (uint8_t)full_len;
        memcpy(segments[0].short_message, full_msg, full_len);
        segments[0].tlvs = NULL;
        return 1;
    }

    if (use_udh) {
        /* 3GPP TS 23.040 6-byte UDH: 153 GSM chars or 67 UCS-2 chars (134 bytes) */
        size_t chunk_size = (data_coding == SMPP_ENCODING_UCS2) ? SMPP_CONCAT_UCS2_MAX_CONCAT : SMPP_CONCAT_GSM_MAX_CONCAT;
        size_t total_segments = (full_len + chunk_size - 1) / chunk_size;

        if (total_segments > max_segments) return -2; /* Insufficient output buffer */
        if (total_segments > 255) return -3;          /* 3GPP UDH supports up to 255 parts */

        uint8_t ref_8bit = (uint8_t)(ref_num & 0xFF);

        for (size_t i = 0; i < total_segments; i++) {
            size_t offset = i * chunk_size;
            size_t c_len = (full_len - offset < chunk_size) ? (full_len - offset) : chunk_size;

            memset(&segments[i], 0, sizeof(smpp_msg_t));
            segments[i].data_coding = data_coding;
            segments[i].esm_class = 0x40; /* User Data Header Indicator (UDHI) */
            segments[i].sm_length = (uint8_t)(SMPP_CONCAT_UDH_LEN + c_len);

            /* 6-Byte UDH: 0x05 0x00 0x03 [ref_8bit] [total] [seq] */
            segments[i].short_message[0] = 0x05; /* UDHL (UDH Length = 5 bytes) */
            segments[i].short_message[1] = 0x00; /* IEI: 8-bit reference concatenated SMS */
            segments[i].short_message[2] = 0x03; /* IEDL: 3 bytes payload */
            segments[i].short_message[3] = ref_8bit;
            segments[i].short_message[4] = (uint8_t)total_segments;
            segments[i].short_message[5] = (uint8_t)(i + 1); /* 1-based sequence */

            memcpy(&segments[i].short_message[SMPP_CONCAT_UDH_LEN], full_msg + offset, c_len);
            segments[i].tlvs = NULL;
        }

        return (int)total_segments;
    } else {
        /* SAR TLV Segmentation: sm_length up to 254 bytes per segment */
        size_t chunk_size = SMPP_CONCAT_SAR_MAX_CHUNK;
        size_t total_segments = (full_len + chunk_size - 1) / chunk_size;

        if (total_segments > max_segments) return -2;
        if (total_segments > 255) return -3;

        uint16_t net_ref = htons(ref_num);
        uint8_t tot_u8 = (uint8_t)total_segments;

        for (size_t i = 0; i < total_segments; i++) {
            size_t offset = i * chunk_size;
            size_t c_len = (full_len - offset < chunk_size) ? (full_len - offset) : chunk_size;

            memset(&segments[i], 0, sizeof(smpp_msg_t));
            segments[i].data_coding = data_coding;
            segments[i].esm_class = 0x00; /* No UDHI for SAR TLVs */
            segments[i].sm_length = (uint8_t)c_len;
            memcpy(segments[i].short_message, full_msg + offset, c_len);

            segments[i].tlvs = NULL;
            uint8_t seq_u8 = (uint8_t)(i + 1);

            smpp_tlv_add(&segments[i].tlvs, SMPP_TLV_SAR_MSG_REF_NUM, 2, (const uint8_t *)&net_ref);
            smpp_tlv_add(&segments[i].tlvs, SMPP_TLV_SAR_TOTAL_SEGMENTS, 1, &tot_u8);
            smpp_tlv_add(&segments[i].tlvs, SMPP_TLV_SAR_SEGMENT_SEQNUM, 1, &seq_u8);
        }

        return (int)total_segments;
    }
}

void smpp_free_segments(smpp_msg_t segments[], size_t count)
{
    if (!segments) return;
    for (size_t i = 0; i < count; i++) {
        if (segments[i].tlvs) {
            smpp_tlv_free_list(segments[i].tlvs);
            segments[i].tlvs = NULL;
        }
    }
}

/* -------------------------------------------------------------------------
 * In-Memory Segment Reassembly Engine
 * ------------------------------------------------------------------------- */

static void free_entry_parts(smpp_reassembly_entry_t *entry)
{
    if (!entry) return;
    for (int i = 0; i < SMPP_CONCAT_MAX_PARTS; i++) {
        if (entry->parts[i].data) {
            free(entry->parts[i].data);
            entry->parts[i].data = NULL;
        }
        entry->parts[i].len = 0;
        entry->parts[i].received = 0;
    }
}

smpp_reassembly_ctx_t *smpp_reassembly_ctx_create(int ttl_seconds)
{
    smpp_reassembly_ctx_t *ctx = (smpp_reassembly_ctx_t *)malloc(sizeof(smpp_reassembly_ctx_t));
    if (!ctx) return NULL;

    ctx->ttl_seconds = (ttl_seconds > 0) ? ttl_seconds : SMPP_CONCAT_DEFAULT_TTL_SEC;
    ctx->entries = NULL;
    pthread_mutex_init(&ctx->lock, NULL);
    return ctx;
}

void smpp_reassembly_ctx_destroy(smpp_reassembly_ctx_t *ctx)
{
    if (!ctx) return;
    pthread_mutex_lock(&ctx->lock);
    smpp_reassembly_entry_t *curr = ctx->entries;
    while (curr) {
        smpp_reassembly_entry_t *next = curr->next;
        free_entry_parts(curr);
        free(curr);
        curr = next;
    }
    ctx->entries = NULL;
    pthread_mutex_unlock(&ctx->lock);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}

void smpp_reassembly_ctx_cleanup(smpp_reassembly_ctx_t *ctx)
{
    if (!ctx) return;
    time_t now = time(NULL);

    pthread_mutex_lock(&ctx->lock);
    smpp_reassembly_entry_t **curr = &ctx->entries;
    while (*curr) {
        smpp_reassembly_entry_t *entry = *curr;
        if (now - entry->last_updated >= ctx->ttl_seconds) {
            *curr = entry->next;
            free_entry_parts(entry);
            free(entry);
        } else {
            curr = &entry->next;
        }
    }
    pthread_mutex_unlock(&ctx->lock);
}

int smpp_reassembly_ctx_add_part(smpp_reassembly_ctx_t *ctx, uint16_t ref_num, uint8_t total, uint8_t seq,
                                const uint8_t *part, size_t part_len,
                                uint8_t *assembled_out, size_t max_out, size_t *assembled_len)
{
    if (!ctx || total == 0 || seq == 0 || seq > total) return -1;
    if (part_len > 0 && !part) return -1;
    if (!assembled_out || !assembled_len) return -1;

    /* Single segment trivial completion */
    if (total == 1 && seq == 1) {
        if (part_len > max_out) return -2;
        if (part_len > 0) memcpy(assembled_out, part, part_len);
        *assembled_len = part_len;
        return 1;
    }

    pthread_mutex_lock(&ctx->lock);

    time_t now = time(NULL);

    /* Purge expired sessions */
    smpp_reassembly_entry_t **tracer = &ctx->entries;
    while (*tracer) {
        smpp_reassembly_entry_t *e = *tracer;
        if (now - e->last_updated >= ctx->ttl_seconds) {
            *tracer = e->next;
            free_entry_parts(e);
            free(e);
        } else {
            tracer = &e->next;
        }
    }

    /* Locate pending entry with matching reference and total parts */
    smpp_reassembly_entry_t *entry = ctx->entries;
    while (entry) {
        if (entry->ref_num == ref_num && entry->total_parts == total) {
            break;
        }
        entry = entry->next;
    }

    if (!entry) {
        entry = (smpp_reassembly_entry_t *)calloc(1, sizeof(smpp_reassembly_entry_t));
        if (!entry) {
            pthread_mutex_unlock(&ctx->lock);
            return -3; /* OOM */
        }
        entry->ref_num = ref_num;
        entry->total_parts = total;
        entry->created_at = now;
        entry->last_updated = now;
        entry->next = ctx->entries;
        ctx->entries = entry;
    }

    /* Record fragment if not already received */
    if (!entry->parts[seq].received) {
        if (part_len > 0) {
            entry->parts[seq].data = (uint8_t *)malloc(part_len);
            if (!entry->parts[seq].data) {
                pthread_mutex_unlock(&ctx->lock);
                return -3;
            }
            memcpy(entry->parts[seq].data, part, part_len);
        } else {
            entry->parts[seq].data = NULL;
        }
        entry->parts[seq].len = part_len;
        entry->parts[seq].received = 1;
        entry->received_count++;
    }
    entry->last_updated = now;

    /* Check if all fragments have arrived */
    if (entry->received_count < entry->total_parts) {
        pthread_mutex_unlock(&ctx->lock);
        return 0; /* Incomplete - awaiting more fragments */
    }

    /* All segments arrived - Reassemble */
    size_t full_len = 0;
    for (int i = 1; i <= (int)entry->total_parts; i++) {
        full_len += entry->parts[i].len;
    }

    if (full_len > max_out) {
        pthread_mutex_unlock(&ctx->lock);
        return -2; /* Output buffer too small */
    }

    size_t offset = 0;
    for (int i = 1; i <= (int)entry->total_parts; i++) {
        if (entry->parts[i].len > 0 && entry->parts[i].data) {
            memcpy(assembled_out + offset, entry->parts[i].data, entry->parts[i].len);
            offset += entry->parts[i].len;
        }
    }
    *assembled_len = full_len;

    /* Unlink entry from list and free memory */
    smpp_reassembly_entry_t **p = &ctx->entries;
    while (*p) {
        if (*p == entry) {
            *p = entry->next;
            break;
        }
        p = &(*p)->next;
    }

    free_entry_parts(entry);
    free(entry);

    pthread_mutex_unlock(&ctx->lock);
    return 1; /* Complete and fully assembled */
}

/* Global Reassembly Singleton */

int smpp_reassembly_init(int ttl_seconds)
{
    if (global_reasm_ctx) return 0;
    global_reasm_ctx = smpp_reassembly_ctx_create(ttl_seconds);
    return (global_reasm_ctx != NULL) ? 0 : -1;
}

void smpp_reassembly_destroy(void)
{
    if (global_reasm_ctx) {
        smpp_reassembly_ctx_destroy(global_reasm_ctx);
        global_reasm_ctx = NULL;
    }
}

int smpp_reassembly_add_part(uint16_t ref_num, uint8_t total, uint8_t seq,
                             const uint8_t *part, size_t part_len,
                             uint8_t *assembled_out, size_t max_out, size_t *assembled_len)
{
    if (!global_reasm_ctx) {
        if (smpp_reassembly_init(SMPP_CONCAT_DEFAULT_TTL_SEC) != 0) return -1;
    }
    return smpp_reassembly_ctx_add_part(global_reasm_ctx, ref_num, total, seq,
                                       part, part_len, assembled_out, max_out, assembled_len);
}

/* -------------------------------------------------------------------------
 * Detection & PDU Reassembly Helpers
 * ------------------------------------------------------------------------- */

int smpp_msg_is_concat(const smpp_msg_t *msg)
{
    if (!msg) return 0;

    /* 1. Check SAR TLVs */
    if (smpp_tlv_find(msg->tlvs, SMPP_TLV_SAR_TOTAL_SEGMENTS) &&
        smpp_tlv_find(msg->tlvs, SMPP_TLV_SAR_SEGMENT_SEQNUM)) {
        return 2; /* SAR TLV */
    }

    /* 2. Check UDH in short_message */
    if ((msg->esm_class & 0x40) && msg->sm_length >= SMPP_CONCAT_UDH_LEN) {
        uint8_t udhl = msg->short_message[0];
        if (udhl >= 5 && msg->sm_length > udhl) {
            size_t idx = 1;
            while (idx + 1 < (size_t)(1 + udhl)) {
                uint8_t iei = msg->short_message[idx];
                uint8_t iedl = msg->short_message[idx + 1];
                if (idx + 2 + iedl > (size_t)(1 + udhl)) break;
                if ((iei == 0x00 && iedl >= 3) || (iei == 0x08 && iedl >= 4)) {
                    return 1; /* UDH */
                }
                idx += 2 + iedl;
            }
        }
    }

    return 0;
}

int smpp_msg_get_concat_info(const smpp_msg_t *msg, uint16_t *out_ref, uint8_t *out_total,
                             uint8_t *out_seq, const uint8_t **out_payload, size_t *out_payload_len)
{
    if (!msg) return -1;

    /* 1. SAR TLVs */
    smpp_tlv_t *t_ref = smpp_tlv_find(msg->tlvs, SMPP_TLV_SAR_MSG_REF_NUM);
    smpp_tlv_t *t_tot = smpp_tlv_find(msg->tlvs, SMPP_TLV_SAR_TOTAL_SEGMENTS);
    smpp_tlv_t *t_seq = smpp_tlv_find(msg->tlvs, SMPP_TLV_SAR_SEGMENT_SEQNUM);

    if (t_tot && t_seq && t_tot->length >= 1 && t_seq->length >= 1) {
        if (out_ref) {
            if (t_ref && t_ref->length == 2) {
                *out_ref = ntohs(*(const uint16_t *)t_ref->value);
            } else if (t_ref && t_ref->length == 1) {
                *out_ref = t_ref->value[0];
            } else {
                *out_ref = 0;
            }
        }
        if (out_total) *out_total = t_tot->value[0];
        if (out_seq) *out_seq = t_seq->value[0];
        if (out_payload) *out_payload = msg->short_message;
        if (out_payload_len) *out_payload_len = msg->sm_length;
        return 2;
    }

    /* 2. UDH */
    if ((msg->esm_class & 0x40) && msg->sm_length >= SMPP_CONCAT_UDH_LEN) {
        uint8_t udhl = msg->short_message[0];
        if (udhl >= 5 && msg->sm_length > udhl) {
            size_t idx = 1;
            while (idx + 1 < (size_t)(1 + udhl)) {
                uint8_t iei = msg->short_message[idx];
                uint8_t iedl = msg->short_message[idx + 1];
                if (idx + 2 + iedl > (size_t)(1 + udhl)) break;
                if (iei == 0x00 && iedl >= 3) {
                    if (out_ref) *out_ref = msg->short_message[idx + 2];
                    if (out_total) *out_total = msg->short_message[idx + 3];
                    if (out_seq) *out_seq = msg->short_message[idx + 4];
                    if (out_payload) *out_payload = msg->short_message + 1 + udhl;
                    if (out_payload_len) *out_payload_len = msg->sm_length - (1 + udhl);
                    return 1;
                } else if (iei == 0x08 && iedl >= 4) {
                    if (out_ref) *out_ref = ((uint16_t)msg->short_message[idx + 2] << 8) | msg->short_message[idx + 3];
                    if (out_total) *out_total = msg->short_message[idx + 4];
                    if (out_seq) *out_seq = msg->short_message[idx + 5];
                    if (out_payload) *out_payload = msg->short_message + 1 + udhl;
                    if (out_payload_len) *out_payload_len = msg->sm_length - (1 + udhl);
                    return 1;
                }
                idx += 2 + iedl;
            }
        }
    }

    return 0;
}

int smpp_reassemble_msg(const smpp_msg_t *msg, uint8_t *assembled_out, size_t max_out, size_t *assembled_len)
{
    if (!msg || !assembled_out || !assembled_len) return -1;

    uint16_t ref = 0;
    uint8_t total = 0, seq = 0;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;

    int type = smpp_msg_get_concat_info(msg, &ref, &total, &seq, &payload, &payload_len);
    if (type <= 0) {
        /* Not a fragmented message - output as is */
        if (msg->sm_length > max_out) return -2;
        if (msg->sm_length > 0) {
            memcpy(assembled_out, msg->short_message, msg->sm_length);
        }
        *assembled_len = msg->sm_length;
        return 1;
    }

    return smpp_reassembly_add_part(ref, total, seq, payload, payload_len,
                                    assembled_out, max_out, assembled_len);
}
