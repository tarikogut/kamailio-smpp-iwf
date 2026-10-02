/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Unified DLR Normalization Engine Implementation
*/

#include "smpp_dlr.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void map_state_to_str(uint8_t state, char *out_str)
{
    switch (state) {
    case SMPP_STATE_ENROUTE: strcpy(out_str, "ENROUTE"); break;
    case SMPP_STATE_DELIVRD: strcpy(out_str, "DELIVRD"); break;
    case SMPP_STATE_EXPIRED: strcpy(out_str, "EXPIRED"); break;
    case SMPP_STATE_DELETED: strcpy(out_str, "DELETED"); break;
    case SMPP_STATE_UNDELIV: strcpy(out_str, "UNDELIV"); break;
    case SMPP_STATE_ACCEPTD: strcpy(out_str, "ACCEPTD"); break;
    case SMPP_STATE_REJECTD: strcpy(out_str, "REJECTD"); break;
    default: strcpy(out_str, "UNKNOWN"); break;
    }
}

int smpp_dlr_normalize(const smpp_msg_t *msg, smpp_dlr_info_t *out_dlr)
{
    if (!msg || !out_dlr) return -1;
    memset(out_dlr, 0, sizeof(*out_dlr));

    /* 1. Try parsing from short_message text */
    if (msg->sm_length > 0) {
        char text[512];
        size_t l = msg->sm_length;
        if (l > sizeof(text) - 1) l = sizeof(text) - 1;
        memcpy(text, msg->short_message, l);
        text[l] = '\0';

        char *id_p = strstr(text, "id:");
        char *stat_p = strstr(text, "stat:");
        char *err_p = strstr(text, "err:");
        char *sub_p = strstr(text, "submit date:");
        char *done_p = strstr(text, "done date:");

        if (id_p && stat_p) {
            sscanf(id_p, "id:%64s", out_dlr->message_id);
            sscanf(stat_p, "stat:%15s", out_dlr->stat_str);
            if (err_p) {
                unsigned int e = 0;
                sscanf(err_p, "err:%u", &e);
                out_dlr->network_error = e;
            }
            if (sub_p) sscanf(sub_p, "submit date:%15s", out_dlr->submit_date);
            if (done_p) sscanf(done_p, "done date:%15s", out_dlr->done_date);

            out_dlr->was_tlv_only = 0;
            return 0;
        }
    }

    /* 2. Fallback: Parse from SMPP / Vendor TLVs */
    smpp_tlv_t *tlv = msg->tlvs;
    int found_id = 0;
    int found_state = 0;

    while (tlv) {
        /* TLV 0x001E: receipted_message_id */
        if (tlv->tag == 0x001E && tlv->length > 0) {
            size_t l = tlv->length < 64 ? tlv->length : 64;
            memcpy(out_dlr->message_id, tlv->value, l);
            out_dlr->message_id[l] = '\0';
            found_id = 1;
        }
        /* TLV 0x0427: message_state */
        else if (tlv->tag == 0x0427 && tlv->length >= 1) {
            out_dlr->message_state = tlv->value[0];
            map_state_to_str(out_dlr->message_state, out_dlr->stat_str);
            found_state = 1;
        }
        /* TLV 0x0423: network_error_code (3 octets: 1 byte type, 2 bytes code) */
        else if (tlv->tag == 0x0423 && tlv->length >= 3) {
            out_dlr->network_error = (tlv->value[1] << 8) | tlv->value[2];
        }
        tlv = tlv->next;
    }

    if (found_id || found_state) {
        out_dlr->was_tlv_only = 1;
        if (!out_dlr->stat_str[0]) strcpy(out_dlr->stat_str, "DELIVRD");

        time_t now = time(NULL);
        struct tm tm_buf;
        gmtime_r(&now, &tm_buf);
        strftime(out_dlr->submit_date, sizeof(out_dlr->submit_date), "%y%m%d%H%M", &tm_buf);
        strftime(out_dlr->done_date, sizeof(out_dlr->done_date), "%y%m%d%H%M", &tm_buf);
        return 0;
    }

    return -1;
}

int smpp_dlr_reconstruct_body(const smpp_dlr_info_t *dlr, char *out_buf, size_t max_out)
{
    if (!dlr || !out_buf || max_out < 80) return -1;

    return snprintf(out_buf, max_out,
        "id:%s sub:001 dlvrd:001 submit date:%s done date:%s stat:%s err:%03u text:",
        dlr->message_id,
        dlr->submit_date[0] ? dlr->submit_date : "2610020645",
        dlr->done_date[0] ? dlr->done_date : "2610020645",
        dlr->stat_str,
        dlr->network_error);
}
