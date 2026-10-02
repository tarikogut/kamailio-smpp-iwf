/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Multi-Protocol Interworking & IMS IP-SM-GW Implementation
*/

#include "smpp_interwork.h"
#include "smpp_manip.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


/* Convert SMPP msg struct into HTTP JSON Webhook payload */
int smpp_to_http_json(const smpp_msg_t *msg, const char *msg_id, const char *b_code,
                      char *out_json, size_t max_out)
{
    if (!msg || !out_json || max_out < 64) return -1;

    char safe_text[512];
    size_t len = msg->sm_length < 255 ? msg->sm_length : 255;
    memcpy(safe_text, msg->short_message, len);
    safe_text[len] = '\0';

    /* Escape quotes in text */
    char escaped[1024];
    size_t e_idx = 0;
    for (size_t i = 0; safe_text[i] != '\0' && e_idx < sizeof(escaped) - 2; i++) {
        if (safe_text[i] == '"' || safe_text[i] == '\\') {
            escaped[e_idx++] = '\\';
        }
        escaped[e_idx++] = safe_text[i];
    }
    escaped[e_idx] = '\0';

    int written = snprintf(out_json, max_out,
        "{\"message_id\":\"%s\",\"from\":\"%s\",\"to\":\"%s\",\"text\":\"%s\","
        "\"coding\":%d,\"b_code\":\"%s\",\"esm_class\":%d}",
        msg_id ? msg_id : "",
        msg->source_addr,
        msg->destination_addr,
        escaped,
        msg->data_coding,
        b_code ? b_code : "",
        msg->esm_class);

    return (written > 0 && (size_t)written < max_out) ? 0 : -2;
}

/* Parse key value from simple JSON */
static int json_extract_str(const char *json, const char *key, char *out, size_t max_out)
{
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char *pos = strstr(json, pattern);
    if (!pos) return -1;

    pos += strlen(pattern);
    while (*pos == ' ' || *pos == '\t') pos++;

    if (*pos != '"') return -2;
    pos++; /* Skip opening quote */

    size_t idx = 0;
    while (*pos && *pos != '"' && idx < max_out - 1) {
        if (*pos == '\\' && *(pos + 1)) pos++;
        out[idx++] = *pos++;
    }
    out[idx] = '\0';
    return 0;
}

int http_json_to_smpp(const char *in_json, smpp_msg_t *msg)
{
    if (!in_json || !msg) return -1;
    memset(msg, 0, sizeof(smpp_msg_t));

    json_extract_str(in_json, "from", msg->source_addr, sizeof(msg->source_addr));
    json_extract_str(in_json, "to", msg->destination_addr, sizeof(msg->destination_addr));

    char text[256];
    if (json_extract_str(in_json, "text", text, sizeof(text)) == 0) {
        msg->sm_length = (uint8_t)strlen(text);
        memcpy(msg->short_message, text, msg->sm_length);
    }

    smpp_detect_ton_npi(msg->source_addr, &msg->source_addr_ton, &msg->source_addr_npi);
    smpp_detect_ton_npi(msg->destination_addr, &msg->dest_addr_ton, &msg->dest_addr_npi);
    msg->data_coding = SMPP_ENCODING_DEFAULT;

    return 0;
}

int http_response_to_smpp_status(int http_code)
{
    if (http_code >= 200 && http_code < 300) return ESME_ROK;
    if (http_code == 429) return ESME_RTHROTTLED;
    if (http_code == 403 || http_code == 401) return ESME_RBINDFAIL;
    if (http_code == 404 || http_code == 400) return ESME_RINVDSTADR;
    return ESME_RSUBMITFAIL;
}

/* 3GPP TS 24.341 & TS 23.204 IP-SM-GW (RP-DATA parser) */
int smpp_ims_rp_data_unpack(const uint8_t *rp_buf, size_t rp_len,
                            char *src_msisdn, char *dst_msisdn,
                            char *text_utf8, size_t max_text, uint8_t *data_coding)
{
    if (!rp_buf || rp_len < 10 || !src_msisdn || !dst_msisdn || !text_utf8) return -1;

    /*
     * 3GPP RP-DATA layout:
     * Byte 0: RP-Message Type (0x00 = RP-DATA MO, 0x01 = RP-DATA MT)
     * Byte 1: RP-Message Reference
     * Byte 2: RP-Originator Address Length
     * ... Originator Address
     * ... RP-Destination Address Length
     * ... Destination Address
     * ... RP-User Data (TPDU - SMS SUBMIT/DELIVER)
     */
    size_t offset = 2;

    /* Read RP-Originator */
    uint8_t orig_len = rp_buf[offset++];
    if (offset + orig_len > rp_len) return -2;
    if (orig_len > 1) {
        /* BCD/E.164 translation placeholder */
        snprintf(src_msisdn, 32, "905321000000");
    } else {
        strcpy(src_msisdn, "UNKNOWN");
    }
    offset += orig_len;

    /* Read RP-Destination */
    if (offset >= rp_len) return -3;
    uint8_t dst_len = rp_buf[offset++];
    if (offset + dst_len > rp_len) return -4;
    if (dst_len > 1) {
        snprintf(dst_msisdn, 32, "905322000000");
    } else {
        strcpy(dst_msisdn, "UNKNOWN");
    }
    offset += dst_len;

    /* Read TPDU */
    if (offset + 1 >= rp_len) return -5;
    uint8_t tpdu_len = rp_buf[offset++];
    if (offset + tpdu_len > rp_len) return -6;

    if (data_coding) *data_coding = SMPP_ENCODING_DEFAULT;

    /* Extract user text from TPDU */
    size_t copy_len = (tpdu_len < max_text - 1) ? tpdu_len : max_text - 1;
    memcpy(text_utf8, rp_buf + offset, copy_len);
    text_utf8[copy_len] = '\0';

    return 0;
}

/* 3GPP TS 24.341 & TS 23.204 IP-SM-GW (RP-DATA builder) */
int smpp_ims_rp_data_pack(const char *src_msisdn, const char *dst_msisdn,
                          const char *text_utf8, uint8_t *out_rp_buf,
                          size_t max_out, size_t *out_len)
{
    if (!src_msisdn || !dst_msisdn || !text_utf8 || !out_rp_buf || max_out < 32) return -1;

    size_t text_len = strlen(text_utf8);
    size_t offset = 0;

    out_rp_buf[offset++] = RP_DATA_MT; /* 0x01 = MT */
    out_rp_buf[offset++] = 0x01;        /* RP-Message Reference */

    /* Originator Address (Dummy minimal BCD) */
    out_rp_buf[offset++] = 0x02;        /* Length */
    out_rp_buf[offset++] = 0x91;        /* Type: International */
    out_rp_buf[offset++] = 0x00;
    
    /* Destination Address */
    out_rp_buf[offset++] = 0x02;
    out_rp_buf[offset++] = 0x91;
    out_rp_buf[offset++] = 0x00;

    /* TP-User-Data Length & Body */
    if (offset + text_len + 1 > max_out) return -2;
    out_rp_buf[offset++] = (uint8_t)text_len;
    memcpy(out_rp_buf + offset, text_utf8, text_len);
    offset += text_len;

    if (out_len) *out_len = offset;
    return 0;
}

/* 3. SMPP -> SIP MO (Mobile Originated) Interworking (RFC 3428) */
static smpp_sip_dispatcher_cb_t g_sip_dispatcher = NULL;

void smpp_set_sip_dispatcher(smpp_sip_dispatcher_cb_t cb)
{
    g_sip_dispatcher = cb;
}

smpp_sip_dispatcher_cb_t smpp_get_sip_dispatcher(void)
{
    return g_sip_dispatcher;
}

int smpp_build_sip_message(const char *src_msisdn, const char *dst_msisdn,
                           const char *body, size_t body_len,
                           const char *domain,
                           char *out_sip, size_t max_out, size_t *out_len)
{
    if (!src_msisdn || !dst_msisdn || !body || !out_sip || max_out < 128) {
        return -1;
    }

    const char *dom = (domain && *domain) ? domain : "127.0.0.1";

    /* Strip leading sip: if present for username */
    const char *src_u = src_msisdn;
    if (strncmp(src_u, "sip:", 4) == 0) src_u += 4;
    const char *dst_u = dst_msisdn;
    if (strncmp(dst_u, "sip:", 4) == 0) dst_u += 4;

    /* If destination contains '@', parse user and host */
    char dst_clean[64] = {0};
    char dst_host[64] = {0};
    const char *at = strchr(dst_u, '@');
    if (at) {
        size_t ulen = (size_t)(at - dst_u);
        if (ulen >= sizeof(dst_clean)) ulen = sizeof(dst_clean) - 1;
        memcpy(dst_clean, dst_u, ulen);
        strncpy(dst_host, at + 1, sizeof(dst_host) - 1);
        dst_u = dst_clean;
        if (dst_host[0]) dom = dst_host;
    }

    /* Generate pseudo random tag and call-id based on timestamp and sequence */
    static uint32_t cseq_counter = 1;
    uint32_t cur_seq = cseq_counter++;
    time_t now = time(NULL);

    int written = snprintf(out_sip, max_out,
        "MESSAGE sip:%s@%s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK-smpp-%lx-%u;rport\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:%s@%s>;tag=smpp-%lx\r\n"
        "To: <sip:%s@%s>\r\n"
        "Call-ID: smpp-mo-%lx-%u@%s\r\n"
        "CSeq: %u MESSAGE\r\n"
        "User-Agent: Kamailio-SMPP-IWF/6.0.8\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%.*s",
        dst_u, dom,
        dom, (unsigned long)now, cur_seq,
        src_u, dom, (unsigned long)now,
        dst_u, dom,
        (unsigned long)now, cur_seq, dom,
        cur_seq,
        body_len,
        (int)body_len, body);

    if (written > 0 && (size_t)written < max_out) {
        if (out_len) *out_len = (size_t)written;
        return 0;
    }
    return -2;
}

int smpp_to_sip_message(const char *src_msisdn, const char *dst_msisdn, const char *body, size_t body_len)
{
    if (!src_msisdn || !dst_msisdn || !body) return -1;

    char sip_buf[2048];
    size_t sip_len = 0;
    int rc = smpp_build_sip_message(src_msisdn, dst_msisdn, body, body_len, "127.0.0.1", sip_buf, sizeof(sip_buf), &sip_len);
    if (rc != 0) return rc;

    if (g_sip_dispatcher) {
        return g_sip_dispatcher(src_msisdn, dst_msisdn, body, body_len, sip_buf, sip_len);
    }

    return 0;
}

