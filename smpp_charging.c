/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Extensible Charging & Credit Control Subsystem Implementation
*/

#include "smpp_charging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static pthread_mutex_t charging_mutex = PTHREAD_MUTEX_INITIALIZER;
static smpp_account_balance_t *balance_head = NULL;
static smpp_charging_mode_t current_mode = SMPP_CHARGING_MODE_LOCAL;
static smpp_diameter_hook_t diameter_hook = NULL;
static uint32_t global_session_seq = 1000;

/* Helper: Find account balance record (internal, assumes mutex locked) */
static smpp_account_balance_t *find_account_locked(const char *account_id)
{
    if (!account_id || !*account_id) return NULL;
    smpp_account_balance_t *curr = balance_head;
    while (curr) {
        if (strcmp(curr->account_id, account_id) == 0) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

int smpp_charging_init(void)
{
    pthread_mutex_lock(&charging_mutex);
    /* Clean up existing list if any */
    smpp_account_balance_t *curr = balance_head;
    while (curr) {
        smpp_account_balance_t *tmp = curr->next;
        free(curr);
        curr = tmp;
    }
    balance_head = NULL;
    current_mode = SMPP_CHARGING_MODE_LOCAL;
    diameter_hook = NULL;

    /* Pre-seed default system accounts with initial credit */
    const char *default_accs[] = {"kamailio_client", "test_esme", "api_user", "default"};
    double default_balances[]  = {1000.0, 500.0, 200.0, 100.0};

    for (int i = 0; i < 4; i++) {
        smpp_account_balance_t *rec = (smpp_account_balance_t *)malloc(sizeof(smpp_account_balance_t));
        if (rec) {
            memset(rec, 0, sizeof(*rec));
            strncpy(rec->account_id, default_accs[i], sizeof(rec->account_id) - 1);
            rec->balance = default_balances[i];
            rec->price_per_segment = 1.0;
            rec->last_updated = time(NULL);
            rec->next = balance_head;
            balance_head = rec;
        }
    }
    pthread_mutex_unlock(&charging_mutex);
    return 0;
}

void smpp_charging_destroy(void)
{
    pthread_mutex_lock(&charging_mutex);
    smpp_account_balance_t *curr = balance_head;
    while (curr) {
        smpp_account_balance_t *tmp = curr->next;
        free(curr);
        curr = tmp;
    }
    balance_head = NULL;
    diameter_hook = NULL;
    pthread_mutex_unlock(&charging_mutex);
}

int smpp_charging_set_mode(smpp_charging_mode_t mode)
{
    pthread_mutex_lock(&charging_mutex);
    current_mode = mode;
    pthread_mutex_unlock(&charging_mutex);
    return 0;
}

smpp_charging_mode_t smpp_charging_get_mode(void)
{
    pthread_mutex_lock(&charging_mutex);
    smpp_charging_mode_t mode = current_mode;
    pthread_mutex_unlock(&charging_mutex);
    return mode;
}

void smpp_charging_set_diameter_hook(smpp_diameter_hook_t hook)
{
    pthread_mutex_lock(&charging_mutex);
    diameter_hook = hook;
    pthread_mutex_unlock(&charging_mutex);
}

smpp_diameter_hook_t smpp_charging_get_diameter_hook(void)
{
    pthread_mutex_lock(&charging_mutex);
    smpp_diameter_hook_t hook = diameter_hook;
    pthread_mutex_unlock(&charging_mutex);
    return hook;
}

int smpp_charging_set_balance(const char *account_id, double balance)
{
    if (!account_id || !*account_id) return -1;
    pthread_mutex_lock(&charging_mutex);
    smpp_account_balance_t *rec = find_account_locked(account_id);
    if (!rec) {
        rec = (smpp_account_balance_t *)malloc(sizeof(smpp_account_balance_t));
        if (!rec) {
            pthread_mutex_unlock(&charging_mutex);
            return -2;
        }
        memset(rec, 0, sizeof(*rec));
        strncpy(rec->account_id, account_id, sizeof(rec->account_id) - 1);
        rec->price_per_segment = 1.0;
        rec->next = balance_head;
        balance_head = rec;
    }
    rec->balance = balance;
    rec->last_updated = time(NULL);
    pthread_mutex_unlock(&charging_mutex);
    return 0;
}

int smpp_charging_add_credit(const char *account_id, double add_amount, double *new_balance)
{
    if (!account_id || !*account_id) return -1;
    pthread_mutex_lock(&charging_mutex);
    smpp_account_balance_t *rec = find_account_locked(account_id);
    if (!rec) {
        rec = (smpp_account_balance_t *)malloc(sizeof(smpp_account_balance_t));
        if (!rec) {
            pthread_mutex_unlock(&charging_mutex);
            return -2;
        }
        memset(rec, 0, sizeof(*rec));
        strncpy(rec->account_id, account_id, sizeof(rec->account_id) - 1);
        rec->price_per_segment = 1.0;
        rec->balance = add_amount;
        rec->next = balance_head;
        balance_head = rec;
    } else {
        rec->balance += add_amount;
    }
    rec->last_updated = time(NULL);
    if (new_balance) *new_balance = rec->balance;
    pthread_mutex_unlock(&charging_mutex);
    return 0;
}

int smpp_charging_get_balance(const char *account_id, double *out_balance)
{
    if (!account_id || !*account_id || !out_balance) return -1;
    pthread_mutex_lock(&charging_mutex);
    smpp_account_balance_t *rec = find_account_locked(account_id);
    if (!rec) {
        pthread_mutex_unlock(&charging_mutex);
        return -2;
    }
    *out_balance = rec->balance;
    pthread_mutex_unlock(&charging_mutex);
    return 0;
}

int smpp_charging_set_price_per_segment(const char *account_id, double price)
{
    if (!account_id || !*account_id || price <= 0.0) return -1;
    pthread_mutex_lock(&charging_mutex);
    smpp_account_balance_t *rec = find_account_locked(account_id);
    if (!rec) {
        pthread_mutex_unlock(&charging_mutex);
        return -2;
    }
    rec->price_per_segment = price;
    pthread_mutex_unlock(&charging_mutex);
    return 0;
}

double smpp_charging_get_price_per_segment(const char *account_id)
{
    if (!account_id || !*account_id) return 1.0;
    pthread_mutex_lock(&charging_mutex);
    smpp_account_balance_t *rec = find_account_locked(account_id);
    double price = rec ? rec->price_per_segment : 1.0;
    pthread_mutex_unlock(&charging_mutex);
    return price;
}

int smpp_charging_account_exists(const char *account_id)
{
    if (!account_id || !*account_id) return 0;
    pthread_mutex_lock(&charging_mutex);
    smpp_account_balance_t *rec = find_account_locked(account_id);
    int exists = rec ? 1 : 0;
    pthread_mutex_unlock(&charging_mutex);
    return exists;
}

/* ========================================================================= */
/* Diameter Ro Protocol Engine (RFC 6733 / RFC 4006 / 3GPP TS 32.299)        */
/* ========================================================================= */

/* Append a 32-bit integer AVP */
static int avp_append_u32(uint8_t *buf, size_t max_len, size_t *offset, uint32_t avp_code, uint8_t flags, uint32_t val)
{
    size_t o = *offset;
    if (o + 12 > max_len) return -1;

    uint32_t n_code = htonl(avp_code);
    memcpy(buf + o, &n_code, 4);
    buf[o + 4] = flags;
    buf[o + 5] = 0;
    buf[o + 6] = 0;
    buf[o + 7] = 12; /* length */

    uint32_t n_val = htonl(val);
    memcpy(buf + o + 8, &n_val, 4);
    *offset = o + 12;
    return 0;
}

/* Append an OctetString / UTF8String AVP */
static int avp_append_str(uint8_t *buf, size_t max_len, size_t *offset, uint32_t avp_code, uint8_t flags, const char *str_val)
{
    size_t o = *offset;
    size_t str_len = strlen(str_val);
    size_t pad = (4 - (str_len % 4)) % 4;
    size_t total_avp_len = 8 + str_len;
    size_t aligned_len = 8 + str_len + pad;

    if (o + aligned_len > max_len) return -1;

    uint32_t n_code = htonl(avp_code);
    memcpy(buf + o, &n_code, 4);
    buf[o + 4] = flags;
    buf[o + 5] = (uint8_t)((total_avp_len >> 16) & 0xFF);
    buf[o + 6] = (uint8_t)((total_avp_len >> 8) & 0xFF);
    buf[o + 7] = (uint8_t)(total_avp_len & 0xFF);

    memcpy(buf + o + 8, str_val, str_len);
    if (pad > 0) {
        memset(buf + o + 8 + str_len, 0, pad);
    }
    *offset = o + aligned_len;
    return 0;
}

int smpp_diameter_pack_ccr(const smpp_diameter_ccr_t *ccr, uint8_t *out_buf, size_t max_out, size_t *out_len)
{
    if (!ccr || !out_buf || max_out < 128) return -1;

    /* Diameter Header: 20 bytes */
    size_t offset = 20;

    /* AVP 263: Session-Id */
    avp_append_str(out_buf, max_out, &offset, 263, 0x40, ccr->session_id);

    /* AVP 264: Origin-Host */
    const char *o_host = ccr->origin_host[0] ? ccr->origin_host : "kamailio-iwf.ims.mnc001.mcc286.3gppnetwork.org";
    avp_append_str(out_buf, max_out, &offset, 264, 0x40, o_host);

    /* AVP 296: Origin-Realm */
    const char *o_realm = ccr->origin_realm[0] ? ccr->origin_realm : "ims.mnc001.mcc286.3gppnetwork.org";
    avp_append_str(out_buf, max_out, &offset, 296, 0x40, o_realm);

    /* AVP 283: Destination-Realm */
    const char *d_realm = ccr->destination_realm[0] ? ccr->destination_realm : "ims.mnc001.mcc286.3gppnetwork.org";
    avp_append_str(out_buf, max_out, &offset, 283, 0x40, d_realm);

    /* AVP 258: Auth-Application-Id (4 = Diameter Credit Control) */
    avp_append_u32(out_buf, max_out, &offset, 258, 0x40, DIAMETER_APP_RO);

    /* AVP 461: Service-Context-Id */
    avp_append_str(out_buf, max_out, &offset, 461, 0x40, "sms@3gpp.org");

    /* AVP 416: CC-Request-Type (4 = EVENT_RECORD) */
    avp_append_u32(out_buf, max_out, &offset, 416, 0x40, ccr->request_type ? ccr->request_type : CC_REQUEST_TYPE_EVENT_RECORD);

    /* AVP 415: CC-Request-Number */
    avp_append_u32(out_buf, max_out, &offset, 415, 0x40, ccr->request_number);

    /* AVP 436: Requested-Action */
    avp_append_u32(out_buf, max_out, &offset, 436, 0x40, ccr->requested_action);

    /* AVP 443: Subscription-Id (Emulated grouped: we encode account/MSISDN in Subscription-Id-Data AVP 444) */
    const char *sub_id = ccr->src_msisdn[0] ? ccr->src_msisdn : ccr->account_id;
    avp_append_str(out_buf, max_out, &offset, 444, 0x40, sub_id);

    /* AVP 417: CC-Service-Specific-Units (Requested segments) */
    avp_append_u32(out_buf, max_out, &offset, 417, 0x40, ccr->requested_units > 0 ? ccr->requested_units : 1);

    /* Write 20-byte Diameter Header */
    out_buf[0] = 1; /* Version */
    out_buf[1] = (uint8_t)((offset >> 16) & 0xFF);
    out_buf[2] = (uint8_t)((offset >> 8) & 0xFF);
    out_buf[3] = (uint8_t)(offset & 0xFF);

    out_buf[4] = DIAMETER_FLAG_REQUEST | DIAMETER_FLAG_PROXIABLE; /* 0xC0 */
    out_buf[5] = 0;
    out_buf[6] = 1;
    out_buf[7] = 16; /* Command-Code 272 */

    uint32_t n_app = htonl(DIAMETER_APP_RO);
    memcpy(out_buf + 8, &n_app, 4);

    uint32_t n_hbh = htonl(ccr->hop_by_hop ? ccr->hop_by_hop : 0x12345678);
    memcpy(out_buf + 12, &n_hbh, 4);

    uint32_t n_ete = htonl(ccr->end_to_end ? ccr->end_to_end : 0x87654321);
    memcpy(out_buf + 16, &n_ete, 4);

    if (out_len) *out_len = offset;
    return 0;
}

int smpp_diameter_unpack_ccr(const uint8_t *buf, size_t len, smpp_diameter_ccr_t *ccr)
{
    if (!buf || len < 20 || !ccr) return -1;
    memset(ccr, 0, sizeof(*ccr));

    uint32_t msg_len = ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | buf[3];
    if (len < msg_len || msg_len < 20) return -2;

    uint32_t cmd_code = ((uint32_t)buf[5] << 16) | ((uint32_t)buf[6] << 8) | buf[7];
    if (cmd_code != DIAMETER_CMD_CC) return -3;

    memcpy(&ccr->hop_by_hop, buf + 12, 4);
    ccr->hop_by_hop = ntohl(ccr->hop_by_hop);
    memcpy(&ccr->end_to_end, buf + 16, 4);
    ccr->end_to_end = ntohl(ccr->end_to_end);

    size_t offset = 20;
    while (offset + 8 <= msg_len) {
        uint32_t code = ntohl(*(uint32_t *)(buf + offset));
        uint32_t avp_len = ((uint32_t)buf[offset + 5] << 16) | ((uint32_t)buf[offset + 6] << 8) | buf[offset + 7];
        if (avp_len < 8 || offset + avp_len > msg_len) break;

        size_t data_len = avp_len - 8;
        const uint8_t *data = buf + offset + 8;

        if (code == 263 && data_len < sizeof(ccr->session_id)) {
            memcpy(ccr->session_id, data, data_len);
            ccr->session_id[data_len] = '\0';
        } else if (code == 264 && data_len < sizeof(ccr->origin_host)) {
            memcpy(ccr->origin_host, data, data_len);
            ccr->origin_host[data_len] = '\0';
        } else if (code == 416 && data_len >= 4) {
            ccr->request_type = ntohl(*(uint32_t *)data);
        } else if (code == 415 && data_len >= 4) {
            ccr->request_number = ntohl(*(uint32_t *)data);
        } else if (code == 436 && data_len >= 4) {
            ccr->requested_action = ntohl(*(uint32_t *)data);
        } else if (code == 444 && data_len < sizeof(ccr->account_id)) {
            memcpy(ccr->account_id, data, data_len);
            ccr->account_id[data_len] = '\0';
        } else if (code == 417 && data_len >= 4) {
            ccr->requested_units = ntohl(*(uint32_t *)data);
        }

        size_t pad = (4 - (avp_len % 4)) % 4;
        offset += avp_len + pad;
    }
    return 0;
}

int smpp_diameter_pack_cca(const smpp_diameter_cca_t *cca, uint8_t *out_buf, size_t max_out, size_t *out_len)
{
    if (!cca || !out_buf || max_out < 96) return -1;

    size_t offset = 20;

    /* AVP 263: Session-Id */
    avp_append_str(out_buf, max_out, &offset, 263, 0x40, cca->session_id);

    /* AVP 268: Result-Code (2001 or 4012) */
    avp_append_u32(out_buf, max_out, &offset, 268, 0x40, cca->result_code);

    /* AVP 416: CC-Request-Type */
    avp_append_u32(out_buf, max_out, &offset, 416, 0x40, cca->request_type ? cca->request_type : CC_REQUEST_TYPE_EVENT_RECORD);

    /* AVP 415: CC-Request-Number */
    avp_append_u32(out_buf, max_out, &offset, 415, 0x40, cca->request_number);

    /* AVP 417: Granted-Units */
    avp_append_u32(out_buf, max_out, &offset, 417, 0x40, cca->granted_units);

    /* Write 20-byte Diameter Answer Header (R-bit = 0) */
    out_buf[0] = 1;
    out_buf[1] = (uint8_t)((offset >> 16) & 0xFF);
    out_buf[2] = (uint8_t)((offset >> 8) & 0xFF);
    out_buf[3] = (uint8_t)(offset & 0xFF);

    out_buf[4] = DIAMETER_FLAG_PROXIABLE; /* Request bit 0 */
    out_buf[5] = 0;
    out_buf[6] = 1;
    out_buf[7] = 16; /* Command-Code 272 */

    uint32_t n_app = htonl(DIAMETER_APP_RO);
    memcpy(out_buf + 8, &n_app, 4);

    uint32_t n_hbh = htonl(cca->hop_by_hop ? cca->hop_by_hop : 0x12345678);
    memcpy(out_buf + 12, &n_hbh, 4);

    uint32_t n_ete = htonl(cca->end_to_end ? cca->end_to_end : 0x87654321);
    memcpy(out_buf + 16, &n_ete, 4);

    if (out_len) *out_len = offset;
    return 0;
}

int smpp_diameter_unpack_cca(const uint8_t *buf, size_t len, smpp_diameter_cca_t *cca)
{
    if (!buf || len < 20 || !cca) return -1;
    memset(cca, 0, sizeof(*cca));

    uint32_t msg_len = ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | buf[3];
    if (len < msg_len || msg_len < 20) return -2;

    memcpy(&cca->hop_by_hop, buf + 12, 4);
    cca->hop_by_hop = ntohl(cca->hop_by_hop);
    memcpy(&cca->end_to_end, buf + 16, 4);
    cca->end_to_end = ntohl(cca->end_to_end);

    size_t offset = 20;
    while (offset + 8 <= msg_len) {
        uint32_t code = ntohl(*(uint32_t *)(buf + offset));
        uint32_t avp_len = ((uint32_t)buf[offset + 5] << 16) | ((uint32_t)buf[offset + 6] << 8) | buf[offset + 7];
        if (avp_len < 8 || offset + avp_len > msg_len) break;

        size_t data_len = avp_len - 8;
        const uint8_t *data = buf + offset + 8;

        if (code == 263 && data_len < sizeof(cca->session_id)) {
            memcpy(cca->session_id, data, data_len);
            cca->session_id[data_len] = '\0';
        } else if (code == 268 && data_len >= 4) {
            cca->result_code = ntohl(*(uint32_t *)data);
        } else if (code == 416 && data_len >= 4) {
            cca->request_type = ntohl(*(uint32_t *)data);
        } else if (code == 415 && data_len >= 4) {
            cca->request_number = ntohl(*(uint32_t *)data);
        } else if (code == 417 && data_len >= 4) {
            cca->granted_units = ntohl(*(uint32_t *)data);
        }

        size_t pad = (4 - (avp_len % 4)) % 4;
        offset += avp_len + pad;
    }
    return 0;
}

/* Internal Ro Emulation engine when no live OCS hook is attached */
static int diameter_ro_emulate(const uint8_t *req, size_t req_len, uint8_t *resp, size_t max_resp, size_t *resp_len)
{
    smpp_diameter_ccr_t ccr;
    if (smpp_diameter_unpack_ccr(req, req_len, &ccr) != 0) {
        return -1;
    }

    smpp_diameter_cca_t cca;
    memset(&cca, 0, sizeof(cca));
    strncpy(cca.session_id, ccr.session_id, sizeof(cca.session_id) - 1);
    cca.request_type = ccr.request_type;
    cca.request_number = ccr.request_number;
    cca.hop_by_hop = ccr.hop_by_hop;
    cca.end_to_end = ccr.end_to_end;

    /* Check against local balance store */
    pthread_mutex_lock(&charging_mutex);
    smpp_account_balance_t *acc = find_account_locked(ccr.account_id);
    if (!acc && ccr.src_msisdn[0]) {
        acc = find_account_locked(ccr.src_msisdn);
    }

    double req_units = ccr.requested_units > 0 ? ccr.requested_units : 1;
    double price = acc ? acc->price_per_segment : 1.0;
    double cost = req_units * price;

    if (acc && acc->balance >= cost) {
        cca.result_code = DIAMETER_SUCCESS; /* 2001 */
        cca.granted_units = (uint32_t)req_units;
        if (ccr.requested_action == REQUESTED_ACTION_DIRECT_DEBITING) {
            acc->balance -= cost;
            acc->total_spent += cost;
            acc->total_messages += 1;
            acc->last_updated = time(NULL);
        }
        cca.remaining_balance = acc->balance;
    } else {
        cca.result_code = DIAMETER_CREDIT_LIMIT_REACHED; /* 4012 */
        cca.granted_units = 0;
        cca.remaining_balance = acc ? acc->balance : 0.0;
    }
    pthread_mutex_unlock(&charging_mutex);

    return smpp_diameter_pack_cca(&cca, resp, max_resp, resp_len);
}

/* ========================================================================= */
/* Core Check & Deduct Functions                                             */
/* ========================================================================= */

int smpp_charging_check_credit(const char *account_id, const char *src, const char *dst,
                               int segments, uint32_t *remaining_credit)
{
    /* Auto-initialize if not yet initialized */
    if (!balance_head) {
        smpp_charging_init();
    }

    int segs = segments > 0 ? segments : 1;

    /* Handle Local Mode */
    if (current_mode == SMPP_CHARGING_MODE_LOCAL) {
        pthread_mutex_lock(&charging_mutex);
        smpp_account_balance_t *acc = find_account_locked(account_id);
        if (!acc && src && *src) {
            acc = find_account_locked(src);
        }

        if (!acc) {
            /* If account unknown, look for "default" */
            acc = find_account_locked("default");
        }

        if (!acc) {
            if (remaining_credit) *remaining_credit = 0;
            pthread_mutex_unlock(&charging_mutex);
            return -1;
        }

        double cost = segs * acc->price_per_segment;
        if (remaining_credit) {
            *remaining_credit = (acc->balance >= 0) ? (uint32_t)acc->balance : 0;
        }

        if (acc->balance >= cost) {
            pthread_mutex_unlock(&charging_mutex);
            return 0; /* SUFFICIENT CREDIT */
        }

        pthread_mutex_unlock(&charging_mutex);
        return -1; /* INSUFFICIENT CREDIT */
    }

    /* Handle Diameter Ro Mode */
    smpp_diameter_ccr_t ccr;
    memset(&ccr, 0, sizeof(ccr));

    pthread_mutex_lock(&charging_mutex);
    uint32_t s_seq = global_session_seq++;
    pthread_mutex_unlock(&charging_mutex);

    snprintf(ccr.session_id, sizeof(ccr.session_id), "kamailio-ro;%lu;%u", (unsigned long)time(NULL), s_seq);
    if (account_id) strncpy(ccr.account_id, account_id, sizeof(ccr.account_id) - 1);
    if (src) strncpy(ccr.src_msisdn, src, sizeof(ccr.src_msisdn) - 1);
    if (dst) strncpy(ccr.dst_msisdn, dst, sizeof(ccr.dst_msisdn) - 1);
    ccr.request_type = CC_REQUEST_TYPE_EVENT_RECORD;
    ccr.request_number = 0;
    ccr.requested_action = REQUESTED_ACTION_CHECK_BALANCE;
    ccr.requested_units = (uint32_t)segs;

    uint8_t ccr_buf[512];
    size_t ccr_len = 0;
    if (smpp_diameter_pack_ccr(&ccr, ccr_buf, sizeof(ccr_buf), &ccr_len) != 0) {
        return -1;
    }

    uint8_t cca_buf[512];
    size_t cca_len = 0;
    int hook_rc = 0;

    if (diameter_hook) {
        hook_rc = diameter_hook(ccr_buf, ccr_len, cca_buf, sizeof(cca_buf), &cca_len);
    } else {
        hook_rc = diameter_ro_emulate(ccr_buf, ccr_len, cca_buf, sizeof(cca_buf), &cca_len);
    }

    if (hook_rc != 0) return -2;

    smpp_diameter_cca_t cca;
    if (smpp_diameter_unpack_cca(cca_buf, cca_len, &cca) != 0) {
        return -3;
    }

    if (remaining_credit) {
        *remaining_credit = (uint32_t)cca.remaining_balance;
    }

    return (cca.result_code == DIAMETER_SUCCESS) ? 0 : -1;
}

int smpp_charging_deduct_credit(const char *account_id, const char *src, const char *dst,
                                int segments, double cost)
{
    /* Auto-initialize if not yet initialized */
    if (!balance_head) {
        smpp_charging_init();
    }

    int segs = segments > 0 ? segments : 1;

    /* Handle Local Mode */
    if (current_mode == SMPP_CHARGING_MODE_LOCAL) {
        pthread_mutex_lock(&charging_mutex);
        smpp_account_balance_t *acc = find_account_locked(account_id);
        if (!acc && src && *src) {
            acc = find_account_locked(src);
        }
        if (!acc) {
            acc = find_account_locked("default");
        }

        if (!acc) {
            pthread_mutex_unlock(&charging_mutex);
            return -1;
        }

        double deduct_amount = (cost > 0.0) ? cost : (segs * acc->price_per_segment);
        if (acc->balance >= deduct_amount) {
            acc->balance -= deduct_amount;
            acc->total_spent += deduct_amount;
            acc->total_messages += 1;
            acc->last_updated = time(NULL);
            pthread_mutex_unlock(&charging_mutex);
            return 0;
        }

        pthread_mutex_unlock(&charging_mutex);
        return -1;
    }

    /* Handle Diameter Ro Mode */
    smpp_diameter_ccr_t ccr;
    memset(&ccr, 0, sizeof(ccr));

    pthread_mutex_lock(&charging_mutex);
    uint32_t s_seq = global_session_seq++;
    pthread_mutex_unlock(&charging_mutex);

    snprintf(ccr.session_id, sizeof(ccr.session_id), "kamailio-ro;%lu;%u", (unsigned long)time(NULL), s_seq);
    if (account_id) strncpy(ccr.account_id, account_id, sizeof(ccr.account_id) - 1);
    if (src) strncpy(ccr.src_msisdn, src, sizeof(ccr.src_msisdn) - 1);
    if (dst) strncpy(ccr.dst_msisdn, dst, sizeof(ccr.dst_msisdn) - 1);
    ccr.request_type = CC_REQUEST_TYPE_EVENT_RECORD;
    ccr.request_number = 1;
    ccr.requested_action = REQUESTED_ACTION_DIRECT_DEBITING;
    ccr.requested_units = (uint32_t)segs;

    uint8_t ccr_buf[512];
    size_t ccr_len = 0;
    if (smpp_diameter_pack_ccr(&ccr, ccr_buf, sizeof(ccr_buf), &ccr_len) != 0) {
        return -1;
    }

    uint8_t cca_buf[512];
    size_t cca_len = 0;
    int hook_rc = 0;

    if (diameter_hook) {
        hook_rc = diameter_hook(ccr_buf, ccr_len, cca_buf, sizeof(cca_buf), &cca_len);
    } else {
        hook_rc = diameter_ro_emulate(ccr_buf, ccr_len, cca_buf, sizeof(cca_buf), &cca_len);
    }

    if (hook_rc != 0) return -2;

    smpp_diameter_cca_t cca;
    if (smpp_diameter_unpack_cca(cca_buf, cca_len, &cca) != 0) {
        return -3;
    }

    return (cca.result_code == DIAMETER_SUCCESS) ? 0 : -1;
}
