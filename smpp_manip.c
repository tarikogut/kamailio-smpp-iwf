/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - PDU Manipulation Implementation
*/

#include "smpp_manip.h"
#include "smpp_pdu.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static smpp_blacklist_rule_t *blacklist_head = NULL;

int smpp_calc_segments(size_t char_count, uint8_t data_coding, int has_udh)
{
    if (char_count == 0) return 0;

    int max_single;
    int max_concat;

    if (data_coding == SMPP_ENCODING_UCS2) {
        max_single = has_udh ? 67 : 70;
        max_concat = 67;
    } else {
        /* GSM 7-bit or default NLI */
        max_single = has_udh ? 153 : 160;
        max_concat = 153;
    }

    if (char_count <= (size_t)max_single) {
        return 1;
    }

    return (int)((char_count + max_concat - 1) / max_concat);
}

int smpp_manip_append_suffix(char *body, size_t max_len, const char *suffix,
                             uint8_t data_coding, int *segments_before, int *segments_after)
{
    if (!body || !suffix) return -1;

    size_t body_len = strlen(body);
    size_t suffix_len = strlen(suffix);

    if (segments_before) {
        *segments_before = smpp_calc_segments(body_len, data_coding, 0);
    }

    if (body_len + suffix_len >= max_len) {
        return -2; /* Buffer overflow */
    }

    strcat(body, suffix);
    size_t new_len = strlen(body);

    if (segments_after) {
        *segments_after = smpp_calc_segments(new_len, data_coding, 0);
    }

    return 0;
}

int smpp_manip_prepend_prefix(char *body, size_t max_len, const char *prefix)
{
    if (!body || !prefix) return -1;

    size_t body_len = strlen(body);
    size_t prefix_len = strlen(prefix);

    if (body_len + prefix_len >= max_len) {
        return -2;
    }

    memmove(body + prefix_len, body, body_len + 1);
    memcpy(body, prefix, prefix_len);
    return 0;
}

int smpp_blacklist_add_rule(const char *pattern, uint8_t action, uint32_t error_code)
{
    if (!pattern || !*pattern) return -1;

    smpp_blacklist_rule_t *rule = (smpp_blacklist_rule_t *)malloc(sizeof(smpp_blacklist_rule_t));
    if (!rule) return -1;

    strncpy(rule->pattern, pattern, sizeof(rule->pattern) - 1);
    rule->pattern[sizeof(rule->pattern) - 1] = '\0';
    rule->action = action;
    rule->error_code = error_code;
    rule->next = blacklist_head;
    blacklist_head = rule;

    return 0;
}

void smpp_blacklist_clear_rules(void)
{
    while (blacklist_head) {
        smpp_blacklist_rule_t *tmp = blacklist_head->next;
        free(blacklist_head);
        blacklist_head = tmp;
    }
}

/* Case-insensitive substring check */
static char *stristr(const char *haystack, const char *needle)
{
    if (!haystack || !needle) return NULL;
    size_t needle_len = strlen(needle);
    if (needle_len == 0) return (char *)haystack;

    for (; *haystack; haystack++) {
        if (strncasecmp(haystack, needle, needle_len) == 0) {
            return (char *)haystack;
        }
    }
    return NULL;
}

int smpp_manip_check_blacklist(const char *body, uint32_t *rejected_status)
{
    if (!body) return SMPP_ACTION_ALLOW;

    const smpp_blacklist_rule_t *curr = blacklist_head;
    while (curr) {
        if (stristr(body, curr->pattern)) {
            if (rejected_status) *rejected_status = curr->error_code;
            return curr->action;
        }
        curr = curr->next;
    }

    return SMPP_ACTION_ALLOW;
}

int smpp_manip_normalize_msisdn(const char *in_num, char *out_e164, size_t max_len,
                                uint8_t *out_ton, uint8_t *out_npi, const char *default_country_code)
{
    if (!in_num || !out_e164 || max_len < 16) return -1;

    char cleaned[64];
    size_t c_idx = 0;

    /* Strip non-digit characters except leading plus */
    for (size_t i = 0; in_num[i] != '\0' && c_idx < sizeof(cleaned) - 1; i++) {
        if (isdigit((unsigned char)in_num[i])) {
            cleaned[c_idx++] = in_num[i];
        } else if (in_num[i] == '+' && c_idx == 0) {
            /* Skip plus, normalize directly to international digits */
        }
    }
    cleaned[c_idx] = '\0';

    if (c_idx == 0) return -2;

    const char *cc = default_country_code ? default_country_code : "90";
    size_t cc_len = strlen(cc);

    if (cleaned[0] == '0' && cleaned[1] == '0') {
        /* International prefix 00XX... -> strip 00 */
        strncpy(out_e164, cleaned + 2, max_len - 1);
    } else if (cleaned[0] == '0' && c_idx >= 10) {
        /* National format 05XXXXXXXXX -> prepend country code */
        snprintf(out_e164, max_len, "%s%s", cc, cleaned + 1);
    } else if (strncmp(cleaned, cc, cc_len) == 0) {
        /* Already in E.164 without plus */
        strncpy(out_e164, cleaned, max_len - 1);
    } else {
        /* Fallback */
        strncpy(out_e164, cleaned, max_len - 1);
    }
    out_e164[max_len - 1] = '\0';

    if (out_ton) *out_ton = SMPP_TON_INTERNATIONAL;
    if (out_npi) *out_npi = SMPP_NPI_ISDN;

    return 0;
}

void smpp_detect_ton_npi(const char *addr, uint8_t *ton, uint8_t *npi)
{
    uint8_t det_ton = SMPP_TON_UNKNOWN;
    uint8_t det_npi = SMPP_NPI_ISDN;

    if (!addr || *addr == '\0') {
        if (ton) *ton = SMPP_TON_UNKNOWN;
        if (npi) *npi = SMPP_NPI_ISDN;
        return;
    }

    const char *p = addr;
    int has_plus = 0;
    if (*p == '+') {
        has_plus = 1;
        p++;
    }

    /* Check if the rest of characters are numeric */
    int is_numeric = 1;
    size_t digits_len = 0;
    for (const char *c = p; *c != '\0'; c++) {
        if (!isdigit((unsigned char)*c)) {
            is_numeric = 0;
            break;
        }
        digits_len++;
    }

    if (!is_numeric || digits_len == 0) {
        /* Contains non-digits (letters or special chars): Alphanumeric */
        det_ton = SMPP_TON_ALPHANUMERIC;
        det_npi = SMPP_NPI_UNKNOWN;
    } else if (has_plus) {
        /* Explicit leading '+' followed by digits -> International E.164 */
        det_ton = SMPP_TON_INTERNATIONAL;
        det_npi = SMPP_NPI_ISDN;
    } else if (digits_len <= 5) {
        /* Numeric and length <= 5: Shortcode / Abbreviated */
        det_ton = SMPP_TON_ABBREVIATED;
        det_npi = SMPP_NPI_UNKNOWN;
    } else if (p[0] == '0') {
        /* Numeric and starts with '0': National (e.g., 0532...) */
        det_ton = SMPP_TON_NATIONAL;
        det_npi = SMPP_NPI_ISDN;
    } else if (digits_len >= 7 && digits_len <= 15) {
        /* Standard International E.164 (e.g., 90532...) */
        det_ton = SMPP_TON_INTERNATIONAL;
        det_npi = SMPP_NPI_ISDN;
    } else {
        /* Otherwise */
        det_ton = SMPP_TON_UNKNOWN;
        det_npi = SMPP_NPI_ISDN;
    }

    if (ton) *ton = det_ton;
    if (npi) *npi = det_npi;
}
