/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - PDU Manipulation, Suffix/Prefix Injection & Fraud Filter
*/

#ifndef _SMPP_MANIP_H_
#define _SMPP_MANIP_H_

#include <stdint.h>
#include <stddef.h>

#define SMPP_ACTION_ALLOW   0
#define SMPP_ACTION_REJECT  1
#define SMPP_ACTION_DROP    2
#define SMPP_ACTION_ALERT   3

typedef struct smpp_blacklist_rule {
    char pattern[128];
    uint8_t action;
    uint32_t error_code;
    struct smpp_blacklist_rule *next;
} smpp_blacklist_rule_t;

/* Calculation of SMS segments based on encoding and length */
int smpp_calc_segments(size_t char_count, uint8_t data_coding, int has_udh);

/* Suffix & Prefix Manipulation */
int smpp_manip_append_suffix(char *body, size_t max_len, const char *suffix,
                             uint8_t data_coding, int *segments_before, int *segments_after);

int smpp_manip_prepend_prefix(char *body, size_t max_len, const char *prefix);

/* Blacklist / Anti-Fraud Content Scanning */
int smpp_blacklist_add_rule(const char *pattern, uint8_t action, uint32_t error_code);
void smpp_blacklist_clear_rules(void);
int smpp_manip_check_blacklist(const char *body, uint32_t *rejected_status);

/* MSISDN Normalization */
int smpp_manip_normalize_msisdn(const char *in_num, char *out_e164, size_t max_len,
                                uint8_t *out_ton, uint8_t *out_npi, const char *default_country_code);

/* Intelligent TON/NPI auto-detection */
void smpp_detect_ton_npi(const char *addr, uint8_t *ton, uint8_t *npi);

#endif /* _SMPP_MANIP_H_ */
