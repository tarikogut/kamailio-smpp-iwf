/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - ENUM & MNP (Number Portability) Engine Header
*/

#ifndef _SMPP_MNP_H_
#define _SMPP_MNP_H_

#include <stdint.h>
#include <stddef.h>

typedef enum {
    SMPP_MNP_MODE_DISABLED = 0,
    SMPP_MNP_MODE_DNS_ENUM,     /* RFC 3761 e164.arpa ENUM DNS NAPTR lookup */
    SMPP_MNP_MODE_IN_MEMORY,    /* High-speed local hash table / cache */
    SMPP_MNP_MODE_REDIS,        /* External Redis database dip */
    SMPP_MNP_MODE_HTTP_REST     /* Centralized Operator MNP HTTP Gateway */
} smpp_mnp_mode_t;

typedef struct smpp_mnp_result {
    char target_smsc[32];       /* Target trunk id: "sim1", "sim2", "sim3", "sim4" */
    char routing_number[16];    /* RN (Routing Number), e.g., "D001", "B002", "21401" */
    char operator_name[32];     /* "TURKCELL", "VODAFONE", "TURK_TELEKOM" */
    int is_ported;              /* 1: Ported number, 0: Native prefix block */
} smpp_mnp_result_t;

/* Global MNP configuration variables */
extern int smpp_mnp_mode;
extern char *smpp_enum_suffix;
extern char *smpp_mnp_redis_host;
extern int smpp_mnp_redis_port;
extern int smpp_mnp_cache_ttl;

/* Engine Initialization & Cleanup */
int smpp_mnp_init(void);
void smpp_mnp_destroy(void);

/* In-memory mapping management (e.g. from DB / local cache) */
int smpp_mnp_add_rule(const char *msisdn, const char *target_smsc, const char *rn, const char *operator_name);
void smpp_mnp_clear_rules(void);

/* Convert E.164 number to ENUM reverse FQDN (e.g. +905321234567 -> 7.6.5.4.3.2.1.2.3.5.0.9.e164.arpa) */
int smpp_mnp_e164_to_enum_domain(const char *e164, const char *suffix, char *out_domain, size_t max_out);

/* Core Lookup: Resolves destination MSISDN to appropriate SMSC trunk via ENUM / MNP */
int smpp_mnp_lookup(const char *msisdn, smpp_mnp_result_t *result);

#endif /* _SMPP_MNP_H_ */
