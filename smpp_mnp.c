/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - ENUM & MNP (Number Portability) Implementation
*/

#include "smpp_mnp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <ctype.h>

int smpp_mnp_mode = SMPP_MNP_MODE_IN_MEMORY;
char *smpp_enum_suffix = "e164.arpa";
char *smpp_mnp_redis_host = "127.0.0.1";
int smpp_mnp_redis_port = 6379;
int smpp_mnp_cache_ttl = 3600;

typedef struct mnp_entry {
    char msisdn[32];
    char target_smsc[32];
    char rn[16];
    char operator_name[32];
    struct mnp_entry *next;
} mnp_entry_t;

#define MNP_HASH_SIZE 1024
static mnp_entry_t *mnp_hash_table[MNP_HASH_SIZE];
static pthread_mutex_t mnp_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned int mnp_hash(const char *str)
{
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % MNP_HASH_SIZE;
}

int smpp_mnp_init(void)
{
    pthread_mutex_lock(&mnp_mutex);
    memset(mnp_hash_table, 0, sizeof(mnp_hash_table));
    pthread_mutex_unlock(&mnp_mutex);
    return 0;
}

void smpp_mnp_clear_rules(void)
{
    pthread_mutex_lock(&mnp_mutex);
    for (int i = 0; i < MNP_HASH_SIZE; i++) {
        mnp_entry_t *curr = mnp_hash_table[i];
        while (curr) {
            mnp_entry_t *tmp = curr->next;
            free(curr);
            curr = tmp;
        }
        mnp_hash_table[i] = NULL;
    }
    pthread_mutex_unlock(&mnp_mutex);
}

void smpp_mnp_destroy(void)
{
    smpp_mnp_clear_rules();
}

int smpp_mnp_add_rule(const char *msisdn, const char *target_smsc, const char *rn, const char *operator_name)
{
    if (!msisdn || !target_smsc) return -1;

    unsigned int idx = mnp_hash(msisdn);
    mnp_entry_t *node = (mnp_entry_t *)malloc(sizeof(mnp_entry_t));
    if (!node) return -2;

    strncpy(node->msisdn, msisdn, sizeof(node->msisdn) - 1);
    node->msisdn[sizeof(node->msisdn) - 1] = '\0';
    strncpy(node->target_smsc, target_smsc, sizeof(node->target_smsc) - 1);
    node->target_smsc[sizeof(node->target_smsc) - 1] = '\0';

    if (rn) strncpy(node->rn, rn, sizeof(node->rn) - 1);
    else node->rn[0] = '\0';

    if (operator_name) strncpy(node->operator_name, operator_name, sizeof(node->operator_name) - 1);
    else node->operator_name[0] = '\0';

    pthread_mutex_lock(&mnp_mutex);
    node->next = mnp_hash_table[idx];
    mnp_hash_table[idx] = node;
    pthread_mutex_unlock(&mnp_mutex);

    return 0;
}

/* Convert E.164 number to ENUM reverse FQDN (RFC 3761) */
int smpp_mnp_e164_to_enum_domain(const char *e164, const char *suffix, char *out_domain, size_t max_out)
{
    if (!e164 || !out_domain || max_out < 32) return -1;

    /* Extract pure digits */
    char digits[64];
    size_t d_idx = 0;
    for (size_t i = 0; e164[i] != '\0' && d_idx < sizeof(digits) - 1; i++) {
        if (isdigit((unsigned char)e164[i])) {
            digits[d_idx++] = e164[i];
        }
    }
    digits[d_idx] = '\0';
    if (d_idx == 0) return -2;

    /* Reverse digits with dots: e.g. 90532 -> 2.3.5.0.9 */
    size_t o_idx = 0;
    for (int i = (int)d_idx - 1; i >= 0 && o_idx < max_out - 2; i--) {
        out_domain[o_idx++] = digits[i];
        out_domain[o_idx++] = '.';
    }

    const char *sfx = (suffix && *suffix) ? suffix : "e164.arpa";
    strncpy(&out_domain[o_idx], sfx, max_out - o_idx - 1);
    out_domain[max_out - 1] = '\0';

    return 0;
}

int smpp_mnp_lookup(const char *msisdn, smpp_mnp_result_t *result)
{
    if (!msisdn || !result) return -1;
    memset(result, 0, sizeof(*result));

    if (smpp_mnp_mode == SMPP_MNP_MODE_DISABLED) {
        return -1;
    }

    /* Clean digits */
    char clean_num[32];
    size_t c_idx = 0;
    for (size_t i = 0; msisdn[i] != '\0' && c_idx < sizeof(clean_num) - 1; i++) {
        if (isdigit((unsigned char)msisdn[i])) {
            clean_num[c_idx++] = msisdn[i];
        }
    }
    clean_num[c_idx] = '\0';

    /* 1. In-Memory Hash Table Dip (Sub-millisecond) */
    unsigned int idx = mnp_hash(clean_num);
    pthread_mutex_lock(&mnp_mutex);
    mnp_entry_t *curr = mnp_hash_table[idx];
    while (curr) {
        if (strcmp(curr->msisdn, clean_num) == 0) {
            strncpy(result->target_smsc, curr->target_smsc, sizeof(result->target_smsc) - 1);
            strncpy(result->routing_number, curr->rn, sizeof(result->routing_number) - 1);
            strncpy(result->operator_name, curr->operator_name, sizeof(result->operator_name) - 1);
            result->is_ported = 1;
            pthread_mutex_unlock(&mnp_mutex);
            return 0;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&mnp_mutex);

    /* 2. Fallback to native prefix detection if not explicitly ported in DB */
    if (strncmp(clean_num, "9053", 4) == 0) {
        strcpy(result->target_smsc, "sim1");
        strcpy(result->routing_number, "D001");
        strcpy(result->operator_name, "TURKCELL");
        result->is_ported = 0;
        return 0;
    } else if (strncmp(clean_num, "9054", 4) == 0) {
        strcpy(result->target_smsc, "sim2");
        strcpy(result->routing_number, "D002");
        strcpy(result->operator_name, "VODAFONE");
        result->is_ported = 0;
        return 0;
    } else if (strncmp(clean_num, "9055", 4) == 0 || strncmp(clean_num, "9050", 4) == 0) {
        strcpy(result->target_smsc, "sim3");
        strcpy(result->routing_number, "D003");
        strcpy(result->operator_name, "TURK_TELEKOM");
        result->is_ported = 0;
        return 0;
    }

    return -2; /* Not found */
}
