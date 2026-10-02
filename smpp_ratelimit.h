/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - High-Speed In-Memory Token Bucket Rate Limiter
*/

#ifndef _SMPP_RATELIMIT_H_
#define _SMPP_RATELIMIT_H_

#include <stdint.h>
#include <stddef.h>

#define SMPP_RL_MAX_BUCKETS 1024

typedef struct smpp_token_bucket {
    char account_id[32];
    uint32_t mps_limit;
    uint32_t burst_limit;
    double tokens;
    uint64_t last_refill_ms;
    uint32_t current_mps_usage;
    uint64_t total_passed;
    uint64_t total_throttled;
    struct smpp_token_bucket *next;
} smpp_token_bucket_t;

int smpp_ratelimit_init(void);
void smpp_ratelimit_destroy(void);

/* Check and consume 1 token. Returns 1 if allowed, 0 if throttled */
int smpp_ratelimit_check(const char *account_id, uint32_t mps_limit, uint32_t burst_limit,
                         uint32_t *out_current_mps, uint64_t *out_throttled_count);

void smpp_ratelimit_reset_account(const char *account_id);

#endif /* _SMPP_RATELIMIT_H_ */
