/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Token Bucket Rate Limiter Implementation
*/

#include "smpp_ratelimit.h"
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <pthread.h>

static smpp_token_bucket_t *buckets_hash[SMPP_RL_MAX_BUCKETS];
static pthread_mutex_t rl_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint64_t current_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((uint64_t)tv.tv_sec * 1000ULL) + ((uint64_t)tv.tv_usec / 1000ULL);
}

static unsigned int hash_str(const char *str)
{
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % SMPP_RL_MAX_BUCKETS;
}

int smpp_ratelimit_init(void)
{
    pthread_mutex_lock(&rl_mutex);
    memset(buckets_hash, 0, sizeof(buckets_hash));
    pthread_mutex_unlock(&rl_mutex);
    return 0;
}

void smpp_ratelimit_destroy(void)
{
    pthread_mutex_lock(&rl_mutex);
    for (int i = 0; i < SMPP_RL_MAX_BUCKETS; i++) {
        smpp_token_bucket_t *curr = buckets_hash[i];
        while (curr) {
            smpp_token_bucket_t *tmp = curr->next;
            free(curr);
            curr = tmp;
        }
        buckets_hash[i] = NULL;
    }
    pthread_mutex_unlock(&rl_mutex);
}

int smpp_ratelimit_check(const char *account_id, uint32_t mps_limit, uint32_t burst_limit,
                         uint32_t *out_current_mps, uint64_t *out_throttled_count)
{
    if (!account_id || !*account_id) return 1; /* Bypass if no account */
    if (mps_limit == 0) return 1; /* 0 means unlimited */

    uint32_t max_capacity = (burst_limit > 0) ? burst_limit : (mps_limit * 2);
    unsigned int idx = hash_str(account_id);
    uint64_t now = current_time_ms();
    int allowed = 0;

    pthread_mutex_lock(&rl_mutex);

    smpp_token_bucket_t *b = buckets_hash[idx];
    while (b) {
        if (strcmp(b->account_id, account_id) == 0) break;
        b = b->next;
    }

    if (!b) {
        b = (smpp_token_bucket_t *)malloc(sizeof(smpp_token_bucket_t));
        if (!b) {
            pthread_mutex_unlock(&rl_mutex);
            return 1;
        }
        strncpy(b->account_id, account_id, sizeof(b->account_id) - 1);
        b->account_id[sizeof(b->account_id) - 1] = '\0';
        b->mps_limit = mps_limit;
        b->burst_limit = max_capacity;
        b->tokens = (double)max_capacity;
        b->last_refill_ms = now;
        b->current_mps_usage = 0;
        b->total_passed = 0;
        b->total_throttled = 0;
        b->next = buckets_hash[idx];
        buckets_hash[idx] = b;
    }

    /* Refill tokens based on elapsed time */
    uint64_t elapsed_ms = (now > b->last_refill_ms) ? (now - b->last_refill_ms) : 0;
    if (elapsed_ms > 0) {
        double added_tokens = ((double)elapsed_ms * (double)mps_limit) / 1000.0;
        b->tokens += added_tokens;
        if (b->tokens > (double)max_capacity) {
            b->tokens = (double)max_capacity;
        }

        /* Estimate current MPS usage */
        if (elapsed_ms >= 1000) {
            b->current_mps_usage = (uint32_t)b->total_passed;
            b->last_refill_ms = now;
        }
    }

    /* Consume token */
    if (b->tokens >= 1.0) {
        b->tokens -= 1.0;
        b->total_passed++;
        allowed = 1;
    } else {
        b->total_throttled++;
        allowed = 0;
    }

    if (out_current_mps) *out_current_mps = b->current_mps_usage;
    if (out_throttled_count) *out_throttled_count = b->total_throttled;

    pthread_mutex_unlock(&rl_mutex);
    return allowed;
}

void smpp_ratelimit_reset_account(const char *account_id)
{
    if (!account_id) return;
    unsigned int idx = hash_str(account_id);
    pthread_mutex_lock(&rl_mutex);
    smpp_token_bucket_t *b = buckets_hash[idx];
    while (b) {
        if (strcmp(b->account_id, account_id) == 0) {
            b->tokens = (double)b->burst_limit;
            b->total_throttled = 0;
            break;
        }
        b = b->next;
    }
    pthread_mutex_unlock(&rl_mutex);
}
