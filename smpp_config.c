/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Configuration Implementation
*/

#include "smpp_config.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

static smpp_smsc_profile_t *smsc_list = NULL;
static smpp_account_profile_t *account_list = NULL;
static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

int smpp_config_init(void)
{
    pthread_mutex_lock(&config_mutex);
    smsc_list = NULL;
    account_list = NULL;
    pthread_mutex_unlock(&config_mutex);
    return 0;
}

void smpp_config_destroy(void)
{
    pthread_mutex_lock(&config_mutex);

    while (smsc_list) {
        smpp_smsc_profile_t *tmp = smsc_list->next;
        free(smsc_list);
        smsc_list = tmp;
    }

    while (account_list) {
        smpp_account_profile_t *tmp = account_list->next;
        free(account_list);
        account_list = tmp;
    }

    pthread_mutex_unlock(&config_mutex);
}

int smpp_config_add_smsc(const smpp_smsc_profile_t *profile)
{
    if (!profile || !*profile->smsc_id) return -1;

    smpp_smsc_profile_t *node = (smpp_smsc_profile_t *)malloc(sizeof(smpp_smsc_profile_t));
    if (!node) return -1;

    memcpy(node, profile, sizeof(smpp_smsc_profile_t));

    pthread_mutex_lock(&config_mutex);
    node->next = smsc_list;
    smsc_list = node;
    pthread_mutex_unlock(&config_mutex);

    return 0;
}

smpp_smsc_profile_t *smpp_config_find_smsc(const char *smsc_id)
{
    if (!smsc_id) return NULL;

    pthread_mutex_lock(&config_mutex);
    smpp_smsc_profile_t *curr = smsc_list;
    while (curr) {
        if (strcmp(curr->smsc_id, smsc_id) == 0) {
            pthread_mutex_unlock(&config_mutex);
            return curr;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&config_mutex);
    return NULL;
}

int smpp_config_add_account(const smpp_account_profile_t *profile)
{
    if (!profile || !*profile->account_id) return -1;

    smpp_account_profile_t *node = (smpp_account_profile_t *)malloc(sizeof(smpp_account_profile_t));
    if (!node) return -1;

    memcpy(node, profile, sizeof(smpp_account_profile_t));

    pthread_mutex_lock(&config_mutex);
    node->next = account_list;
    account_list = node;
    pthread_mutex_unlock(&config_mutex);

    return 0;
}

smpp_account_profile_t *smpp_config_find_account(const char *account_id)
{
    if (!account_id) return NULL;

    pthread_mutex_lock(&config_mutex);
    smpp_account_profile_t *curr = account_list;
    while (curr) {
        if (strcmp(curr->account_id, account_id) == 0) {
            pthread_mutex_unlock(&config_mutex);
            return curr;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&config_mutex);
    return NULL;
}

int smpp_config_reload(void)
{
    /* Atomic hot reload - in real DB deployment, loads new list and swaps pointers */
    return 0;
}
