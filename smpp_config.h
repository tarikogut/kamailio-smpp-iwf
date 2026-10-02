/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Configuration Backend & In-Memory Profiles
*/

#ifndef _SMPP_CONFIG_H_
#define _SMPP_CONFIG_H_

#include <stdint.h>
#include <stddef.h>

typedef struct smpp_smsc_profile {
    char smsc_id[32];
    char host[128];
    int port;
    char system_id[32];
    char password[64];
    char system_type[32];
    char mode[8];               /* "trx", "tx", "rx" */
    uint8_t version;            /* 0x34 or 0x50 */
    uint8_t nli_mode;           /* 0=none, 1=auto, 2=single, 3=locking */
    char nli_allowed_langs[64]; /* "tr", "tr,es", "all" */
    char fallback_policy[16];   /* "ucs2", "translit", "reject" */
    char default_b_code[16];    /* e.g., " B251" */
    int mps_limit;
    struct smpp_smsc_profile *next;
} smpp_smsc_profile_t;

typedef struct smpp_account_profile {
    char account_id[32];
    char password[64];
    char allowed_ips[256];
    char allowed_senders[256];
    int mps_limit;
    int burst_limit;
    int max_binds;
    char force_b_code[16];
    char msgid_format[64];      /* e.g., "%PREFIX%-%TIMESTAMP%-%HEXSEQ%" */
    struct smpp_account_profile *next;
} smpp_account_profile_t;

int smpp_config_init(void);
void smpp_config_destroy(void);

int smpp_config_add_smsc(const smpp_smsc_profile_t *profile);
smpp_smsc_profile_t *smpp_config_find_smsc(const char *smsc_id);

int smpp_config_add_account(const smpp_account_profile_t *profile);
smpp_account_profile_t *smpp_config_find_account(const char *account_id);

/* Reload all configuration in shared memory atomically */
int smpp_config_reload(void);

#endif /* _SMPP_CONFIG_H_ */
