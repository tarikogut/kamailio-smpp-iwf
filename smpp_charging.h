/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Extensible Charging & Credit Control Subsystem Header
*/

#ifndef _SMPP_CHARGING_H_
#define _SMPP_CHARGING_H_

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>

/* Charging Modes */
typedef enum {
    SMPP_CHARGING_MODE_LOCAL = 0,    /* In-memory account balance store */
    SMPP_CHARGING_MODE_DIAMETER = 1  /* 3GPP Ro Diameter CCR/CCA Credit Control */
} smpp_charging_mode_t;

/* Diameter RFC 6733 / RFC 4006 / 3GPP TS 32.299 Constants */
#define DIAMETER_APP_RO                   4
#define DIAMETER_CMD_CC                   272
#define DIAMETER_FLAG_REQUEST             0x80
#define DIAMETER_FLAG_PROXIABLE           0x40

/* CC-Request-Type (AVP 416) */
#define CC_REQUEST_TYPE_INITIAL_REQUEST   1
#define CC_REQUEST_TYPE_UPDATE_REQUEST    2
#define CC_REQUEST_TYPE_TERMINATION_REQ   3
#define CC_REQUEST_TYPE_EVENT_RECORD      4

/* Requested-Action (AVP 436) */
#define REQUESTED_ACTION_DIRECT_DEBITING  0
#define REQUESTED_ACTION_REFUND           1
#define REQUESTED_ACTION_CHECK_BALANCE    2
#define REQUESTED_ACTION_PRICE_ENQUIRY    3

/* Diameter Standard Result-Codes (AVP 268) */
#define DIAMETER_SUCCESS                  2001
#define DIAMETER_LIMITED_SUCCESS          2002
#define DIAMETER_COMMAND_UNSUPPORTED      3001
#define DIAMETER_END_USER_SERVICE_DENIED  4010
#define DIAMETER_CREDIT_CONTROL_NOT_APPL  4011
#define DIAMETER_CREDIT_LIMIT_REACHED     4012
#define DIAMETER_USER_UNKNOWN             5030
#define DIAMETER_RATING_FAILED            5031

/* In-Memory Local Account Balance */
typedef struct smpp_account_balance {
    char account_id[64];
    double balance;               /* Current available credit units */
    double price_per_segment;     /* Cost per SMS segment (default 1.0) */
    double total_spent;           /* Total deducted credit */
    uint64_t total_messages;      /* Total messages charged */
    time_t last_updated;          /* Modification timestamp */
    struct smpp_account_balance *next;
} smpp_account_balance_t;

/* Diameter Ro Credit-Control-Request (CCR) Descriptor */
typedef struct {
    char session_id[128];
    char origin_host[64];
    char origin_realm[64];
    char destination_realm[64];
    char account_id[64];
    char src_msisdn[32];
    char dst_msisdn[32];
    uint32_t request_type;        /* EVENT_RECORD = 4 */
    uint32_t request_number;
    uint32_t requested_action;    /* DIRECT_DEBITING = 0, CHECK_BALANCE = 2 */
    uint32_t requested_units;     /* SMS segments requested */
    uint32_t hop_by_hop;
    uint32_t end_to_end;
} smpp_diameter_ccr_t;

/* Diameter Ro Credit-Control-Answer (CCA) Descriptor */
typedef struct {
    char session_id[128];
    uint32_t result_code;         /* 2001 (SUCCESS), 4012 (CREDIT_LIMIT_REACHED), etc. */
    uint32_t request_type;
    uint32_t request_number;
    uint32_t granted_units;       /* Granted segments */
    double remaining_balance;
    uint32_t hop_by_hop;
    uint32_t end_to_end;
} smpp_diameter_cca_t;

/* Diameter Socket/Transport Hook Callback */
typedef int (*smpp_diameter_hook_t)(const uint8_t *req, size_t req_len,
                                    uint8_t *resp, size_t max_resp, size_t *resp_len);

/* Subsystem Lifecycle */
int smpp_charging_init(void);
void smpp_charging_destroy(void);

/* Configuration & Mode Management */
int smpp_charging_set_mode(smpp_charging_mode_t mode);
smpp_charging_mode_t smpp_charging_get_mode(void);
void smpp_charging_set_diameter_hook(smpp_diameter_hook_t hook);
smpp_diameter_hook_t smpp_charging_get_diameter_hook(void);

/* Local Balance Store Operations */
int smpp_charging_set_balance(const char *account_id, double balance);
int smpp_charging_add_credit(const char *account_id, double add_amount, double *new_balance);
int smpp_charging_get_balance(const char *account_id, double *out_balance);
int smpp_charging_set_price_per_segment(const char *account_id, double price);
double smpp_charging_get_price_per_segment(const char *account_id);
int smpp_charging_account_exists(const char *account_id);

/* Core Credit Checking & Deduction Interface */
int smpp_charging_check_credit(const char *account_id, const char *src, const char *dst,
                               int segments, uint32_t *remaining_credit);
int smpp_charging_deduct_credit(const char *account_id, const char *src, const char *dst,
                                int segments, double cost);

/* Diameter Ro Serialization & Protocol Engine */
int smpp_diameter_pack_ccr(const smpp_diameter_ccr_t *ccr, uint8_t *out_buf, size_t max_out, size_t *out_len);
int smpp_diameter_unpack_ccr(const uint8_t *buf, size_t len, smpp_diameter_ccr_t *ccr);
int smpp_diameter_pack_cca(const smpp_diameter_cca_t *cca, uint8_t *out_buf, size_t max_out, size_t *out_len);
int smpp_diameter_unpack_cca(const uint8_t *buf, size_t len, smpp_diameter_cca_t *cca);

#endif /* _SMPP_CHARGING_H_ */
