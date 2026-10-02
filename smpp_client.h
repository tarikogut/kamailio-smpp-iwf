/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - ESME Client Engine Header
*/

#ifndef _SMPP_CLIENT_H_
#define _SMPP_CLIENT_H_

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include "smpp_pdu.h"
#include "smpp_config.h"

typedef enum {
    SMPP_STATE_DISCONNECTED = 0,
    SMPP_STATE_CONNECTING,
    SMPP_STATE_CONNECTED,
    SMPP_STATE_BOUND_TX,
    SMPP_STATE_BOUND_RX,
    SMPP_STATE_BOUND_TRX,
    SMPP_STATE_UNBINDING
} smpp_session_state_t;

typedef struct smpp_client_conn {
    char smsc_id[32];
    int sock_fd;
    smpp_session_state_t state;
    uint32_t sequence_number;
    uint64_t last_activity_ms;
    smpp_smsc_profile_t profile;
    pthread_t rx_thread;
    volatile int running;
    struct smpp_client_conn *next;
} smpp_client_conn_t;

/* Callback when client receives deliver_sm (DLR or Inbound MO SMS) from SMSC */
typedef void (*smpp_client_deliver_cb_t)(const char *smsc_id, const smpp_msg_t *msg);
void smpp_client_set_deliver_cb(smpp_client_deliver_cb_t cb);

int smpp_client_init(void);
void smpp_client_destroy(void);

smpp_client_conn_t *smpp_client_connect(const smpp_smsc_profile_t *profile);
int smpp_client_disconnect(smpp_client_conn_t *conn);

int smpp_client_send_submit_sm(smpp_client_conn_t *conn, const char *src, const char *dst,
                              const uint8_t *msg_data, uint8_t msg_len, uint8_t data_coding,
                              uint8_t esm_class, smpp_tlv_t *tlvs, char *out_msg_id);

int smpp_client_send_enquire_link(smpp_client_conn_t *conn);

smpp_client_conn_t *smpp_client_find(const char *smsc_id);

#endif /* _SMPP_CLIENT_H_ */

