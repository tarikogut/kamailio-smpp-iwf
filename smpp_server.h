/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - SMSC Server Engine Header
*/

#ifndef _SMPP_SERVER_H_
#define _SMPP_SERVER_H_

#include <stdint.h>
#include <stddef.h>
#include "smpp_pdu.h"
#include "smpp_config.h"
#include "smpp_client.h"

typedef struct smpp_server_session {
    int client_fd;
    char account_id[32];
    char client_ip[64];
    smpp_session_state_t state;
    uint8_t version;
    uint32_t active_binds;
    struct smpp_server_session *next;
} smpp_server_session_t;

int smpp_server_start(const char *ip, int port);
void smpp_server_stop(void);

/* Callback when server receives a valid SUBMIT_SM */
typedef int (*smpp_server_submit_cb_t)(smpp_server_session_t *sess, const smpp_msg_t *msg, char *out_msg_id);
void smpp_server_set_submit_cb(smpp_server_submit_cb_t cb);

/* Process an incoming PDU from a connected client */
int smpp_server_handle_pdu(smpp_server_session_t *sess, const uint8_t *in_buf, size_t in_len,
                           uint8_t *out_buf, size_t max_out, size_t *out_len);

/* Send a deliver_sm (DLR or Inbound MO) to connected server clients */
int smpp_server_send_deliver_sm(const char *account_id, const char *src, const char *dst,
                                const uint8_t *msg_data, uint8_t msg_len, uint8_t esm_class);

#endif /* _SMPP_SERVER_H_ */

