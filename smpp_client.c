/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - ESME Client Engine Implementation
*/

#include "smpp_client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>

static smpp_client_conn_t *client_conns = NULL;
static pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;

int smpp_client_init(void)
{
    pthread_mutex_lock(&client_mutex);
    client_conns = NULL;
    pthread_mutex_unlock(&client_mutex);
    return 0;
}

void smpp_client_destroy(void)
{
    pthread_mutex_lock(&client_mutex);
    smpp_client_conn_t *curr = client_conns;
    while (curr) {
        smpp_client_conn_t *tmp = curr->next;
        if (curr->sock_fd >= 0) close(curr->sock_fd);
        free(curr);
        curr = tmp;
    }
    client_conns = NULL;
    pthread_mutex_unlock(&client_mutex);
}

smpp_client_conn_t *smpp_client_find(const char *smsc_id)
{
    if (!smsc_id) return NULL;
    pthread_mutex_lock(&client_mutex);
    smpp_client_conn_t *curr = client_conns;
    while (curr) {
        if (strcmp(curr->smsc_id, smsc_id) == 0) {
            pthread_mutex_unlock(&client_mutex);
            return curr;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&client_mutex);
    return NULL;
}

smpp_client_conn_t *smpp_client_connect(const smpp_smsc_profile_t *profile)
{
    if (!profile) return NULL;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    /* Set 5-second socket timeout */
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(profile->port);

    if (inet_pton(AF_INET, profile->host, &serv_addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(profile->host);
        if (!he) {
            close(fd);
            return NULL;
        }
        memcpy(&serv_addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    if (connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(fd);
        return NULL;
    }

    smpp_client_conn_t *conn = (smpp_client_conn_t *)malloc(sizeof(smpp_client_conn_t));
    if (!conn) {
        close(fd);
        return NULL;
    }

    memset(conn, 0, sizeof(smpp_client_conn_t));
    strncpy(conn->smsc_id, profile->smsc_id, sizeof(conn->smsc_id) - 1);
    conn->sock_fd = fd;
    conn->state = SMPP_STATE_CONNECTED;
    conn->sequence_number = 1;
    memcpy(&conn->profile, profile, sizeof(smpp_smsc_profile_t));

    /* Send bind_transceiver */
    smpp_pdu_t bind_pdu;
    memset(&bind_pdu, 0, sizeof(bind_pdu));
    smpp_header_init(&bind_pdu.header, SMPP_CMD_BIND_TRANSCEIVER, ESME_ROK, conn->sequence_number++);

    strncpy(bind_pdu.body.bind_req.system_id, profile->system_id, sizeof(bind_pdu.body.bind_req.system_id) - 1);
    strncpy(bind_pdu.body.bind_req.password, profile->password, sizeof(bind_pdu.body.bind_req.password) - 1);
    strncpy(bind_pdu.body.bind_req.system_type, profile->system_type, sizeof(bind_pdu.body.bind_req.system_type) - 1);
    bind_pdu.body.bind_req.interface_version = profile->version ? profile->version : SMPP_VERSION_34;

    uint8_t tx_buf[512];
    size_t tx_len = 0;
    if (smpp_pdu_pack(&bind_pdu, tx_buf, sizeof(tx_buf), &tx_len) == 0) {
        send(fd, tx_buf, tx_len, 0);

        /* Wait for bind_transceiver_resp */
        uint8_t rx_buf[512];
        ssize_t rx_len = recv(fd, rx_buf, sizeof(rx_buf), 0);
        if (rx_len >= SMPP_HEADER_LEN) {
            smpp_pdu_t resp_pdu;
            if (smpp_pdu_unpack(rx_buf, (size_t)rx_len, &resp_pdu) == 0) {
                if (resp_pdu.header.command_status == ESME_ROK) {
                    conn->state = SMPP_STATE_BOUND_TRX;
                }
                smpp_pdu_free(&resp_pdu);
            }
        }
    }

    pthread_mutex_lock(&client_mutex);
    conn->next = client_conns;
    client_conns = conn;
    pthread_mutex_unlock(&client_mutex);

    return conn;
}

int smpp_client_disconnect(smpp_client_conn_t *conn)
{
    if (!conn) return -1;

    if (conn->sock_fd >= 0) {
        if (conn->state == SMPP_STATE_BOUND_TRX) {
            smpp_pdu_t unbind_pdu;
            smpp_make_unbind(&unbind_pdu, conn->sequence_number++);
            uint8_t buf[64];
            size_t len = 0;
            if (smpp_pdu_pack(&unbind_pdu, buf, sizeof(buf), &len) == 0) {
                send(conn->sock_fd, buf, len, 0);
            }
        }
        close(conn->sock_fd);
        conn->sock_fd = -1;
    }
    conn->state = SMPP_STATE_DISCONNECTED;
    return 0;
}

int smpp_client_send_submit_sm(smpp_client_conn_t *conn, const char *src, const char *dst,
                              const uint8_t *msg_data, uint8_t msg_len, uint8_t data_coding,
                              uint8_t esm_class, smpp_tlv_t *tlvs, char *out_msg_id)
{
    if (!conn || conn->sock_fd < 0 || conn->state != SMPP_STATE_BOUND_TRX) return -1;

    smpp_pdu_t pdu;
    memset(&pdu, 0, sizeof(pdu));
    uint32_t seq = conn->sequence_number++;
    smpp_header_init(&pdu.header, SMPP_CMD_SUBMIT_SM, ESME_ROK, seq);

    if (src) strncpy(pdu.body.msg.source_addr, src, sizeof(pdu.body.msg.source_addr) - 1);
    if (dst) strncpy(pdu.body.msg.destination_addr, dst, sizeof(pdu.body.msg.destination_addr) - 1);
    pdu.body.msg.source_addr_ton = SMPP_TON_ALPHANUMERIC;
    pdu.body.msg.source_addr_npi = SMPP_NPI_UNKNOWN;
    pdu.body.msg.dest_addr_ton = SMPP_TON_INTERNATIONAL;
    pdu.body.msg.dest_addr_npi = SMPP_NPI_ISDN;

    pdu.body.msg.data_coding = data_coding;
    pdu.body.msg.esm_class = esm_class;
    pdu.body.msg.registered_delivery = 1; /* Request DLR */

    if (msg_data && msg_len > 0) {
        pdu.body.msg.sm_length = msg_len;
        memcpy(pdu.body.msg.short_message, msg_data, msg_len);
    }
    pdu.body.msg.tlvs = tlvs;

    uint8_t tx_buf[4096];
    size_t tx_len = 0;
    if (smpp_pdu_pack(&pdu, tx_buf, sizeof(tx_buf), &tx_len) < 0) return -2;

    if (send(conn->sock_fd, tx_buf, tx_len, 0) < 0) return -3;

    /* Read submit_sm_resp */
    uint8_t rx_buf[1024];
    ssize_t rx_len = recv(conn->sock_fd, rx_buf, sizeof(rx_buf), 0);
    if (rx_len < SMPP_HEADER_LEN) return -4;

    smpp_pdu_t resp;
    if (smpp_pdu_unpack(rx_buf, (size_t)rx_len, &resp) < 0) return -5;

    int res = (resp.header.command_status == ESME_ROK) ? 0 : (int)resp.header.command_status;
    if (res == 0 && out_msg_id) {
        strncpy(out_msg_id, resp.body.msg_resp.message_id, 64);
        out_msg_id[64] = '\0';
    }

    smpp_pdu_free(&resp);
    return res;
}

int smpp_client_send_enquire_link(smpp_client_conn_t *conn)
{
    if (!conn || conn->sock_fd < 0 || conn->state != SMPP_STATE_BOUND_TRX) return -1;

    smpp_pdu_t pdu;
    smpp_make_enquire_link(&pdu, conn->sequence_number++);

    uint8_t tx_buf[64];
    size_t tx_len = 0;
    if (smpp_pdu_pack(&pdu, tx_buf, sizeof(tx_buf), &tx_len) < 0) return -2;

    if (send(conn->sock_fd, tx_buf, tx_len, 0) < 0) return -3;

    uint8_t rx_buf[64];
    ssize_t rx_len = recv(conn->sock_fd, rx_buf, sizeof(rx_buf), 0);
    if (rx_len < SMPP_HEADER_LEN) return -4;

    smpp_pdu_t resp;
    if (smpp_pdu_unpack(rx_buf, (size_t)rx_len, &resp) < 0) return -5;

    int ok = (resp.header.command_id == SMPP_CMD_ENQUIRE_LINK_RESP && resp.header.command_status == ESME_ROK) ? 0 : -6;
    smpp_pdu_free(&resp);
    return ok;
}
