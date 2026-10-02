/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - ESME Client Engine Implementation
*/

#include "smpp_client.h"
#include "smpp_manip.h"
#include "smpp_concat.h"
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
#include <time.h>

static smpp_client_conn_t *client_conns = NULL;
static pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;
static smpp_client_deliver_cb_t client_deliver_cb = NULL;

/* Supervisor Thread Controls */
static pthread_t supervisor_thread;
static volatile int supervisor_running = 0;
static int supervisor_reconnect_interval = 10;
static int supervisor_enquire_interval = 30;

void smpp_client_set_deliver_cb(smpp_client_deliver_cb_t cb)
{
    pthread_mutex_lock(&client_mutex);
    client_deliver_cb = cb;
    pthread_mutex_unlock(&client_mutex);
}

static void *client_rx_thread_func(void *arg)
{
    smpp_client_conn_t *conn = (smpp_client_conn_t *)arg;
    if (!conn) return NULL;

    uint8_t rx_buf[4096];

    while (conn->running && conn->state == SMPP_STATE_BOUND_TRX && conn->sock_fd >= 0) {
        ssize_t n = recv(conn->sock_fd, rx_buf, sizeof(rx_buf), 0);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            break;
        }

        smpp_pdu_t pdu;
        if (smpp_pdu_unpack(rx_buf, (size_t)n, &pdu) == 0) {
            if (pdu.header.command_id == SMPP_CMD_DELIVER_SM) {
                /* Acknowledge deliver_sm immediately back to SMSC */
                smpp_pdu_t d_resp;
                memset(&d_resp, 0, sizeof(d_resp));
                smpp_header_init(&d_resp.header, SMPP_CMD_DELIVER_SM_RESP, ESME_ROK, pdu.header.sequence_number);
                uint8_t d_tx[64];
                size_t d_tx_len = 0;
                if (smpp_pdu_pack(&d_resp, d_tx, sizeof(d_tx), &d_tx_len) == 0) {
                    send(conn->sock_fd, d_tx, d_tx_len, 0);
                }

                pthread_mutex_lock(&client_mutex);
                smpp_client_deliver_cb_t cb = client_deliver_cb;
                pthread_mutex_unlock(&client_mutex);

                if (cb) {
                    cb(conn->smsc_id, &pdu.body.msg);
                }
            } else if (pdu.header.command_id == SMPP_CMD_SUBMIT_SM_RESP) {
                pthread_mutex_lock(&conn->resp_mutex);
                if (pdu.header.sequence_number == conn->waiting_seq) {
                    conn->resp_received = 1;
                    conn->resp_status = pdu.header.command_status;
                    if (pdu.header.command_status == ESME_ROK) {
                        strncpy(conn->resp_msg_id, pdu.body.msg_resp.message_id, 64);
                        conn->resp_msg_id[64] = '\0';
                    }
                    pthread_cond_broadcast(&conn->resp_cond);
                }
                pthread_mutex_unlock(&conn->resp_mutex);
            } else if (pdu.header.command_id == SMPP_CMD_ENQUIRE_LINK) {
                smpp_pdu_t el_resp;
                memset(&el_resp, 0, sizeof(el_resp));
                smpp_make_enquire_link_resp(&el_resp, pdu.header.sequence_number);
                uint8_t el_tx[64];
                size_t el_tx_len = 0;
                if (smpp_pdu_pack(&el_resp, el_tx, sizeof(el_tx), &el_tx_len) == 0) {
                    send(conn->sock_fd, el_tx, el_tx_len, 0);
                }
            } else if (pdu.header.command_id == SMPP_CMD_ENQUIRE_LINK_RESP) {
                /* Keepalive response acknowledged */
            }
            smpp_pdu_free(&pdu);
        }
    }

    conn->state = SMPP_STATE_DISCONNECTED;
    return NULL;
}

int smpp_client_init(void)
{
    pthread_mutex_lock(&client_mutex);
    client_conns = NULL;
    pthread_mutex_unlock(&client_mutex);
    return 0;
}

void smpp_client_destroy(void)
{
    smpp_client_stop_supervisor();

    pthread_mutex_lock(&client_mutex);
    smpp_client_conn_t *curr = client_conns;
    while (curr) {
        smpp_client_conn_t *tmp = curr->next;
        curr->running = 0;
        if (curr->sock_fd >= 0) {
            close(curr->sock_fd);
            curr->sock_fd = -1;
        }
        pthread_mutex_destroy(&curr->resp_mutex);
        pthread_cond_destroy(&curr->resp_cond);
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

static int do_client_connect_and_bind(smpp_client_conn_t *conn)
{
    if (!conn) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* Set 5-second socket timeout */
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(conn->profile.port);

    if (inet_pton(AF_INET, conn->profile.host, &serv_addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(conn->profile.host);
        if (!he) {
            close(fd);
            return -2;
        }
        memcpy(&serv_addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    if (connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(fd);
        return -3;
    }

    conn->sock_fd = fd;
    conn->state = SMPP_STATE_CONNECTED;

    /* Send bind_transceiver */
    smpp_pdu_t bind_pdu;
    memset(&bind_pdu, 0, sizeof(bind_pdu));
    smpp_header_init(&bind_pdu.header, SMPP_CMD_BIND_TRANSCEIVER, ESME_ROK, conn->sequence_number++);

    strncpy(bind_pdu.body.bind_req.system_id, conn->profile.system_id, sizeof(bind_pdu.body.bind_req.system_id) - 1);
    strncpy(bind_pdu.body.bind_req.password, conn->profile.password, sizeof(bind_pdu.body.bind_req.password) - 1);
    strncpy(bind_pdu.body.bind_req.system_type, conn->profile.system_type, sizeof(bind_pdu.body.bind_req.system_type) - 1);
    bind_pdu.body.bind_req.interface_version = conn->profile.version ? conn->profile.version : SMPP_VERSION_34;

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

    if (conn->state == SMPP_STATE_BOUND_TRX) {
        conn->running = 1;
        conn->owner_pid = getpid();
        conn->last_activity_ms = (uint64_t)time(NULL);
        pthread_create(&conn->rx_thread, NULL, client_rx_thread_func, conn);
        return 0;
    }

    close(fd);
    conn->sock_fd = -1;
    conn->state = SMPP_STATE_DISCONNECTED;
    return -4;
}

smpp_client_conn_t *smpp_client_connect(const smpp_smsc_profile_t *profile)
{
    if (!profile) return NULL;

    /* Check if already in list */
    pthread_mutex_lock(&client_mutex);
    smpp_client_conn_t *existing = client_conns;
    while (existing) {
        if (strcmp(existing->smsc_id, profile->smsc_id) == 0) {
            pthread_mutex_unlock(&client_mutex);
            if (existing->state != SMPP_STATE_BOUND_TRX) {
                do_client_connect_and_bind(existing);
            }
            return existing;
        }
        existing = existing->next;
    }

    smpp_client_conn_t *conn = (smpp_client_conn_t *)malloc(sizeof(smpp_client_conn_t));
    if (!conn) {
        pthread_mutex_unlock(&client_mutex);
        return NULL;
    }

    memset(conn, 0, sizeof(smpp_client_conn_t));
    strncpy(conn->smsc_id, profile->smsc_id, sizeof(conn->smsc_id) - 1);
    conn->sock_fd = -1;
    conn->state = SMPP_STATE_DISCONNECTED;
    conn->sequence_number = 1;
    memcpy(&conn->profile, profile, sizeof(smpp_smsc_profile_t));
    pthread_mutex_init(&conn->resp_mutex, NULL);
    pthread_cond_init(&conn->resp_cond, NULL);

    conn->next = client_conns;
    client_conns = conn;
    pthread_mutex_unlock(&client_mutex);

    do_client_connect_and_bind(conn);
    return conn;
}

int smpp_client_disconnect(smpp_client_conn_t *conn)
{
    if (!conn) return -1;

    conn->running = 0;
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

int smpp_client_send_submit_sm_ex(smpp_client_conn_t *conn, const char *src, const char *dst,
                                 uint8_t src_ton, uint8_t src_npi, uint8_t dst_ton, uint8_t dst_npi,
                                 const uint8_t *msg_data, uint8_t msg_len, uint8_t data_coding,
                                 uint8_t esm_class, smpp_tlv_t *tlvs, char *out_msg_id)
{
    if (!conn || conn->sock_fd < 0 || conn->state != SMPP_STATE_BOUND_TRX) return -1;

    /* Auto-segment messages that exceed single PDU limit and have no segmentation headers attached */
    size_t threshold = (data_coding == SMPP_ENCODING_UCS2) ? SMPP_CONCAT_UCS2_MAX_SINGLE : SMPP_CONCAT_GSM_MAX_SINGLE;
    if (msg_len > threshold && (esm_class & 0x40) == 0 && !smpp_tlv_find(tlvs, SMPP_TLV_SAR_TOTAL_SEGMENTS)) {
        return smpp_client_send_multipart_ex(conn, src, dst, src_ton, src_npi, dst_ton, dst_npi,
                                             msg_data, msg_len, data_coding, 1 /* use_udh */, out_msg_id);
    }

    smpp_pdu_t pdu;
    memset(&pdu, 0, sizeof(pdu));
    uint32_t seq = conn->sequence_number++;
    smpp_header_init(&pdu.header, SMPP_CMD_SUBMIT_SM, ESME_ROK, seq);

    if (src) strncpy(pdu.body.msg.source_addr, src, sizeof(pdu.body.msg.source_addr) - 1);
    if (dst) strncpy(pdu.body.msg.destination_addr, dst, sizeof(pdu.body.msg.destination_addr) - 1);

    /* Determine Source TON and NPI */
    if (src_ton == 0xFF || src_npi == 0xFF || (src_ton == 0 && src_npi == 0)) {
        smpp_detect_ton_npi(pdu.body.msg.source_addr, &pdu.body.msg.source_addr_ton, &pdu.body.msg.source_addr_npi);
    } else {
        pdu.body.msg.source_addr_ton = src_ton;
        pdu.body.msg.source_addr_npi = src_npi;
    }

    /* Determine Destination TON and NPI */
    if (dst_ton == 0xFF || dst_npi == 0xFF || (dst_ton == 0 && dst_npi == 0)) {
        smpp_detect_ton_npi(pdu.body.msg.destination_addr, &pdu.body.msg.dest_addr_ton, &pdu.body.msg.dest_addr_npi);
    } else {
        pdu.body.msg.dest_addr_ton = dst_ton;
        pdu.body.msg.dest_addr_npi = dst_npi;
    }

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

    /* If called from a forked child process (different PID from rx_thread owner),
     * pthread cond_wait cannot be signaled across processes without shared memory.
     * In this case, send the SUBMIT_SM and generate a tracking sequence ID immediately. */
    if (conn->owner_pid != 0 && conn->owner_pid != getpid()) {
        if (send(conn->sock_fd, tx_buf, tx_len, 0) < 0) {
            return -3;
        }
        conn->last_activity_ms = (uint64_t)time(NULL);
        if (out_msg_id) {
            snprintf(out_msg_id, 65, "SIP-%u", seq);
        }
        return 0;
    }

    /* Prepare response waiter (same process where rx_thread runs) */
    pthread_mutex_lock(&conn->resp_mutex);
    conn->waiting_seq = seq;
    conn->resp_received = 0;
    conn->resp_status = (uint32_t)-1;
    conn->resp_msg_id[0] = '\0';

    if (send(conn->sock_fd, tx_buf, tx_len, 0) < 0) {
        conn->waiting_seq = 0;
        pthread_mutex_unlock(&conn->resp_mutex);
        return -3;
    }

    conn->last_activity_ms = (uint64_t)time(NULL);

    /* Wait for SUBMIT_SM_RESP up to 5 seconds */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;

    int wait_rc = 0;
    while (!conn->resp_received && wait_rc == 0) {
        wait_rc = pthread_cond_timedwait(&conn->resp_cond, &conn->resp_mutex, &ts);
    }

    int res = -4;
    if (conn->resp_received) {
        res = (conn->resp_status == ESME_ROK) ? 0 : (int)conn->resp_status;
        if (res == 0 && out_msg_id) {
            strncpy(out_msg_id, conn->resp_msg_id, 64);
            out_msg_id[64] = '\0';
        }
    } else {
        res = -4; /* Timeout waiting for response */
    }

    conn->waiting_seq = 0;
    pthread_mutex_unlock(&conn->resp_mutex);

    return res;
}

int smpp_client_send_submit_sm(smpp_client_conn_t *conn, const char *src, const char *dst,
                              const uint8_t *msg_data, uint8_t msg_len, uint8_t data_coding,
                              uint8_t esm_class, smpp_tlv_t *tlvs, char *out_msg_id)
{
    return smpp_client_send_submit_sm_ex(conn, src, dst, 0xFF, 0xFF, 0xFF, 0xFF,
                                        msg_data, msg_len, data_coding, esm_class, tlvs, out_msg_id);
}

int smpp_client_send_multipart_ex(smpp_client_conn_t *conn, const char *src, const char *dst,
                                 uint8_t src_ton, uint8_t src_npi, uint8_t dst_ton, uint8_t dst_npi,
                                 const uint8_t *msg_data, size_t msg_len, uint8_t data_coding,
                                 int use_udh, char *out_first_msg_id)
{
    if (!conn || !msg_data || msg_len == 0) return -1;

    static uint16_t concat_ref_counter = 1;
    uint16_t ref = (uint16_t)__sync_fetch_and_add(&concat_ref_counter, 1);
    if (ref == 0) ref = (uint16_t)__sync_fetch_and_add(&concat_ref_counter, 1);

    smpp_msg_t segments[SMPP_CONCAT_MAX_PARTS];
    int n_segs = smpp_split_message(msg_data, msg_len, data_coding, use_udh, ref, segments, SMPP_CONCAT_MAX_PARTS);
    if (n_segs <= 0) return -2;

    int overall_rc = 0;
    char first_id[65] = {0};

    for (int i = 0; i < n_segs; i++) {
        char seg_msg_id[65] = {0};
        int rc = smpp_client_send_submit_sm_ex(conn, src, dst, src_ton, src_npi, dst_ton, dst_npi,
                                              segments[i].short_message, segments[i].sm_length,
                                              segments[i].data_coding, segments[i].esm_class,
                                              segments[i].tlvs, seg_msg_id);
        if (i == 0 && rc == 0) {
            strncpy(first_id, seg_msg_id, sizeof(first_id) - 1);
        }
        if (rc != 0) {
            overall_rc = rc;
            break;
        }
    }

    smpp_free_segments(segments, n_segs);

    if (overall_rc == 0 && out_first_msg_id) {
        strncpy(out_first_msg_id, first_id, 64);
        out_first_msg_id[64] = '\0';
    }

    return overall_rc;
}

int smpp_client_send_multipart(smpp_client_conn_t *conn, const char *src, const char *dst,
                              const uint8_t *msg_data, size_t msg_len, uint8_t data_coding,
                              int use_udh, char *out_first_msg_id)
{
    return smpp_client_send_multipart_ex(conn, src, dst, 0xFF, 0xFF, 0xFF, 0xFF,
                                         msg_data, msg_len, data_coding, use_udh, out_first_msg_id);
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
    conn->last_activity_ms = (uint64_t)time(NULL);
    return 0;
}

static void *supervisor_thread_func(void *arg)
{
    (void)arg;
    while (supervisor_running) {
        sleep(1);
        if (!supervisor_running) break;

        uint64_t now = (uint64_t)time(NULL);

        pthread_mutex_lock(&client_mutex);
        smpp_client_conn_t *curr = client_conns;
        while (curr) {
            if (curr->state == SMPP_STATE_DISCONNECTED) {
                if (now - curr->last_activity_ms >= (uint64_t)supervisor_reconnect_interval) {
                    curr->last_activity_ms = now;
                    pthread_mutex_unlock(&client_mutex);
                    do_client_connect_and_bind(curr);
                    pthread_mutex_lock(&client_mutex);
                }
            } else if (curr->state == SMPP_STATE_BOUND_TRX) {
                if (now - curr->last_activity_ms >= (uint64_t)supervisor_enquire_interval) {
                    smpp_client_send_enquire_link(curr);
                }
            }
            curr = curr->next;
        }
        pthread_mutex_unlock(&client_mutex);
    }
    return NULL;
}

int smpp_client_start_supervisor(int reconnect_sec, int enquire_sec)
{
    if (supervisor_running) return 0;
    if (reconnect_sec > 0) supervisor_reconnect_interval = reconnect_sec;
    if (enquire_sec > 0) supervisor_enquire_interval = enquire_sec;
    supervisor_running = 1;
    return pthread_create(&supervisor_thread, NULL, supervisor_thread_func, NULL);
}

void smpp_client_stop_supervisor(void)
{
    if (!supervisor_running) return;
    supervisor_running = 0;
    pthread_join(supervisor_thread, NULL);
}
