/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - SMSC Server Engine Implementation
*/

#include "smpp_server.h"
#include "smpp_ratelimit.h"
#include "smpp_manip.h"
#include "smpp_concat.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern char *smpp_msgid_format;

static int server_socket_fd = -1;
static volatile int server_running = 0;
static uint32_t global_msg_counter = 1000;
static pthread_mutex_t server_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t server_thread;
static smpp_server_submit_cb_t server_submit_cb = NULL;
static smpp_server_deliver_cb_t server_deliver_cb = NULL;

void smpp_server_set_submit_cb(smpp_server_submit_cb_t cb)
{
    pthread_mutex_lock(&server_mutex);
    server_submit_cb = cb;
    pthread_mutex_unlock(&server_mutex);
}

void smpp_server_set_deliver_cb(smpp_server_deliver_cb_t cb)
{
    pthread_mutex_lock(&server_mutex);
    server_deliver_cb = cb;
    pthread_mutex_unlock(&server_mutex);
}

static smpp_server_session_t *active_sessions = NULL;
static pthread_mutex_t sessions_mutex = PTHREAD_MUTEX_INITIALIZER;

static void register_active_session(smpp_server_session_t *sess)
{
    pthread_mutex_lock(&sessions_mutex);
    sess->next = active_sessions;
    active_sessions = sess;
    pthread_mutex_unlock(&sessions_mutex);
}

static void unregister_active_session(smpp_server_session_t *sess)
{
    pthread_mutex_lock(&sessions_mutex);
    smpp_server_session_t **curr = &active_sessions;
    while (*curr) {
        if (*curr == sess) {
            *curr = sess->next;
            break;
        }
        curr = &((*curr)->next);
    }
    pthread_mutex_unlock(&sessions_mutex);
}

int smpp_server_send_deliver_sm(const char *account_id, const char *src, const char *dst,
                                const uint8_t *msg_data, uint8_t msg_len, uint8_t esm_class)
{
    pthread_mutex_lock(&sessions_mutex);
    smpp_server_session_t *curr = active_sessions;
    int sent_count = 0;

    while (curr) {
        if (!account_id || curr->account_id[0] == '\0' || strcmp(curr->account_id, account_id) == 0) {
            if (curr->state == SMPP_STATE_BOUND_TRX || curr->state == SMPP_STATE_BOUND_RX) {
                smpp_pdu_t deliver_pdu;
                memset(&deliver_pdu, 0, sizeof(deliver_pdu));
                smpp_header_init(&deliver_pdu.header, SMPP_CMD_DELIVER_SM, ESME_ROK, ++global_msg_counter);
                
                if (src) strncpy(deliver_pdu.body.msg.source_addr, src, sizeof(deliver_pdu.body.msg.source_addr) - 1);
                if (dst) strncpy(deliver_pdu.body.msg.destination_addr, dst, sizeof(deliver_pdu.body.msg.destination_addr) - 1);
                deliver_pdu.body.msg.esm_class = esm_class;
                deliver_pdu.body.msg.data_coding = 0; /* GSM 7-bit default */
                deliver_pdu.body.msg.sm_length = msg_len;
                if (msg_data && msg_len > 0) {
                    memcpy(deliver_pdu.body.msg.short_message, msg_data, msg_len);
                }

                uint8_t tx_buf[2048];
                size_t tx_len = 0;
                if (smpp_pdu_pack(&deliver_pdu, tx_buf, sizeof(tx_buf), &tx_len) == 0) {
                    send(curr->client_fd, tx_buf, tx_len, 0);
                    sent_count++;
                }
            }
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&sessions_mutex);
    return sent_count;
}

static void *client_worker_thread(void *arg)
{
    int cfd = (int)(intptr_t)arg;
    smpp_server_session_t sess;
    memset(&sess, 0, sizeof(sess));
    sess.client_fd = cfd;
    sess.state = SMPP_STATE_CONNECTED;
    register_active_session(&sess);

    uint8_t rx_buf[4096];
    uint8_t tx_buf[4096];

    while (server_running && sess.state != SMPP_STATE_DISCONNECTED) {
        ssize_t n = recv(cfd, rx_buf, sizeof(rx_buf), 0);
        if (n <= 0) break;

        size_t tx_len = 0;
        int rc = smpp_server_handle_pdu(&sess, rx_buf, (size_t)n, tx_buf, sizeof(tx_buf), &tx_len);
        if (rc == 0 && tx_len > 0) {
            send(cfd, tx_buf, tx_len, 0);
        }
    }

    unregister_active_session(&sess);
    close(cfd);
    return NULL;
}


static void *server_listener_thread(void *arg)
{
    (void)arg;
    while (server_running) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int cfd = accept(server_socket_fd, (struct sockaddr *)&caddr, &clen);
        if (cfd < 0) {
            if (!server_running) break;
            continue;
        }

        pthread_t tid;
        pthread_create(&tid, NULL, client_worker_thread, (void *)(intptr_t)cfd);
        pthread_detach(tid);
    }
    return NULL;
}

int smpp_server_start(const char *ip, int port)
{
    if (server_running) return 0;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (!ip || strcmp(ip, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, ip, &addr.sin_addr);
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -2;
    }

    if (listen(fd, 128) < 0) {
        close(fd);
        return -3;
    }

    server_socket_fd = fd;
    server_running = 1;

    pthread_create(&server_thread, NULL, server_listener_thread, NULL);
    return 0;
}

void smpp_server_stop(void)
{
    server_running = 0;
    if (server_socket_fd >= 0) {
        close(server_socket_fd);
        server_socket_fd = -1;
    }
    pthread_join(server_thread, NULL);
}

int smpp_server_handle_pdu(smpp_server_session_t *sess, const uint8_t *in_buf, size_t in_len,
                           uint8_t *out_buf, size_t max_out, size_t *out_len)
{
    if (!sess || !in_buf || !out_buf || !out_len) return -1;
    *out_len = 0;

    smpp_pdu_t in_pdu;
    if (smpp_pdu_unpack(in_buf, in_len, &in_pdu) < 0) {
        /* Generate generic_nack */
        smpp_pdu_t nack;
        smpp_make_generic_nack(&nack, 0, ESME_RINVCMDLEN);
        return smpp_pdu_pack(&nack, out_buf, max_out, out_len);
    }

    smpp_pdu_t resp_pdu;
    memset(&resp_pdu, 0, sizeof(resp_pdu));
    uint32_t seq = in_pdu.header.sequence_number;

    switch (in_pdu.header.command_id) {
    case SMPP_CMD_BIND_TRANSMITTER:
    case SMPP_CMD_BIND_RECEIVER:
    case SMPP_CMD_BIND_TRANSCEIVER: {
        uint32_t resp_cmd = (in_pdu.header.command_id == SMPP_CMD_BIND_TRANSMITTER) ? SMPP_CMD_BIND_TRANSMITTER_RESP :
                            (in_pdu.header.command_id == SMPP_CMD_BIND_RECEIVER) ? SMPP_CMD_BIND_RECEIVER_RESP :
                            SMPP_CMD_BIND_TRANSCEIVER_RESP;

        smpp_account_profile_t *acc = smpp_config_find_account(in_pdu.body.bind_req.system_id);
        uint32_t status = ESME_ROK;

        if (!acc) {
            status = ESME_RINVSYSID;
        } else if (strcmp(acc->password, in_pdu.body.bind_req.password) != 0) {
            status = ESME_RINVPASWD;
        }

        smpp_header_init(&resp_pdu.header, resp_cmd, status, seq);
        if (status == ESME_ROK) {
            strncpy(sess->account_id, acc->account_id, sizeof(sess->account_id) - 1);
            sess->state = SMPP_STATE_BOUND_TRX;
            sess->version = in_pdu.body.bind_req.interface_version;
            strncpy(resp_pdu.body.bind_resp.system_id, "KAMAILIO_SMSC", 15);
        }
        break;
    }

    case SMPP_CMD_SUBMIT_SM: {
        uint32_t status = ESME_ROK;

        if (sess->state != SMPP_STATE_BOUND_TRX && sess->state != SMPP_STATE_BOUND_TX) {
            status = ESME_RINVBNDSTS;
        } else {
            /* 1. Rate Limiting Check (MPS) */
            smpp_account_profile_t *acc = smpp_config_find_account(sess->account_id);
            int mps = acc ? acc->mps_limit : 30;
            int burst = acc ? acc->burst_limit : 60;
            if (!smpp_ratelimit_check(sess->account_id, mps, burst, NULL, NULL)) {
                status = ESME_RTHROTTLED;
            }

            /* 2. Blacklist / Anti-Fraud Check */
            if (status == ESME_ROK && in_pdu.body.msg.sm_length > 0) {
                char msg_str[256];
                size_t l = in_pdu.body.msg.sm_length < 255 ? in_pdu.body.msg.sm_length : 255;
                memcpy(msg_str, in_pdu.body.msg.short_message, l);
                msg_str[l] = '\0';

                uint32_t fraud_err = 0;
                int action = smpp_manip_check_blacklist(msg_str, &fraud_err);
                if (action == SMPP_ACTION_REJECT || action == SMPP_ACTION_DROP) {
                    status = fraud_err ? fraud_err : ESME_RMSGBLOCKED;
                }
            }
        }

        smpp_header_init(&resp_pdu.header, SMPP_CMD_SUBMIT_SM_RESP, status, seq);
        if (status == ESME_ROK) {
            pthread_mutex_lock(&server_mutex);
            uint32_t mid = global_msg_counter++;
            smpp_server_submit_cb_t cb = server_submit_cb;
            pthread_mutex_unlock(&server_mutex);

            /* Check Account-specific format or fallback to global format */
            smpp_account_profile_t *acc = smpp_config_find_account(sess->account_id);
            const char *fmt = (acc && acc->msgid_format[0] != '\0') ? acc->msgid_format :
                              (smpp_msgid_format && *smpp_msgid_format) ? smpp_msgid_format :
                              "%PREFIX%-%TIMESTAMP%-%HEXSEQ%";

            /* Generate Timestamp YYYYMMDDHHMMSS */
            time_t now = time(NULL);
            struct tm tm_buf;
            gmtime_r(&now, &tm_buf);
            char ts_str[32];
            strftime(ts_str, sizeof(ts_str), "%Y%m%d%H%M%S", &tm_buf);

            char hex_seq[16];
            snprintf(hex_seq, sizeof(hex_seq), "%08X", mid);
            char dec_seq[16];
            snprintf(dec_seq, sizeof(dec_seq), "%u", mid);

            /* Format message_id using template */
            char res_id[128] = {0};
            const char *p = fmt;
            size_t r_idx = 0;

            while (*p && r_idx < 63) {
                if (strncmp(p, "%PREFIX%", 8) == 0) {
                    const char *pfx = (acc && *acc->account_id) ? acc->account_id : "KAMAILIO";
                    size_t plen = strlen(pfx);
                    if (r_idx + plen > 63) plen = 63 - r_idx;
                    memcpy(&res_id[r_idx], pfx, plen);
                    r_idx += plen;
                    p += 8;
                } else if (strncmp(p, "%TIMESTAMP%", 11) == 0) {
                    size_t tlen = strlen(ts_str);
                    if (r_idx + tlen > 63) tlen = 63 - r_idx;
                    memcpy(&res_id[r_idx], ts_str, tlen);
                    r_idx += tlen;
                    p += 11;
                } else if (strncmp(p, "%HEXSEQ%", 8) == 0) {
                    size_t hlen = strlen(hex_seq);
                    if (r_idx + hlen > 63) hlen = 63 - r_idx;
                    memcpy(&res_id[r_idx], hex_seq, hlen);
                    r_idx += hlen;
                    p += 8;
                } else if (strncmp(p, "%DECSEQ%", 8) == 0) {
                    size_t dlen = strlen(dec_seq);
                    if (r_idx + dlen > 63) dlen = 63 - r_idx;
                    memcpy(&res_id[r_idx], dec_seq, dlen);
                    r_idx += dlen;
                    p += 8;
                } else if (strncmp(p, "%ACCOUNT%", 9) == 0) {
                    const char *acc_name = (acc && *acc->account_id) ? acc->account_id : "DEFAULT";
                    size_t alen = strlen(acc_name);
                    if (r_idx + alen > 63) alen = 63 - r_idx;
                    memcpy(&res_id[r_idx], acc_name, alen);
                    r_idx += alen;
                    p += 9;
                } else {
                    res_id[r_idx++] = *p++;
                }
            }
            res_id[r_idx] = '\0';

            strncpy(resp_pdu.body.msg_resp.message_id, res_id, 64);
            resp_pdu.body.msg_resp.message_id[64] = '\0';

            if (cb) {
                cb(sess, &in_pdu.body.msg, resp_pdu.body.msg_resp.message_id);
            }
        }
        break;
    }

    case SMPP_CMD_DELIVER_SM: {
        uint32_t status = ESME_ROK;
        if (sess->state != SMPP_STATE_BOUND_TRX && sess->state != SMPP_STATE_BOUND_RX) {
            status = ESME_RINVBNDSTS;
        }

        smpp_header_init(&resp_pdu.header, SMPP_CMD_DELIVER_SM_RESP, status, seq);
        if (status == ESME_ROK) {
            uint8_t assembled_buf[4096];
            size_t assembled_len = 0;
            int reasm_res = smpp_reassemble_msg(&in_pdu.body.msg, assembled_buf, sizeof(assembled_buf), &assembled_len);
            if (reasm_res == 1) {
                smpp_msg_t full_msg = in_pdu.body.msg;
                full_msg.esm_class &= ~0x40; /* Clear UDHI */
                if (assembled_len <= sizeof(full_msg.short_message)) {
                    memcpy(full_msg.short_message, assembled_buf, assembled_len);
                    full_msg.sm_length = (uint8_t)assembled_len;
                }
                pthread_mutex_lock(&server_mutex);
                smpp_server_deliver_cb_t cb = server_deliver_cb;
                pthread_mutex_unlock(&server_mutex);
                if (cb) {
                    cb(sess, &full_msg);
                }
            }
        }
        break;
    }

    case SMPP_CMD_ENQUIRE_LINK:
        smpp_make_enquire_link_resp(&resp_pdu, seq);
        break;

    case SMPP_CMD_UNBIND:
        smpp_make_unbind_resp(&resp_pdu, seq);
        sess->state = SMPP_STATE_DISCONNECTED;
        break;

    default:
        smpp_make_generic_nack(&resp_pdu, seq, ESME_RINVCMDID);
        break;
    }

    int rc = smpp_pdu_pack(&resp_pdu, out_buf, max_out, out_len);
    smpp_pdu_free(&in_pdu);
    smpp_pdu_free(&resp_pdu);
    return rc;
}
