/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Built-in REST API Server Header
*/

#ifndef _SMPP_HTTP_API_H_
#define _SMPP_HTTP_API_H_

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* Global REST API configuration */
extern int smpp_http_api_enable;
extern int smpp_http_api_port;
extern char *smpp_http_api_token;

/* DLR / Message Query Record */
typedef struct smpp_api_msg_record {
    char message_id[65];
    char src[32];
    char dst[32];
    char status[16];        /* "SENT", "DELIVRD", "UNDELIV", "REJECTD" */
    char smsc_id[32];
    char created_at[32];
    struct smpp_api_msg_record *next;
} smpp_api_msg_record_t;

/* Start & Stop HTTP Server */
int smpp_http_api_start(const char *ip, int port);
void smpp_http_api_stop(void);

/* Record message event for querying via GET /api/v1/sms/query?id=... */
int smpp_http_api_record_msg(const char *msg_id, const char *src, const char *dst, const char *status, const char *smsc_id);

/* Process an incoming raw HTTP request and generate HTTP JSON response */
int smpp_http_api_handle_request(const char *req_buf, size_t req_len, char *resp_buf, size_t max_resp, size_t *out_len);

#endif /* _SMPP_HTTP_API_H_ */
