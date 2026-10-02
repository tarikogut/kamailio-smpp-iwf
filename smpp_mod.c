/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Module Core
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../core/sr_module.h"
#include "../../core/dprint.h"
#include "../../core/mem/mem.h"
#include "../../core/kemi.h"

#include "smpp_mod.h"
#include "smpp_pdu.h"
#include "smpp_tlv.h"
#include "smpp_nli.h"
#include "smpp_manip.h"
#include "smpp_ratelimit.h"
#include "smpp_config.h"
#include "smpp_client.h"
#include "smpp_server.h"
#include "smpp_interwork.h"
#include "smpp_dlr.h"
#include "smpp_mnp.h"
#include "smpp_http_api.h"
#include "smpp_pv.h"
#include "smpp_rpc.h"

#include "../../core/mod_fix.h"

MODULE_VERSION

/* Module Parameters */
int smpp_listen_port = 2775;
char *smpp_listen_ip = "0.0.0.0";
int smpp_worker_procs = 2;
int smpp_enquire_link_interval = 30;
int smpp_response_timeout = 5;
int smpp_reconnect_interval = 10;
char *smpp_db_url = NULL;
int smpp_default_client_mps = 30;
char *smpp_msgid_format = "%PREFIX%-%TIMESTAMP%-%HEXSEQ%";
int smpp_http_api_enable = 1;
int smpp_http_api_port = 8080;
char *smpp_http_api_token = "secret-token-123";

static int mod_init(void);
static int child_init(int rank);
static void destroy(void);
static int on_server_submit(smpp_server_session_t *sess, const smpp_msg_t *msg, char *out_msg_id);
static void on_client_deliver(const char *smsc_id, const smpp_msg_t *msg);

/* Script Commands Prototypes */
static int w_smpp_send(struct sip_msg *msg, char *smsc, char *src, char *dst, char *text);
static int w_smpp_append_suffix(struct sip_msg *msg, char *suffix);
static int w_smpp_prepend_prefix(struct sip_msg *msg, char *prefix);

/* Exported Functions */
static cmd_export_t cmds[] = {
    {"smpp_send", (cmd_function)w_smpp_send, 4, fixup_spve_all, fixup_free_spve_all,
        REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE | LOCAL_ROUTE},
    {"smpp_append_suffix", (cmd_function)w_smpp_append_suffix, 1, fixup_spve_null, fixup_free_spve_null,
        REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE | LOCAL_ROUTE},
    {"smpp_prepend_prefix", (cmd_function)w_smpp_prepend_prefix, 1, fixup_spve_null, fixup_free_spve_null,
        REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE | LOCAL_ROUTE},
    {0, 0, 0, 0, 0, 0}
};

/* Exported Parameters */
static param_export_t params[] = {
    {"listen_port",            PARAM_INT,    &smpp_listen_port},
    {"listen_ip",              PARAM_STRING, &smpp_listen_ip},
    {"worker_procs",           PARAM_INT,    &smpp_worker_procs},
    {"enquire_link_interval",  PARAM_INT,    &smpp_enquire_link_interval},
    {"response_timeout",       PARAM_INT,    &smpp_response_timeout},
    {"reconnect_interval",     PARAM_INT,    &smpp_reconnect_interval},
    {"db_url",                 PARAM_STRING, &smpp_db_url},
    {"default_client_mps",     PARAM_INT,    &smpp_default_client_mps},
    {"msgid_format",           PARAM_STRING, &smpp_msgid_format},
    {"mnp_mode",               PARAM_INT,    &smpp_mnp_mode},
    {"enum_suffix",            PARAM_STRING, &smpp_enum_suffix},
    {"mnp_redis_host",         PARAM_STRING, &smpp_mnp_redis_host},
    {"mnp_cache_ttl",          PARAM_INT,    &smpp_mnp_cache_ttl},
    {"http_api_enable",        PARAM_INT,    &smpp_http_api_enable},
    {"http_api_port",          PARAM_INT,    &smpp_http_api_port},
    {"http_api_token",         PARAM_STRING, &smpp_http_api_token},
    {0, 0, 0}
};

/* Exported Pseudo-Variables */
static pv_export_t mod_pvs[] = {
    {str_init("smpp"), PVT_OTHER, pv_get_smpp, pv_set_smpp, pv_parse_smpp_name, 0, 0, 0},
    {{0, 0}, 0, 0, 0, 0, 0, 0, 0}
};

/* Module Exports */
struct module_exports exports = {
    "smpp",
    DEFAULT_DLFLAGS,
    cmds,
    params,
    0,            /* RPC methods registered via smpp_init_rpc() */
    mod_pvs,      /* Pseudo-variables */
    0,            /* Response function */
    mod_init,
    child_init,
    destroy
};

static int mod_init(void)
{
    LM_INFO("Initializing SMPP (SMS-IWF) Module [Port:%d, Workers:%d, Default MPS:%d]\n",
            smpp_listen_port, smpp_worker_procs, smpp_default_client_mps);

    smpp_ratelimit_init();
    smpp_config_init();
    smpp_client_init();
    smpp_mnp_init();
    smpp_init_rpc();

    /* Initialize default anti-fraud rules */
    smpp_blacklist_add_rule("phishing", SMPP_ACTION_REJECT, ESME_RMSGBLOCKED);
    smpp_blacklist_add_rule("malware", SMPP_ACTION_REJECT, ESME_RMSGBLOCKED);
    smpp_blacklist_add_rule("bahis", SMPP_ACTION_REJECT, ESME_RMSGBLOCKED);

    /* Add default authorized client accounts for inbound connections */
    smpp_account_profile_t acc1;
    memset(&acc1, 0, sizeof(acc1));
    strcpy(acc1.account_id, "kamailio_client");
    strcpy(acc1.password, "kamailio_pass");
    acc1.mps_limit = smpp_default_client_mps ? smpp_default_client_mps : 50;
    acc1.burst_limit = acc1.mps_limit * 2;
    strcpy(acc1.msgid_format, "%PREFIX%-%TIMESTAMP%-%HEXSEQ%");
    smpp_config_add_account(&acc1);

    smpp_account_profile_t acc2;
    memset(&acc2, 0, sizeof(acc2));
    strcpy(acc2.account_id, "test_esme");
    strcpy(acc2.password, "test_pwd");
    acc2.mps_limit = 100;
    acc2.burst_limit = 200;
    strcpy(acc2.msgid_format, "SMS-%ACCOUNT%-%TIMESTAMP%-%DECSEQ%");
    smpp_config_add_account(&acc2);

    /* Pre-configure the 4 Melrose Labs SMSC Simulators */
    int sim_ports[4] = {2775, 2776, 2777, 2778};
    char *sim_ids[4] = {"sim1", "sim2", "sim3", "sim4"};
    char *b_codes[4] = {"B251", "B001", "B002", "B003"};

    for (int i = 0; i < 4; i++) {
        smpp_smsc_profile_t sp;
        memset(&sp, 0, sizeof(sp));
        strcpy(sp.smsc_id, sim_ids[i]);

        /* In Docker network, use container name smsc_sim1..4 on port 2775 */
        char host_buf[64];
        snprintf(host_buf, sizeof(host_buf), "smsc_sim%d", i + 1);
        struct hostent *he = gethostbyname(host_buf);
        if (he) {
            strncpy(sp.host, host_buf, sizeof(sp.host) - 1);
            sp.port = 2775;
        } else {
            strcpy(sp.host, "127.0.0.1");
            sp.port = sim_ports[i];
        }

        strcpy(sp.system_id, "kamailio_out");
        strcpy(sp.password, "password");
        strcpy(sp.system_type, "CMT");
        sp.version = SMPP_VERSION_34;
        sp.mps_limit = 100;
        strcpy(sp.default_b_code, b_codes[i]);
        sp.nli_mode = 1; /* Enabled */
        smpp_config_add_smsc(&sp);

        /* Connect client session */
        smpp_client_conn_t *c = smpp_client_connect(&sp);
        if (c && c->state == SMPP_STATE_BOUND_TRX) {
            LM_INFO("SMPP Client connected and bound TRX to %s (%s:%d)\n",
                    sim_ids[i], sp.host, sp.port);
        }
    }

    if (smpp_listen_port > 0) {
        smpp_server_set_submit_cb(on_server_submit);
        if (smpp_server_start(smpp_listen_ip, smpp_listen_port) < 0) {
            LM_WARN("Could not bind SMPP listener to %s:%d (maybe non-root or port in use)\n",
                    smpp_listen_ip, smpp_listen_port);
        } else {
            LM_INFO("SMPP SMSC Server listener active on %s:%d\n", smpp_listen_ip, smpp_listen_port);
        }
    }

    /* Start HTTP REST API server if enabled */
    if (smpp_http_api_enable && smpp_http_api_port > 0) {
        if (smpp_http_api_start("0.0.0.0", smpp_http_api_port) == 0) {
            LM_INFO("SMPP HTTP REST API active on port %d\n", smpp_http_api_port);
        } else {
            LM_WARN("Could not start SMPP HTTP REST API on port %d\n", smpp_http_api_port);
        }
    }

    smpp_client_set_deliver_cb(on_client_deliver);

    /* Start supervisor thread for auto-reconnect and keepalive */
    smpp_client_start_supervisor(smpp_reconnect_interval, smpp_enquire_link_interval);
    LM_INFO("SMPP Client Supervisor active (reconnect=%ds, keepalive=%ds)\n",
            smpp_reconnect_interval, smpp_enquire_link_interval);

    return 0;
}

static void on_client_deliver(const char *smsc_id, const smpp_msg_t *msg)
{
    if (!msg) return;

    /* Normalize DLR */
    smpp_dlr_info_t dlr;
    if (smpp_dlr_normalize(msg, &dlr) == 0) {
        LM_INFO("Received DLR from SMSC '%s' for MsgID '%s': Status='%s' (was_tlv_only=%d)\n",
                smsc_id ? smsc_id : "unknown", dlr.message_id, dlr.stat_str, dlr.was_tlv_only);

        /* Update REST API tracker */
        smpp_http_api_record_msg(dlr.message_id, msg->source_addr, msg->destination_addr,
                                 dlr.stat_str, smsc_id ? smsc_id : "sim1");

        /* If body was reconstructed or empty, ensure standard body */
        char healed_body[SMPP_MAX_SHORT_MSG_LEN];
        size_t b_len = msg->sm_length;
        if (b_len > 0) {
            memcpy(healed_body, msg->short_message, b_len);
            healed_body[b_len] = '\0';
        } else {
            smpp_dlr_reconstruct_body(&dlr, healed_body, sizeof(healed_body));
            b_len = strlen(healed_body);
        }

        /* Forward deliver_sm to all bound transceiver/receiver client ESMEs */
        int forwarded = smpp_server_send_deliver_sm(NULL, msg->source_addr, msg->destination_addr,
                                                    (const uint8_t *)healed_body, (uint8_t)b_len, msg->esm_class);
        LM_INFO("Forwarded deliver_sm (DLR) to %d connected ESME client(s)\n", forwarded);
    } else {
        /* Standard inbound MO SMS */
        int forwarded = smpp_server_send_deliver_sm(NULL, msg->source_addr, msg->destination_addr,
                                                    msg->short_message, msg->sm_length, msg->esm_class);
        LM_INFO("Forwarded inbound MO SMS from '%s' to %d connected ESME client(s)\n",
                msg->source_addr, forwarded);
    }
}


static int child_init(int rank)
{
    if (rank == PROC_INIT || rank == PROC_MAIN || rank == PROC_TCP_MAIN)
        return 0;

    LM_DBG("Child init SMPP module for process rank: %d\n", rank);
    return 0;
}

static void destroy(void)
{
    LM_INFO("Destroying SMPP (SMS-IWF) module\n");
    if (smpp_http_api_enable) {
        smpp_http_api_stop();
    }
    smpp_server_stop();
    smpp_client_destroy();
    smpp_config_destroy();
    smpp_ratelimit_destroy();
    smpp_mnp_destroy();
    smpp_blacklist_clear_rules();
}

static int on_server_submit(smpp_server_session_t *sess, const smpp_msg_t *msg, char *out_msg_id)
{
    (void)sess;
    (void)out_msg_id;
    if (!msg) return -1;

    char body[SMPP_MAX_SHORT_MSG_LEN];
    size_t l = msg->sm_length < sizeof(body) - 1 ? msg->sm_length : sizeof(body) - 1;
    memcpy(body, msg->short_message, l);
    body[l] = '\0';

    LM_INFO("SMPP Server received SUBMIT_SM from '%s' to '%s': '%s'\n",
            msg->source_addr, msg->destination_addr, body);

    /* Route via ENUM / MNP Resolution Engine */
    smpp_client_conn_t *conn = NULL;
    smpp_mnp_result_t mnp_res;
    if (smpp_mnp_lookup(msg->destination_addr, &mnp_res) == 0 && *mnp_res.target_smsc) {
        conn = smpp_client_find(mnp_res.target_smsc);
        if (conn) {
            LM_INFO("MNP/ENUM resolved destination '%s' to SMSC '%s' (RN: %s, Operator: %s, Ported: %d)\n",
                    msg->destination_addr, mnp_res.target_smsc, mnp_res.routing_number,
                    mnp_res.operator_name, mnp_res.is_ported);
        }
    }

    /* Fallback to default pool if MNP returned no active trunk */
    if (!conn) conn = smpp_client_find("sim1");
    if (!conn) conn = smpp_client_find("sim2");
    if (!conn) conn = smpp_client_find("sim3");
    if (!conn) conn = smpp_client_find("sim4");

    if (conn) {
        char remote_msg_id[65] = {0};
        int rc = smpp_client_send_submit_sm(conn, msg->source_addr, msg->destination_addr,
                                            msg->short_message, msg->sm_length,
                                            msg->data_coding, msg->esm_class,
                                            NULL, remote_msg_id);
        if (rc == 0) {
            LM_INFO("Successfully forwarded SUBMIT_SM to SMSC '%s' (Remote MsgID: %s)\n",
                    conn->smsc_id, remote_msg_id);
            return 0;
        } else {
            LM_ERR("Failed to forward SUBMIT_SM to SMSC '%s': rc=%d\n", conn->smsc_id, rc);
        }
    } else {
        LM_WARN("No active outbound SMSC connection found to forward message\n");
    }
    return 0;
}

static int w_smpp_send(struct sip_msg *msg, char *smsc, char *src, char *dst, char *text)
{
    str s_smsc = {0, 0};
    str s_src = {0, 0};
    str s_dst = {0, 0};
    str s_text = {0, 0};

    if (fixup_get_svalue(msg, (fparam_t *)smsc, &s_smsc) < 0) {
        LM_ERR("Failed to evaluate smsc parameter\n");
        return -1;
    }
    if (src && fixup_get_svalue(msg, (fparam_t *)src, &s_src) < 0) {
        LM_ERR("Failed to evaluate src parameter\n");
        return -1;
    }
    if (fixup_get_svalue(msg, (fparam_t *)dst, &s_dst) < 0) {
        LM_ERR("Failed to evaluate dst parameter\n");
        return -1;
    }
    if (fixup_get_svalue(msg, (fparam_t *)text, &s_text) < 0) {
        LM_ERR("Failed to evaluate text parameter\n");
        return -1;
    }

    char c_smsc[32] = {0};
    size_t slen = s_smsc.len < 31 ? s_smsc.len : 31;
    memcpy(c_smsc, s_smsc.s, slen);

    char c_src[32] = {0};
    if (s_src.s && s_src.len > 0) {
        size_t srclen = s_src.len < 31 ? s_src.len : 31;
        memcpy(c_src, s_src.s, srclen);
    }

    char c_dst[32] = {0};
    size_t dlen = s_dst.len < 31 ? s_dst.len : 31;
    memcpy(c_dst, s_dst.s, dlen);

    char c_text[256] = {0};
    size_t tlen = s_text.len < 255 ? s_text.len : 255;
    memcpy(c_text, s_text.s, tlen);

    LM_INFO("smpp_send called: smsc='%s', src='%s', dst='%s', text='%s'\n",
            c_smsc, c_src, c_dst, c_text);

    /* In-flight context update */
    smpp_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    strncpy(ctx.src, c_src, sizeof(ctx.src) - 1);
    strncpy(ctx.dst, c_dst, sizeof(ctx.dst) - 1);
    strncpy(ctx.body, c_text, sizeof(ctx.body) - 1);
    smpp_ctx_set_current(&ctx);

    smpp_client_conn_t *conn = smpp_client_find(c_smsc);
    if (!conn) {
        smpp_smsc_profile_t *p = smpp_config_find_smsc(c_smsc);
        if (p) {
            conn = smpp_client_connect(p);
        }
    }

    if (!conn) {
        LM_ERR("SMSC '%s' not found or failed to connect\n", c_smsc);
        return -1;
    }

    char out_msg_id[65] = {0};
    uint8_t sm_data[256];
    uint8_t sm_len = (uint8_t)strlen(c_text);
    if (sm_len > 255) sm_len = 255;
    memcpy(sm_data, c_text, sm_len);

    int rc = smpp_client_send_submit_sm(conn, c_src, c_dst, sm_data, sm_len,
                                        SMPP_ENCODING_DEFAULT, 0, NULL, out_msg_id);
    if (rc == 0) {
        LM_INFO("smpp_send success to '%s': MsgID=%s\n", c_smsc, out_msg_id);
        smpp_http_api_record_msg(out_msg_id, c_src[0] ? c_src : "SIP", c_dst, "SUBMITTED", c_smsc);
        return 1;
    }

    LM_ERR("smpp_send to '%s' failed with error code %d\n", c_smsc, rc);
    return -1;
}

static int w_smpp_append_suffix(struct sip_msg *msg, char *suffix)
{
    if (!suffix) return -1;
    smpp_ctx_t *ctx = smpp_ctx_get_current();
    smpp_manip_append_suffix(ctx->body, sizeof(ctx->body), suffix, SMPP_ENCODING_DEFAULT, NULL, NULL);
    LM_DBG("smpp_append_suffix applied: new body='%s'\n", ctx->body);
    return 1;
}

static int w_smpp_prepend_prefix(struct sip_msg *msg, char *prefix)
{
    if (!prefix) return -1;
    smpp_ctx_t *ctx = smpp_ctx_get_current();
    smpp_manip_prepend_prefix(ctx->body, sizeof(ctx->body), prefix);
    LM_DBG("smpp_prepend_prefix applied: new body='%s'\n", ctx->body);
    return 1;
}

/* KEMI Bindings */
static int ki_smpp_send(sip_msg_t *msg, str *smsc, str *src, str *dst, str *text)
{
    if (!smsc || !dst || !text || smsc->len == 0 || dst->len == 0 || text->len == 0) {
        LM_ERR("KEMI smpp.send: invalid parameters\n");
        return -1;
    }

    char smsc_buf[32] = {0};
    size_t slen = smsc->len < 31 ? smsc->len : 31;
    memcpy(smsc_buf, smsc->s, slen);

    char src_buf[32] = {0};
    if (src && src->len > 0) {
        size_t srclen = src->len < 31 ? src->len : 31;
        memcpy(src_buf, src->s, srclen);
    }

    char dst_buf[32] = {0};
    size_t dlen = dst->len < 31 ? dst->len : 31;
    memcpy(dst_buf, dst->s, dlen);

    char txt_buf[256] = {0};
    size_t tlen = text->len < 255 ? text->len : 255;
    memcpy(txt_buf, text->s, tlen);

    LM_INFO("KEMI smpp.send: smsc='%s', src='%s', dst='%s', text='%s'\n",
            smsc_buf, src_buf, dst_buf, txt_buf);

    return w_smpp_send((struct sip_msg *)msg, smsc_buf, src_buf, dst_buf, txt_buf);
}

static str ki_smpp_mnp_lookup(sip_msg_t *msg, str *msisdn)
{
    static char target_buf[32];
    str res = {target_buf, 0};
    if (!msisdn || msisdn->len == 0) return res;

    char num_str[64];
    size_t l = msisdn->len < sizeof(num_str) - 1 ? msisdn->len : sizeof(num_str) - 1;
    memcpy(num_str, msisdn->s, l);
    num_str[l] = '\0';

    smpp_mnp_result_t mnp_res;
    if (smpp_mnp_lookup(num_str, &mnp_res) == 0) {
        strncpy(target_buf, mnp_res.target_smsc, sizeof(target_buf) - 1);
        target_buf[sizeof(target_buf) - 1] = '\0';
        res.len = strlen(target_buf);
    }
    return res;
}

static sr_kemi_t sr_kemi_smpp_exports[] = {
    {str_init("smpp"), str_init("send"),
        SR_KEMIP_INT, ki_smpp_send,
        {SR_KEMIP_STR, SR_KEMIP_STR, SR_KEMIP_STR, SR_KEMIP_STR, SR_KEMIP_NONE, SR_KEMIP_NONE}},
    {str_init("smpp"), str_init("mnp_lookup"),
        SR_KEMIP_STR, ki_smpp_mnp_lookup,
        {SR_KEMIP_STR, SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE}},
    {{0, 0}, {0, 0}, 0, NULL, {0, 0, 0, 0, 0, 0}}
};

int mod_register(char *path, int *dlflags, void *p1, void *p2)
{
    sr_kemi_modules_add(sr_kemi_smpp_exports);
    return 0;
}
