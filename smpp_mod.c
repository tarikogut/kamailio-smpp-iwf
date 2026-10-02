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
#include "smpp_pv.h"
#include "smpp_rpc.h"

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

static int mod_init(void);
static int child_init(int rank);
static void destroy(void);
static int on_server_submit(smpp_server_session_t *sess, const smpp_msg_t *msg, char *out_msg_id);

/* Script Commands Prototypes */
static int w_smpp_send(struct sip_msg *msg, char *smsc, char *src, char *dst, char *text);
static int w_smpp_append_suffix(struct sip_msg *msg, char *suffix);
static int w_smpp_prepend_prefix(struct sip_msg *msg, char *prefix);

/* Exported Functions */
static cmd_export_t cmds[] = {
    {"smpp_send", (cmd_function)w_smpp_send, 4, 0, 0,
        REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE | LOCAL_ROUTE},
    {"smpp_append_suffix", (cmd_function)w_smpp_append_suffix, 1, 0, 0,
        REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE | LOCAL_ROUTE},
    {"smpp_prepend_prefix", (cmd_function)w_smpp_prepend_prefix, 1, 0, 0,
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

    return 0;
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
    smpp_server_stop();
    smpp_client_destroy();
    smpp_config_destroy();
    smpp_ratelimit_destroy();
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

    /* Route to connected SMSC client (default sim1 or based on destination) */
    smpp_client_conn_t *conn = smpp_client_find("sim1");
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
    if (!smsc || !dst || !text) {
        LM_ERR("Invalid parameters to smpp_send\n");
        return -1;
    }

    LM_INFO("smpp_send called: smsc='%s', src='%s', dst='%s', text='%s'\n",
            smsc, src ? src : "", dst, text);

    /* In-flight context update */
    smpp_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (src) strncpy(ctx.src, src, sizeof(ctx.src) - 1);
    strncpy(ctx.dst, dst, sizeof(ctx.dst) - 1);
    strncpy(ctx.body, text, sizeof(ctx.body) - 1);
    smpp_ctx_set_current(&ctx);

    smpp_client_conn_t *conn = smpp_client_find(smsc);
    if (!conn) {
        smpp_smsc_profile_t *p = smpp_config_find_smsc(smsc);
        if (p) {
            conn = smpp_client_connect(p);
        }
    }

    if (!conn) {
        LM_ERR("SMSC '%s' not found or failed to connect\n", smsc);
        return -1;
    }

    char out_msg_id[65] = {0};
    uint8_t sm_data[256];
    uint8_t sm_len = (uint8_t)strlen(text);
    if (sm_len > 255) sm_len = 255;
    memcpy(sm_data, text, sm_len);

    int rc = smpp_client_send_submit_sm(conn, src, dst, sm_data, sm_len,
                                        SMPP_ENCODING_DEFAULT, 0, NULL, out_msg_id);
    if (rc == 0) {
        LM_INFO("smpp_send success to '%s': MsgID=%s\n", smsc, out_msg_id);
        return 1;
    }

    LM_ERR("smpp_send to '%s' failed with error code %d\n", smsc, rc);
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
    LM_INFO("KEMI smpp.send: smsc='%.*s', dst='%.*s'\n", smsc->len, smsc->s, dst->len, dst->s);
    return 1;
}

static sr_kemi_t sr_kemi_smpp_exports[] = {
    {str_init("smpp"), str_init("send"),
        SR_KEMIP_INT, ki_smpp_send,
        {SR_KEMIP_STR, SR_KEMIP_STR, SR_KEMIP_STR, SR_KEMIP_STR, SR_KEMIP_NONE, SR_KEMIP_NONE}},
    {{0, 0}, {0, 0}, 0, NULL, {0, 0, 0, 0, 0, 0}}
};

int mod_register(char *path, int *dlflags, void *p1, void *p2)
{
    sr_kemi_modules_add(sr_kemi_smpp_exports);
    return 0;
}
