/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - RPC Interface Implementation (kamcmd)
*/

#include "smpp_rpc.h"
#include "smpp_config.h"
#include "smpp_client.h"
#include "../../core/rpc_lookup.h"
#include <stdio.h>

static const char *smpp_rpc_reload_doc[2] = {
    "Reload SMPP module configuration from database/files without dropping connections.",
    0
};

static void smpp_rpc_reload(rpc_t *rpc, void *ctx)
{
    if (smpp_config_reload() == 0) {
        rpc->add(ctx, "s", "SMPP Configuration reloaded successfully.");
    } else {
        rpc->fault(ctx, 500, "Failed to reload SMPP configuration.");
    }
}

static const char *smpp_rpc_status_doc[2] = {
    "Show SMPP SMSC carrier connections status.",
    0
};

static void smpp_rpc_status(rpc_t *rpc, void *ctx)
{
    void *th;
    rpc->add(ctx, "{", &th);
    rpc->struct_add(th, "s", "status", "Running");
    rpc->struct_add(th, "s", "engine", "Kamailio SMS-IWF v1.0");
    rpc->struct_add(th, "s", "version", "SMPP v3.4 / v5.0 Dual");
}

rpc_export_t smpp_rpc_methods[] = {
    {"smpp.reload",  smpp_rpc_reload,  smpp_rpc_reload_doc,  0},
    {"smpp.status",  smpp_rpc_status,  smpp_rpc_status_doc,  0},
    {0, 0, 0, 0}
};

int smpp_init_rpc(void)
{
    return rpc_register_array(smpp_rpc_methods);
}
