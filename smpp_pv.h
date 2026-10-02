/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Pseudo-Variable Engine Header
*/

#ifndef _SMPP_PV_H_
#define _SMPP_PV_H_

#include "../../core/pvar.h"

int pv_get_smpp(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_set_smpp(struct sip_msg *msg, pv_param_t *param, int flag, pv_value_t *val);
int pv_parse_smpp_name(pv_spec_p sp, str *in);

/* Global in-flight SMPP context for current script transaction */
typedef struct smpp_ctx {
    char src[64];
    char dst[64];
    char body[512];
    char msg_id[64];
    char account[32];
    uint32_t mps;
    uint8_t coding;
    uint8_t nli;
} smpp_ctx_t;

void smpp_ctx_set_current(const smpp_ctx_t *ctx);
smpp_ctx_t *smpp_ctx_get_current(void);

#endif /* _SMPP_PV_H_ */
