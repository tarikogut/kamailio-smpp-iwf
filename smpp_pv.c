/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Pseudo-Variable Implementation
*/

#include "smpp_pv.h"
#include <string.h>

static __thread smpp_ctx_t current_ctx;

void smpp_ctx_set_current(const smpp_ctx_t *ctx)
{
    if (ctx) {
        memcpy(&current_ctx, ctx, sizeof(smpp_ctx_t));
    } else {
        memset(&current_ctx, 0, sizeof(smpp_ctx_t));
    }
}

smpp_ctx_t *smpp_ctx_get_current(void)
{
    return &current_ctx;
}

int pv_parse_smpp_name(pv_spec_p sp, str *in)
{
    if (!sp || !in || in->len == 0) return -1;

    if (strncmp(in->s, "src", 3) == 0) {
        sp->pvp.pvn.u.isname.name.n = 1;
    } else if (strncmp(in->s, "dst", 3) == 0) {
        sp->pvp.pvn.u.isname.name.n = 2;
    } else if (strncmp(in->s, "body", 4) == 0) {
        sp->pvp.pvn.u.isname.name.n = 3;
    } else if (strncmp(in->s, "msg_id", 6) == 0) {
        sp->pvp.pvn.u.isname.name.n = 4;
    } else if (strncmp(in->s, "account", 7) == 0) {
        sp->pvp.pvn.u.isname.name.n = 5;
    } else if (strncmp(in->s, "mps", 3) == 0) {
        sp->pvp.pvn.u.isname.name.n = 6;
    } else if (strncmp(in->s, "coding", 6) == 0) {
        sp->pvp.pvn.u.isname.name.n = 7;
    } else if (strncmp(in->s, "nli", 3) == 0) {
        sp->pvp.pvn.u.isname.name.n = 8;
    } else {
        return -1;
    }

    sp->pvp.pvn.type = PV_NAME_INTSTR;
    return 0;
}

int pv_get_smpp(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
    if (!param || !res) return -1;

    smpp_ctx_t *ctx = smpp_ctx_get_current();

    switch (param->pvn.u.isname.name.n) {
    case 1: /* src */
        return pv_get_strzval(msg, param, res, ctx->src);
    case 2: /* dst */
        return pv_get_strzval(msg, param, res, ctx->dst);
    case 3: /* body */
        return pv_get_strzval(msg, param, res, ctx->body);
    case 4: /* msg_id */
        return pv_get_strzval(msg, param, res, ctx->msg_id);
    case 5: /* account */
        return pv_get_strzval(msg, param, res, ctx->account);
    case 6: /* mps */
        return pv_get_uintval(msg, param, res, ctx->mps);
    case 7: /* coding */
        return pv_get_uintval(msg, param, res, ctx->coding);
    case 8: /* nli */
        return pv_get_uintval(msg, param, res, ctx->nli);
    default:
        return pv_get_null(msg, param, res);
    }
}

int pv_set_smpp(struct sip_msg *msg, pv_param_t *param, int flag, pv_value_t *val)
{
    (void)msg;
    (void)flag;
    if (!param) return -1;
    smpp_ctx_t *ctx = smpp_ctx_get_current();

    if (!val || (val->flags & PV_VAL_NULL)) return 0;

        switch (param->pvn.u.isname.name.n) {
        case 1: /* src */
            if (val->rs.s) {
                size_t l = val->rs.len < sizeof(ctx->src) - 1 ? val->rs.len : sizeof(ctx->src) - 1;
                memcpy(ctx->src, val->rs.s, l);
                ctx->src[l] = '\0';
            }
            break;
        case 2: /* dst */
            if (val->rs.s) {
                size_t l = val->rs.len < sizeof(ctx->dst) - 1 ? val->rs.len : sizeof(ctx->dst) - 1;
                memcpy(ctx->dst, val->rs.s, l);
                ctx->dst[l] = '\0';
            }
            break;
        case 3: /* body */
            if (val->rs.s) {
                size_t l = val->rs.len < sizeof(ctx->body) - 1 ? val->rs.len : sizeof(ctx->body) - 1;
                memcpy(ctx->body, val->rs.s, l);
                ctx->body[l] = '\0';
            }
            break;
        default:
            break;
        }
    return 0;
}
