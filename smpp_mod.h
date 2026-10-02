/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Module Core Header
*/

#ifndef _SMPP_MOD_H_
#define _SMPP_MOD_H_

#include "../../core/sr_module.h"

extern int smpp_listen_port;
extern char *smpp_listen_ip;
extern int smpp_worker_procs;
extern int smpp_enquire_link_interval;
extern int smpp_response_timeout;
extern int smpp_reconnect_interval;
extern char *smpp_db_url;
extern int smpp_default_client_mps;
extern char *smpp_msgid_format;
extern int smpp_http_api_enable;
extern int smpp_http_api_port;
extern char *smpp_http_api_token;

#endif /* _SMPP_MOD_H_ */

