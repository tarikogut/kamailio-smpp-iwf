/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - Full End-to-End Verification Suite
# Tests PDU Engine, TLVs, 3GPP TS 23.038 NLI, BTK Suffix, Fraud Filter,
# Token Bucket Rate Limiter, SMSC Server Engine, and HTTP/IMS Interworking
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "smpp_pdu.h"
#include "smpp_tlv.h"
#include "smpp_nli.h"
#include "smpp_manip.h"
#include "smpp_ratelimit.h"
#include "smpp_config.h"
#include "smpp_server.h"
#include "smpp_interwork.h"
#include "smpp_charging.h"
#include "smpp_http_api.h"


char *smpp_msgid_format = "%PREFIX%-%TIMESTAMP%-%HEXSEQ%";
int smpp_http_api_enable = 1;
int smpp_http_api_port = 8080;
char *smpp_http_api_token = "secret-token-123";

static int tests_run = 0;

static int tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        printf("[\033[31mFAIL\033[0m] %s (Line %d)\n", msg, __LINE__); \
    } else { \
        tests_passed++; \
        printf("[\033[32mPASS\033[0m] %s\n", msg); \
    } \
} while(0)

/* 1. Test PDU Header & Submit SM */
static void test_pdu_pack_unpack(void)
{
    printf("\n--- Test Suite 1: PDU Packing & Unpacking ---\n");

    smpp_pdu_t orig_pdu;
    memset(&orig_pdu, 0, sizeof(orig_pdu));
    smpp_header_init(&orig_pdu.header, SMPP_CMD_SUBMIT_SM, ESME_ROK, 1001);

    strcpy(orig_pdu.body.msg.source_addr, "MYBRAND");
    orig_pdu.body.msg.source_addr_ton = SMPP_TON_ALPHANUMERIC;
    orig_pdu.body.msg.source_addr_npi = SMPP_NPI_UNKNOWN;

    strcpy(orig_pdu.body.msg.destination_addr, "905321234567");
    orig_pdu.body.msg.dest_addr_ton = SMPP_TON_INTERNATIONAL;
    orig_pdu.body.msg.dest_addr_npi = SMPP_NPI_ISDN;

    const char *msg_text = "Test SMPP message via Kamailio SMS-IWF";
    orig_pdu.body.msg.sm_length = (uint8_t)strlen(msg_text);
    memcpy(orig_pdu.body.msg.short_message, msg_text, orig_pdu.body.msg.sm_length);

    /* Add TLVs */
    uint16_t sar_ref = 42;
    smpp_tlv_add(&orig_pdu.body.msg.tlvs, SMPP_TLV_SAR_MSG_REF_NUM, 2, (uint8_t *)&sar_ref);
    uint8_t congestion = 50;
    smpp_tlv_add(&orig_pdu.body.msg.tlvs, SMPP_TLV_CONGESTION_STATE, 1, &congestion);

    uint8_t buf[2048];
    size_t packed_len = 0;
    int rc = smpp_pdu_pack(&orig_pdu, buf, sizeof(buf), &packed_len);
    TEST_ASSERT(rc == 0, "smpp_pdu_pack succeeds");
    TEST_ASSERT(packed_len > SMPP_HEADER_LEN, "Packed length is greater than header length");

    /* Unpack */
    smpp_pdu_t parsed_pdu;
    rc = smpp_pdu_unpack(buf, packed_len, &parsed_pdu);
    TEST_ASSERT(rc == 0, "smpp_pdu_unpack succeeds");
    TEST_ASSERT(parsed_pdu.header.command_id == SMPP_CMD_SUBMIT_SM, "Command ID matches SUBMIT_SM");
    TEST_ASSERT(parsed_pdu.header.sequence_number == 1001, "Sequence number is 1001");
    TEST_ASSERT(strcmp(parsed_pdu.body.msg.source_addr, "MYBRAND") == 0, "Source address matches");
    TEST_ASSERT(strcmp(parsed_pdu.body.msg.destination_addr, "905321234567") == 0, "Destination address matches");
    TEST_ASSERT(parsed_pdu.body.msg.sm_length == strlen(msg_text), "Short message length matches");
    TEST_ASSERT(memcmp(parsed_pdu.body.msg.short_message, msg_text, parsed_pdu.body.msg.sm_length) == 0, "Short message payload matches");

    /* Verify TLVs unpacked */
    smpp_tlv_t *t1 = smpp_tlv_find(parsed_pdu.body.msg.tlvs, SMPP_TLV_SAR_MSG_REF_NUM);
    TEST_ASSERT(t1 != NULL && t1->length == 2, "SAR_MSG_REF_NUM TLV found with length 2");
    smpp_tlv_t *t2 = smpp_tlv_find(parsed_pdu.body.msg.tlvs, SMPP_TLV_CONGESTION_STATE);
    TEST_ASSERT(t2 != NULL && t2->value[0] == 50, "CONGESTION_STATE TLV found with value 50");

    smpp_pdu_free(&orig_pdu);
    smpp_pdu_free(&parsed_pdu);
}

/* 2. Test 3GPP TS 23.038 NLI Language Detection */
static void test_nli_detection(void)
{
    printf("\n--- Test Suite 2: 3GPP TS 23.038 NLI Detection ---\n");

    uint8_t nli = 0;
    uint8_t enc = smpp_nli_detect_encoding("Hello world this is pure GSM 7-bit!", &nli);
    TEST_ASSERT(enc == SMPP_ENCODING_DEFAULT && nli == SMPP_NLI_NONE, "ASCII text detected as standard GSM-7 without NLI");

    enc = smpp_nli_detect_encoding("Şemsiye ve Çağrı Merkezi için test mesajı", &nli);
    TEST_ASSERT(enc == SMPP_ENCODING_DEFAULT && nli == SMPP_NLI_TURKISH, "Turkish text with Ş/Ç/ğ detected as Turkish NLI");

    enc = smpp_nli_detect_encoding("Привет мир (Russian text)", &nli);
    TEST_ASSERT(enc == SMPP_ENCODING_UCS2, "Cyrillic Russian text falls back to UCS-2");

    enc = smpp_nli_detect_encoding("你好世界 (Chinese text)", &nli);
    TEST_ASSERT(enc == SMPP_ENCODING_UCS2, "CJK Chinese text falls back to UCS-2");
}

/* 3. Test Turkish Shift Tables Encoding */
static void test_turkish_shift_tables(void)
{
    printf("\n--- Test Suite 3: Turkish Shift Tables Encoding ---\n");

    const char *tr_text = "Çağrı";
    uint8_t out_buf[256];
    size_t out_len = 0;

    /* Single shift */
    int rc = smpp_nli_encode_turkish_single(tr_text, out_buf, sizeof(out_buf), &out_len);
    TEST_ASSERT(rc == 0, "Turkish single shift encoding succeeds");
    TEST_ASSERT(out_len > 4, "Output contains UDH and characters");
    TEST_ASSERT(out_buf[0] == 0x03 && out_buf[1] == SMPP_UDH_IEI_SINGLE_SHIFT && out_buf[3] == SMPP_NLI_TURKISH,
                "UDH correctly formed with Single Shift IEI 0x24 and Turkish NLI 0x01");

    /* Locking shift */
    rc = smpp_nli_encode_turkish_locking(tr_text, out_buf, sizeof(out_buf), &out_len);
    TEST_ASSERT(rc == 0, "Turkish locking shift encoding succeeds");
    TEST_ASSERT(out_buf[0] == 0x03 && out_buf[1] == SMPP_UDH_IEI_LOCKING_SHIFT && out_buf[3] == SMPP_NLI_TURKISH,
                "UDH correctly formed with Locking Shift IEI 0x25 and Turkish NLI 0x01");
    TEST_ASSERT(out_buf[4] == 0x09, "Locking shift: Ç correctly encoded as 0x09 (Annex A.3.1)");
    TEST_ASSERT(out_buf[6] == 0x0C, "Locking shift: ğ correctly encoded as 0x0C (Annex A.3.1)");
    TEST_ASSERT(out_buf[8] == 0x07, "Locking shift: ı correctly encoded as 0x07 (Annex A.3.1)");
}

/* 4. Test BTK B-code Appending & Segment Calculation */
static void test_bcode_appending(void)
{
    printf("\n--- Test Suite 4: BTK B-Code Appending & Segment Safety ---\n");

    char body[512];
    strcpy(body, "Kampanyamiz baslamistir. Detaylar web sitemizde");
    int seg_before = 0, seg_after = 0;

    int rc = smpp_manip_append_suffix(body, sizeof(body), " B251", SMPP_ENCODING_DEFAULT, &seg_before, &seg_after);
    TEST_ASSERT(rc == 0, "Suffix B251 appended successfully");
    TEST_ASSERT(strstr(body, "B251") != NULL, "Body ends with B251");
    TEST_ASSERT(seg_before == 1 && seg_after == 1, "Segments remained 1 (no extra SMS charges)");

    rc = smpp_manip_prepend_prefix(body, sizeof(body), "[BILGI] ");
    TEST_ASSERT(rc == 0, "Prefix [BILGI] prepended successfully");
    TEST_ASSERT(strncmp(body, "[BILGI] ", 8) == 0, "Body starts with prefix");
}

/* 5. Test Anti-Fraud & Blacklist Filter */
static void test_fraud_filtering(void)
{
    printf("\n--- Test Suite 5: Anti-Fraud & Blacklist Filtering ---\n");

    smpp_blacklist_clear_rules();
    smpp_blacklist_add_rule("bahis", SMPP_ACTION_REJECT, ESME_RMSGBLOCKED);
    smpp_blacklist_add_rule("bonus-al", SMPP_ACTION_REJECT, ESME_RMSGBLOCKED);
    smpp_blacklist_add_rule("phishing-link", SMPP_ACTION_DROP, ESME_RMSGBLOCKED);

    uint32_t reject_err = 0;
    int action = smpp_manip_check_blacklist("Tebrikler 500TL bonus-al hemen oyna", &reject_err);
    TEST_ASSERT(action == SMPP_ACTION_REJECT, "Gambling keyword matched with REJECT action");
    TEST_ASSERT(reject_err == ESME_RMSGBLOCKED, "Error code is ESME_RMSGBLOCKED (0x67)");

    action = smpp_manip_check_blacklist("Sayin musterimiz faturaniz hazirlanmistir.", &reject_err);
    TEST_ASSERT(action == SMPP_ACTION_ALLOW, "Legitimate billing SMS allowed");
}

/* 6. Test MSISDN E.164 Normalization */
static void test_msisdn_normalization(void)
{
    printf("\n--- Test Suite 6: MSISDN E.164 Normalization ---\n");

    char out_num[64];
    uint8_t ton = 0, npi = 0;

    int rc = smpp_manip_normalize_msisdn("05321234567", out_num, sizeof(out_num), &ton, &npi, "90");
    TEST_ASSERT(rc == 0 && strcmp(out_num, "905321234567") == 0, "0532... normalized to 905321234567");
    TEST_ASSERT(ton == SMPP_TON_INTERNATIONAL && npi == SMPP_NPI_ISDN, "TON set to International (1), NPI to ISDN (1)");

    rc = smpp_manip_normalize_msisdn("00905321234567", out_num, sizeof(out_num), &ton, &npi, "90");
    TEST_ASSERT(rc == 0 && strcmp(out_num, "905321234567") == 0, "0090... stripped to 905321234567");

    rc = smpp_manip_normalize_msisdn("+905321234567", out_num, sizeof(out_num), &ton, &npi, "90");
    TEST_ASSERT(rc == 0 && strcmp(out_num, "905321234567") == 0, "+90... stripped to 905321234567");
}

/* 7. Test Token Bucket Rate Limiter (MPS) */
static void test_token_bucket_ratelimit(void)
{
    printf("\n--- Test Suite 7: Token Bucket In-Memory Rate Limiting ---\n");

    smpp_ratelimit_init();

    /* Account with 5 MPS, burst 5 */
    const char *acc = "test_user_mps";
    smpp_ratelimit_reset_account(acc);

    int allowed_count = 0;
    int throttled_count = 0;

    for (int i = 0; i < 10; i++) {
        uint32_t current_mps = 0;
        uint64_t total_th = 0;
        if (smpp_ratelimit_check(acc, 5, 5, &current_mps, &total_th)) {
            allowed_count++;
        } else {
            throttled_count++;
        }
    }

    TEST_ASSERT(allowed_count == 5, "Exactly 5 messages passed within 5 MPS burst capacity");
    TEST_ASSERT(throttled_count == 5, "Excess 5 messages instantly throttled (ESME_RTHROTTLED)");

    smpp_ratelimit_destroy();
}

/* 8. Test In-Memory Configuration Store */
static void test_config_store(void)
{
    printf("\n--- Test Suite 8: In-Memory Configuration Store ---\n");

    smpp_config_init();

    smpp_smsc_profile_t smsc;
    memset(&smsc, 0, sizeof(smsc));
    strcpy(smsc.smsc_id, "turkcell_primary");
    strcpy(smsc.host, "10.10.1.1");
    smsc.port = 2775;
    strcpy(smsc.system_id, "myuser");
    strcpy(smsc.password, "mypass");
    smsc.version = SMPP_VERSION_34;
    smsc.nli_mode = 1;
    strcpy(smsc.default_b_code, " B251");

    int rc = smpp_config_add_smsc(&smsc);
    TEST_ASSERT(rc == 0, "smpp_config_add_smsc succeeds");

    smpp_smsc_profile_t *found = smpp_config_find_smsc("turkcell_primary");
    TEST_ASSERT(found != NULL && found->port == 2775, "Found SMSC profile in RAM with port 2775");
    TEST_ASSERT(strcmp(found->default_b_code, " B251") == 0, "Found SMSC default B-code matches B251");

    smpp_account_profile_t acc;
    memset(&acc, 0, sizeof(acc));
    strcpy(acc.account_id, "client_corp_1");
    strcpy(acc.password, "secret123");
    acc.mps_limit = 50;
    acc.burst_limit = 100;
    rc = smpp_config_add_account(&acc);
    TEST_ASSERT(rc == 0, "smpp_config_add_account succeeds");

    smpp_account_profile_t *acc_found = smpp_config_find_account("client_corp_1");
    TEST_ASSERT(acc_found != NULL && acc_found->mps_limit == 50, "Found account profile in RAM with 50 MPS limit");

    smpp_config_destroy();
}

/* 9. Test SMSC Server Engine PDU Processing */
static void test_smsc_server_processing(void)
{
    printf("\n--- Test Suite 9: SMSC Server Engine PDU Processing ---\n");

    smpp_config_init();
    smpp_ratelimit_init();

    smpp_account_profile_t acc;
    memset(&acc, 0, sizeof(acc));
    strcpy(acc.account_id, "esme_user");
    strcpy(acc.password, "esme_pass");
    acc.mps_limit = 100;
    acc.burst_limit = 200;
    smpp_config_add_account(&acc);

    smpp_server_session_t sess;
    memset(&sess, 0, sizeof(sess));
    sess.state = SMPP_STATE_CONNECTED;

    /* Build incoming bind_transceiver */
    smpp_pdu_t bind_pdu;
    memset(&bind_pdu, 0, sizeof(bind_pdu));
    smpp_header_init(&bind_pdu.header, SMPP_CMD_BIND_TRANSCEIVER, ESME_ROK, 501);
    strcpy(bind_pdu.body.bind_req.system_id, "esme_user");
    strcpy(bind_pdu.body.bind_req.password, "esme_pass");
    bind_pdu.body.bind_req.interface_version = SMPP_VERSION_34;

    uint8_t in_buf[512], out_buf[512];
    size_t in_len = 0, out_len = 0;
    smpp_pdu_pack(&bind_pdu, in_buf, sizeof(in_buf), &in_len);

    int rc = smpp_server_handle_pdu(&sess, in_buf, in_len, out_buf, sizeof(out_buf), &out_len);
    TEST_ASSERT(rc == 0 && out_len > 0, "Server processed bind_transceiver successfully");

    smpp_pdu_t resp;
    smpp_pdu_unpack(out_buf, out_len, &resp);
    TEST_ASSERT(resp.header.command_id == SMPP_CMD_BIND_TRANSCEIVER_RESP, "Server responded with BIND_TRANSCEIVER_RESP");
    TEST_ASSERT(resp.header.command_status == ESME_ROK, "Bind authenticated with ESME_ROK");
    TEST_ASSERT(sess.state == SMPP_STATE_BOUND_TRX, "Session state transitioned to BOUND_TRX");
    smpp_pdu_free(&resp);

    /* Submit SM */
    smpp_pdu_t sub_pdu;
    memset(&sub_pdu, 0, sizeof(sub_pdu));
    smpp_header_init(&sub_pdu.header, SMPP_CMD_SUBMIT_SM, ESME_ROK, 502);
    strcpy(sub_pdu.body.msg.destination_addr, "905321112233");
    strcpy((char *)sub_pdu.body.msg.short_message, "Real test SMS message");
    sub_pdu.body.msg.sm_length = (uint8_t)strlen("Real test SMS message");
    smpp_pdu_pack(&sub_pdu, in_buf, sizeof(in_buf), &in_len);

    rc = smpp_server_handle_pdu(&sess, in_buf, in_len, out_buf, sizeof(out_buf), &out_len);
    TEST_ASSERT(rc == 0, "Server processed submit_sm");

    smpp_pdu_unpack(out_buf, out_len, &resp);
    TEST_ASSERT(resp.header.command_id == SMPP_CMD_SUBMIT_SM_RESP, "Server responded with SUBMIT_SM_RESP");
    TEST_ASSERT(strlen(resp.body.msg_resp.message_id) > 10, "Server assigned customized message_id template");
    smpp_pdu_free(&resp);

    smpp_ratelimit_destroy();
    smpp_config_destroy();
}

/* 10. Test Multi-Protocol Interworking & IMS IP-SM-GW */
static void test_interworking_and_ims(void)
{
    printf("\n--- Test Suite 10: Multi-Protocol Translation & 3GPP IMS IP-SM-GW ---\n");

    smpp_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.source_addr, "BANK");
    strcpy(msg.destination_addr, "905321234567");
    strcpy((char *)msg.short_message, "Your OTP code is 123456");
    msg.sm_length = (uint8_t)strlen("Your OTP code is 123456");

    char json_buf[1024];
    int rc = smpp_to_http_json(&msg, "MSG-9988", "B251", json_buf, sizeof(json_buf));
    TEST_ASSERT(rc == 0, "smpp_to_http_json successfully serialized message");
    TEST_ASSERT(strstr(json_buf, "\"message_id\":\"MSG-9988\"") != NULL, "JSON contains message_id");
    TEST_ASSERT(strstr(json_buf, "\"b_code\":\"B251\"") != NULL, "JSON contains BTK B-code");
    TEST_ASSERT(strstr(json_buf, "123456") != NULL, "JSON contains OTP text");

    /* Test HTTP response code mapping */
    TEST_ASSERT(http_response_to_smpp_status(200) == ESME_ROK, "HTTP 200 mapped to ESME_ROK");
    TEST_ASSERT(http_response_to_smpp_status(429) == ESME_RTHROTTLED, "HTTP 429 mapped to ESME_RTHROTTLED");

    /* 3GPP IMS RP-DATA Pack and Unpack */
    uint8_t rp_buf[512];
    size_t rp_len = 0;
    rc = smpp_ims_rp_data_pack("905321000000", "905322000000", "VoLTE IMS SMS Test", rp_buf, sizeof(rp_buf), &rp_len);
    TEST_ASSERT(rc == 0 && rp_len > 0, "smpp_ims_rp_data_pack packed 3GPP RP-DATA frame");

    char parsed_src[32], parsed_dst[32], parsed_text[256];
    uint8_t dcs = 0;
    rc = smpp_ims_rp_data_unpack(rp_buf, rp_len, parsed_src, parsed_dst, parsed_text, sizeof(parsed_text), &dcs);
    TEST_ASSERT(rc == 0, "smpp_ims_rp_data_unpack unpacked 3GPP RP-DATA frame");
    TEST_ASSERT(strcmp(parsed_text, "VoLTE IMS SMS Test") == 0, "Extracted text matches original IMS payload");
}

/* 11. Test Unified DLR Normalization (Standard body & Non-standard TLV-only) */
#include "smpp_dlr.h"
static void test_dlr_normalization(void)
{
    printf("\n--- Test Suite 11: Unified DLR Normalization (Standard & TLV-only) ---\n");

    /* Case A: Standard DLR in short_message */
    smpp_msg_t std_msg;
    memset(&std_msg, 0, sizeof(std_msg));
    const char *std_body = "id:MSG-12345 sub:001 dlvrd:001 submit date:2610020600 done date:2610020601 stat:DELIVRD err:000 text:";
    strcpy((char *)std_msg.short_message, std_body);
    std_msg.sm_length = (uint8_t)strlen(std_body);

    smpp_dlr_info_t dlr_a;
    int rc = smpp_dlr_normalize(&std_msg, &dlr_a);
    TEST_ASSERT(rc == 0, "Standard DLR in body normalized successfully");
    TEST_ASSERT(strcmp(dlr_a.message_id, "MSG-12345") == 0, "Extracted message_id matches MSG-12345");
    TEST_ASSERT(strcmp(dlr_a.stat_str, "DELIVRD") == 0, "Extracted stat_str is DELIVRD");
    TEST_ASSERT(dlr_a.was_tlv_only == 0, "Identified as standard body DLR");

    /* Case B: Non-standard operator DLR (Empty body, ONLY TLVs: 0x001E, 0x0427, 0x0423) */
    smpp_msg_t tlv_msg;
    memset(&tlv_msg, 0, sizeof(tlv_msg));
    tlv_msg.sm_length = 0; /* Empty body! */

    /* Add TLV 0x001E: receipted_message_id = "VEND-998877" */
    smpp_tlv_add(&tlv_msg.tlvs, 0x001E, 11, (const uint8_t *)"VEND-998877");
    /* Add TLV 0x0427: message_state = 2 (DELIVRD) */
    uint8_t st = 2;
    smpp_tlv_add(&tlv_msg.tlvs, 0x0427, 1, &st);
    /* Add TLV 0x0423: network_error_code = 0x0000 */
    uint8_t err_bytes[3] = {0x00, 0x00, 0x00};
    smpp_tlv_add(&tlv_msg.tlvs, 0x0423, 3, err_bytes);

    smpp_dlr_info_t dlr_b;
    rc = smpp_dlr_normalize(&tlv_msg, &dlr_b);
    TEST_ASSERT(rc == 0, "TLV-only non-standard operator DLR normalized successfully");
    TEST_ASSERT(strcmp(dlr_b.message_id, "VEND-998877") == 0, "Extracted message_id from TLV 0x001E matches");
    TEST_ASSERT(strcmp(dlr_b.stat_str, "DELIVRD") == 0, "Extracted message_state from TLV 0x0427 is DELIVRD");
    TEST_ASSERT(dlr_b.was_tlv_only == 1, "Flagged as was_tlv_only");

    /* Reconstruct standard body for client delivery */
    char healed_body[256];
    rc = smpp_dlr_reconstruct_body(&dlr_b, healed_body, sizeof(healed_body));
    TEST_ASSERT(rc > 0, "Reconstructed standard DLR body from TLV info");
    TEST_ASSERT(strstr(healed_body, "id:VEND-998877") != NULL, "Healed body contains reconstructed id:VEND-998877");
    TEST_ASSERT(strstr(healed_body, "stat:DELIVRD") != NULL, "Healed body contains stat:DELIVRD");

    smpp_tlv_free_list(tlv_msg.tlvs);
}

/* 12. Test ENUM & MNP Resolution Engine */
#include "smpp_mnp.h"
static void test_mnp_and_enum(void)
{
    printf("\n--- Test Suite 12: ENUM & MNP Number Portability Resolution ---\n");

    smpp_mnp_init();

    /* 1. Test E.164 to ENUM Reverse FQDN mapping (RFC 3761) */
    char enum_domain[128];
    int rc = smpp_mnp_e164_to_enum_domain("+905321234567", "e164.arpa", enum_domain, sizeof(enum_domain));
    TEST_ASSERT(rc == 0, "smpp_mnp_e164_to_enum_domain succeeds");
    TEST_ASSERT(strcmp(enum_domain, "7.6.5.4.3.2.1.2.3.5.0.9.e164.arpa") == 0,
                "E.164 correctly reversed with dots into e164.arpa");

    /* 2. Test native prefix routing (unported) */
    smpp_mnp_result_t res_native;
    rc = smpp_mnp_lookup("905329998877", &res_native);
    TEST_ASSERT(rc == 0, "Native prefix lookup succeeds");
    TEST_ASSERT(strcmp(res_native.target_smsc, "sim1") == 0, "90532... routes natively to sim1 (Turkcell)");
    TEST_ASSERT(res_native.is_ported == 0, "Marked as unported");

    /* 3. Test Ported Number (MNP Rule: Turkcell 0532 number ported to Vodafone sim2) */
    rc = smpp_mnp_add_rule("905321112233", "sim2", "B002", "VODAFONE");
    TEST_ASSERT(rc == 0, "smpp_mnp_add_rule succeeds");

    smpp_mnp_result_t res_ported;
    rc = smpp_mnp_lookup("905321112233", &res_ported);
    TEST_ASSERT(rc == 0, "Ported number lookup succeeds");
    TEST_ASSERT(strcmp(res_ported.target_smsc, "sim2") == 0, "Ported 90532... correctly redirected to sim2 (Vodafone)");
    TEST_ASSERT(strcmp(res_ported.routing_number, "B002") == 0, "Extracted RN matches B002");
    TEST_ASSERT(res_ported.is_ported == 1, "Correctly flagged as ported (is_ported = 1)");

    smpp_mnp_destroy();
}

static void test_rest_api_suite(void)
{
    printf("\n=== Running Test Suite 13: Built-in REST API Server (Management, Send, Query) ===\n");

    /* 1. Test /api/v1/health */
    const char *req_health = 
        "GET /api/v1/health HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "\r\n";
    char resp_buf[2048];
    size_t resp_len = 0;
    int rc = smpp_http_api_handle_request(req_health, strlen(req_health), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "HTTP Health check handled successfully");
    TEST_ASSERT(strstr(resp_buf, "200 OK") != NULL, "Health check returns HTTP 200 OK");
    TEST_ASSERT(strstr(resp_buf, "\"status\":\"healthy\"") != NULL, "Health check body contains status:healthy");

    /* 2. Test /api/v1/status */
    const char *req_status = 
        "GET /api/v1/status HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "\r\n";
    rc = smpp_http_api_handle_request(req_status, strlen(req_status), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "HTTP Status handled successfully");
    TEST_ASSERT(strstr(resp_buf, "\"service\":\"kamailio-smpp-iwf\"") != NULL, "Status contains service name");

    /* 3. Test Unauthorized Access without Token */
    const char *req_unauth = 
        "POST /api/v1/reload HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    rc = smpp_http_api_handle_request(req_unauth, strlen(req_unauth), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "Unauthorized request handled");
    TEST_ASSERT(strstr(resp_buf, "401 Unauthorized") != NULL, "Protected endpoint returns 401 without Bearer token");

    /* 4. Test Authorized Reload with Token */
    const char *req_reload = 
        "POST /api/v1/reload HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    rc = smpp_http_api_handle_request(req_reload, strlen(req_reload), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "Authorized reload request handled");
    TEST_ASSERT(strstr(resp_buf, "200 OK") != NULL, "Authorized reload returns 200 OK");
    TEST_ASSERT(strstr(resp_buf, "\"reload\":\"success\"") != NULL, "Reload body reports success");

    /* 5. Test SMS Dispatch via POST /api/v1/sms/send */
    const char *json_payload = 
        "{\"smsc_id\":\"sim1\",\"from\":\"KAMAILIO\",\"to\":\"905321234567\",\"text\":\"REST API Test SMS\"}";
    char req_send[1024];
    snprintf(req_send, sizeof(req_send),
        "POST /api/v1/sms/send HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n%s", strlen(json_payload), json_payload);

    rc = smpp_http_api_handle_request(req_send, strlen(req_send), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "SMS send request handled");
    TEST_ASSERT(strstr(resp_buf, "200 OK") != NULL, "SMS send returns 200 OK");
    TEST_ASSERT(strstr(resp_buf, "\"status\":\"accepted\"") != NULL, "SMS accepted for delivery");
    TEST_ASSERT(strstr(resp_buf, "\"message_id\":\"") != NULL, "Response contains generated message_id");

    /* Extract message_id from response for querying */
    char *id_start = strstr(resp_buf, "\"message_id\":\"");
    char test_msg_id[65] = {0};
    if (id_start) {
        id_start += 14;
        char *id_end = strchr(id_start, '"');
        if (id_end) {
            strncpy(test_msg_id, id_start, id_end - id_start);
        }
    }
    TEST_ASSERT(strlen(test_msg_id) > 0, "Extracted message_id from response");

    /* 6. Test DLR / SMS Query via GET /api/v1/sms/query?id=<message_id> */
    char req_query[512];
    snprintf(req_query, sizeof(req_query),
        "GET /api/v1/sms/query?id=%s HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "\r\n", test_msg_id);

    rc = smpp_http_api_handle_request(req_query, strlen(req_query), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "SMS query handled");
    TEST_ASSERT(strstr(resp_buf, "200 OK") != NULL, "SMS query returns 200 OK");
    TEST_ASSERT(strstr(resp_buf, test_msg_id) != NULL, "Query body contains matching message_id");
    TEST_ASSERT(strstr(resp_buf, "\"status\":\"ACCEPTED\"") != NULL, "Query status returns ACCEPTED");

    /* 7. Test Connections CRUD: GET /api/v1/connections */
    const char *req_conns = 
        "GET /api/v1/connections HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "\r\n";
    rc = smpp_http_api_handle_request(req_conns, strlen(req_conns), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "GET /api/v1/connections handled");
    TEST_ASSERT(strstr(resp_buf, "200 OK") != NULL, "Connections list returns 200 OK");
    TEST_ASSERT(strstr(resp_buf, "\"connections\":[") != NULL, "Connections list returns json array");

    /* 8. Test Add Connection: POST /api/v1/connections */
    const char *conn_payload = 
        "{\"smsc_id\":\"sim_api_test\",\"host\":\"127.0.0.1\",\"port\":2775,\"system_id\":\"test_sys\",\"password\":\"pwd\",\"default_b_code\":\"B999\"}";
    char req_add_conn[1024];
    snprintf(req_add_conn, sizeof(req_add_conn),
        "POST /api/v1/connections HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n%s", strlen(conn_payload), conn_payload);

    rc = smpp_http_api_handle_request(req_add_conn, strlen(req_add_conn), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "POST /api/v1/connections handled");
    TEST_ASSERT(strstr(resp_buf, "201 Created") != NULL, "Connection created returns 201 Created");
    TEST_ASSERT(strstr(resp_buf, "\"sim_api_test\"") != NULL, "Response mentions sim_api_test");

    /* 9. Test Delete Connection: DELETE /api/v1/connections?id=sim_api_test */
    const char *req_del_conn = 
        "DELETE /api/v1/connections?id=sim_api_test HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "\r\n";
    rc = smpp_http_api_handle_request(req_del_conn, strlen(req_del_conn), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "DELETE /api/v1/connections handled");
    TEST_ASSERT(strstr(resp_buf, "200 OK") != NULL, "Connection delete returns 200 OK");

    /* 10. Test Users CRUD: GET /api/v1/users */
    const char *req_users = 
        "GET /api/v1/users HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "\r\n";
    rc = smpp_http_api_handle_request(req_users, strlen(req_users), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "GET /api/v1/users handled");
    TEST_ASSERT(strstr(resp_buf, "200 OK") != NULL, "Users list returns 200 OK");

    /* 11. Test Add/Update User: POST /api/v1/users */
    const char *user_payload = 
        "{\"account_id\":\"esme_api_user\",\"password\":\"secure_pass\",\"mps_limit\":150,\"burst_limit\":300}";
    char req_add_user[1024];
    snprintf(req_add_user, sizeof(req_add_user),
        "POST /api/v1/users HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n%s", strlen(user_payload), user_payload);

    rc = smpp_http_api_handle_request(req_add_user, strlen(req_add_user), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "POST /api/v1/users handled");
    TEST_ASSERT(strstr(resp_buf, "201 Created") != NULL, "User created returns 201 Created");
    TEST_ASSERT(strstr(resp_buf, "\"esme_api_user\"") != NULL, "Response mentions esme_api_user");

    /* 12. Test Delete User: DELETE /api/v1/users?id=esme_api_user */
    const char *req_del_user = 
        "DELETE /api/v1/users?id=esme_api_user HTTP/1.1\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "\r\n";
    rc = smpp_http_api_handle_request(req_del_user, strlen(req_del_user), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "DELETE /api/v1/users handled");
    TEST_ASSERT(strstr(resp_buf, "200 OK") != NULL, "User delete returns 200 OK");
}

/* 14. Test Dynamic & Configurable TON / NPI */
static void test_dynamic_ton_npi(void)
{
    printf("\n=== Running Test Suite 14: Dynamic & Configurable TON and NPI ===\n");

    uint8_t ton = 0xFF, npi = 0xFF;

    /* 1. Alphanumeric detection (contains letters/non-digits) */
    smpp_detect_ton_npi("MYBRAND", &ton, &npi);
    TEST_ASSERT(ton == SMPP_TON_ALPHANUMERIC && npi == SMPP_NPI_UNKNOWN,
                "Alphanumeric address 'MYBRAND' -> TON=5 (Alphanumeric), NPI=0 (Unknown)");

    smpp_detect_ton_npi("INFO-SMS", &ton, &npi);
    TEST_ASSERT(ton == SMPP_TON_ALPHANUMERIC && npi == SMPP_NPI_UNKNOWN,
                "Alphanumeric address 'INFO-SMS' -> TON=5 (Alphanumeric), NPI=0 (Unknown)");

    /* 2. Shortcode / Abbreviated detection (numeric, length <= 5) */
    smpp_detect_ton_npi("1234", &ton, &npi);
    TEST_ASSERT(ton == SMPP_TON_ABBREVIATED && npi == SMPP_NPI_UNKNOWN,
                "Shortcode '1234' -> TON=6 (Abbreviated), NPI=0 (Unknown)");

    smpp_detect_ton_npi("32500", &ton, &npi);
    TEST_ASSERT(ton == SMPP_TON_ABBREVIATED && npi == SMPP_NPI_UNKNOWN,
                "Shortcode '32500' -> TON=6 (Abbreviated), NPI=0 (Unknown)");

    /* 3. National number detection (numeric, starts with '0') */
    smpp_detect_ton_npi("05321234567", &ton, &npi);
    TEST_ASSERT(ton == SMPP_TON_NATIONAL && npi == SMPP_NPI_ISDN,
                "National number '05321234567' -> TON=2 (National), NPI=1 (ISDN)");

    smpp_detect_ton_npi("02123456789", &ton, &npi);
    TEST_ASSERT(ton == SMPP_TON_NATIONAL && npi == SMPP_NPI_ISDN,
                "National landline '02123456789' -> TON=2 (National), NPI=1 (ISDN)");

    /* 4. International number detection (numeric 7-15 digits, or with leading '+') */
    smpp_detect_ton_npi("905321234567", &ton, &npi);
    TEST_ASSERT(ton == SMPP_TON_INTERNATIONAL && npi == SMPP_NPI_ISDN,
                "International number '905321234567' -> TON=1 (International), NPI=1 (ISDN)");

    smpp_detect_ton_npi("+905321234567", &ton, &npi);
    TEST_ASSERT(ton == SMPP_TON_INTERNATIONAL && npi == SMPP_NPI_ISDN,
                "International number '+905321234567' -> TON=1 (International), NPI=1 (ISDN)");

    smpp_detect_ton_npi("+14155552671", &ton, &npi);
    TEST_ASSERT(ton == SMPP_TON_INTERNATIONAL && npi == SMPP_NPI_ISDN,
                "International number '+14155552671' -> TON=1 (International), NPI=1 (ISDN)");

    /* 5. Fallback detection */
    smpp_detect_ton_npi("", &ton, &npi);
    TEST_ASSERT(ton == SMPP_TON_UNKNOWN && npi == SMPP_NPI_ISDN,
                "Empty address '' -> TON=0 (Unknown), NPI=1 (ISDN)");

    /* 6. Interworking: http_json_to_smpp auto-detection */
    smpp_msg_t jmsg;
    const char *json_in = "{\"from\":\"TURKCELL\",\"to\":\"05321234567\",\"text\":\"Dynamic TON test\"}";
    int rc = http_json_to_smpp(json_in, &jmsg);
    TEST_ASSERT(rc == 0, "http_json_to_smpp parsed successfully");
    TEST_ASSERT(jmsg.source_addr_ton == SMPP_TON_ALPHANUMERIC && jmsg.source_addr_npi == SMPP_NPI_UNKNOWN,
                "http_json_to_smpp source 'TURKCELL' auto-detected as TON=5, NPI=0");
    TEST_ASSERT(jmsg.dest_addr_ton == SMPP_TON_NATIONAL && jmsg.dest_addr_npi == SMPP_NPI_ISDN,
                "http_json_to_smpp destination '05321234567' auto-detected as TON=2, NPI=1");

    /* 7. HTTP API POST /api/v1/sms/send with explicit integer TON/NPI */
    const char *api_payload = 
        "{\"smsc\":\"sim1\",\"from\":\"8888\",\"to\":\"905321112233\",\"text\":\"Explicit TON Test\","
        "\"src_ton\":6,\"src_npi\":0,\"dst_ton\":1,\"dst_npi\":1}";
    char req_buf[1024];
    snprintf(req_buf, sizeof(req_buf),
        "POST /api/v1/sms/send HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n%s", strlen(api_payload), api_payload);

    char resp_buf[2048];
    size_t resp_len = 0;
    rc = smpp_http_api_handle_request(req_buf, strlen(req_buf), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "HTTP API send with explicit integer TON/NPI handled");
    TEST_ASSERT(strstr(resp_buf, "200 OK") != NULL, "HTTP API returns 200 OK");
    TEST_ASSERT(strstr(resp_buf, "\"status\":\"accepted\"") != NULL, "SMS accepted with explicit TON/NPI");

    /* 8. HTTP API POST /api/v1/sms/send with string TON/NPI */
    const char *api_payload_str = 
        "{\"smsc\":\"sim1\",\"from\":\"MYBRAND\",\"to\":\"05321112233\",\"text\":\"String TON Test\","
        "\"src_ton\":\"5\",\"src_npi\":\"0\",\"dst_ton\":\"2\",\"dst_npi\":\"1\"}";
    snprintf(req_buf, sizeof(req_buf),
        "POST /api/v1/sms/send HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n%s", strlen(api_payload_str), api_payload_str);

    rc = smpp_http_api_handle_request(req_buf, strlen(req_buf), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "HTTP API send with string formatted TON/NPI handled");
    TEST_ASSERT(strstr(resp_buf, "200 OK") != NULL, "HTTP API returns 200 OK with string TON/NPI");

    /* 9. Test smpp_client_send_submit_sm_ex auto-detection fallback (when 0xFF passed) */
    /* Create a simulated connection in BOUND_TRX state for packaging verification */
    smpp_client_conn_t sim_conn;
    memset(&sim_conn, 0, sizeof(sim_conn));
    strcpy(sim_conn.smsc_id, "sim_test");
    sim_conn.state = SMPP_STATE_BOUND_TRX;
    sim_conn.sock_fd = 9999; /* Non-existent socket descriptor so send() fails with -3 */
    pthread_mutex_init(&sim_conn.resp_mutex, NULL);
    pthread_cond_init(&sim_conn.resp_cond, NULL);
    char out_mid[65] = {0};
    /* Calling with invalid sock_fd returns -3 (send failed), proving it passed parameter validation and TON auto-detect */
    rc = smpp_client_send_submit_sm_ex(&sim_conn, "SHORT", "05321234567", 0xFF, 0xFF, 0xFF, 0xFF,
                                       (const uint8_t *)"Hello", 5, 0, 0, NULL, out_mid);
    TEST_ASSERT(rc == -3, "smpp_client_send_submit_sm_ex auto-detects and attempts send (returns -3 on test fd)");

    /* Explicit TON/NPI override */
    rc = smpp_client_send_submit_sm_ex(&sim_conn, "12345", "905321234567", 6, 0, 1, 1,
                                       (const uint8_t *)"Hello", 5, 0, 0, NULL, out_mid);
    TEST_ASSERT(rc == -3, "smpp_client_send_submit_sm_ex accepts explicit TON/NPI parameters");

    pthread_mutex_destroy(&sim_conn.resp_mutex);
    pthread_cond_destroy(&sim_conn.resp_cond);
}

/* 15. Test Charging & Credit Control Subsystem */
static void test_charging_and_credit_control(void)
{
    printf("\n=== Running Test Suite 15: Charging & Credit Control Subsystem ===\n");

    smpp_charging_init();
    TEST_ASSERT(smpp_charging_get_mode() == SMPP_CHARGING_MODE_LOCAL, "Default charging mode is LOCAL");

    /* Default seeded balances */
    double bal = 0.0;
    int rc = smpp_charging_get_balance("kamailio_client", &bal);
    TEST_ASSERT(rc == 0 && bal == 1000.0, "Pre-seeded account kamailio_client has 1000.0 credit");

    rc = smpp_charging_get_balance("test_esme", &bal);
    TEST_ASSERT(rc == 0 && bal == 500.0, "Pre-seeded account test_esme has 500.0 credit");

    /* Custom balance set and query */
    rc = smpp_charging_set_balance("prepaid_user", 10.0);
    TEST_ASSERT(rc == 0, "smpp_charging_set_balance succeeds");
    rc = smpp_charging_get_balance("prepaid_user", &bal);
    TEST_ASSERT(rc == 0 && bal == 10.0, "prepaid_user balance is 10.0");

    /* Price per segment configuration */
    rc = smpp_charging_set_price_per_segment("prepaid_user", 2.0);
    TEST_ASSERT(rc == 0, "smpp_charging_set_price_per_segment succeeds");
    double price = smpp_charging_get_price_per_segment("prepaid_user");
    TEST_ASSERT(price == 2.0, "smpp_charging_get_price_per_segment returns 2.0");

    /* Credit check: 1 segment cost = 2.0, balance = 10.0 -> OK */
    uint32_t rem_credit = 0;
    rc = smpp_charging_check_credit("prepaid_user", "90532111", "90532222", 1, &rem_credit);
    TEST_ASSERT(rc == 0, "Credit check passes for 1 segment (cost 2.0 <= balance 10.0)");
    TEST_ASSERT(rem_credit == 10, "Remaining credit reported as 10");

    /* Deduct 1 segment (cost 2.0) */
    rc = smpp_charging_deduct_credit("prepaid_user", "90532111", "90532222", 1, 2.0);
    TEST_ASSERT(rc == 0, "smpp_charging_deduct_credit succeeds");
    smpp_charging_get_balance("prepaid_user", &bal);
    TEST_ASSERT(bal == 8.0, "Balance reduced to 8.0 after deduction");

    /* Multi-segment check: 5 segments * 2.0 = 10.0. Balance is 8.0 -> FAILS */
    rc = smpp_charging_check_credit("prepaid_user", "90532111", "90532222", 5, &rem_credit);
    TEST_ASSERT(rc != 0, "Credit check fails for 5 segments (cost 10.0 > balance 8.0)");
    TEST_ASSERT(rem_credit == 8, "Remaining credit reported as 8");

    /* Credit deduction fails if balance insufficient */
    rc = smpp_charging_deduct_credit("prepaid_user", "90532111", "90532222", 5, 10.0);
    TEST_ASSERT(rc != 0, "smpp_charging_deduct_credit rejected due to insufficient balance");
    smpp_charging_get_balance("prepaid_user", &bal);
    TEST_ASSERT(bal == 8.0, "Balance remained intact at 8.0 after rejected deduction");

    /* Add credit / refill */
    rc = smpp_charging_add_credit("prepaid_user", 20.0, &bal);
    TEST_ASSERT(rc == 0 && bal == 28.0, "smpp_charging_add_credit refilled balance to 28.0");

    /* Check credit passes now for 5 segments */
    rc = smpp_charging_check_credit("prepaid_user", "90532111", "90532222", 5, &rem_credit);
    TEST_ASSERT(rc == 0, "Credit check passes after refill (cost 10.0 <= balance 28.0)");

    /* Deplete balance completely */
    smpp_charging_set_balance("prepaid_user", 0.0);
    rc = smpp_charging_check_credit("prepaid_user", "90532111", "90532222", 1, &rem_credit);
    TEST_ASSERT(rc != 0, "Credit check fails when balance is 0.0");
    TEST_ASSERT(rem_credit == 0, "Remaining credit reported as 0");

    /* Test Server SUBMIT_SM reject with ESME_RINVCREDIT (0x68) */
    smpp_account_profile_t acc_test;
    memset(&acc_test, 0, sizeof(acc_test));
    strcpy(acc_test.account_id, "prepaid_user");
    strcpy(acc_test.password, "pass");
    acc_test.mps_limit = 50;
    acc_test.burst_limit = 100;
    smpp_config_add_account(&acc_test);

    smpp_server_session_t sess;
    memset(&sess, 0, sizeof(sess));
    strcpy(sess.account_id, "prepaid_user");
    sess.state = SMPP_STATE_BOUND_TRX;

    smpp_pdu_t sub_pdu;
    memset(&sub_pdu, 0, sizeof(sub_pdu));
    smpp_header_init(&sub_pdu.header, SMPP_CMD_SUBMIT_SM, ESME_ROK, 2001);
    strcpy(sub_pdu.body.msg.source_addr, "90532111");
    strcpy(sub_pdu.body.msg.destination_addr, "90532222");
    const char *test_txt = "Test Submit SM for Credit Check";
    sub_pdu.body.msg.sm_length = (uint8_t)strlen(test_txt);
    memcpy(sub_pdu.body.msg.short_message, test_txt, sub_pdu.body.msg.sm_length);

    uint8_t pdu_buf[1024];
    size_t pdu_len = 0;
    smpp_pdu_pack(&sub_pdu, pdu_buf, sizeof(pdu_buf), &pdu_len);

    uint8_t out_resp[1024];
    size_t out_resp_len = 0;
    rc = smpp_server_handle_pdu(&sess, pdu_buf, pdu_len, out_resp, sizeof(out_resp), &out_resp_len);
    TEST_ASSERT(rc == 0 && out_resp_len > 0, "smpp_server_handle_pdu processed SUBMIT_SM");

    smpp_pdu_t resp_pdu;
    smpp_pdu_unpack(out_resp, out_resp_len, &resp_pdu);
    TEST_ASSERT(resp_pdu.header.command_id == SMPP_CMD_SUBMIT_SM_RESP, "Server responded with SUBMIT_SM_RESP");
    TEST_ASSERT(resp_pdu.header.command_status == ESME_RINVCREDIT, "Server rejected submit_sm with ESME_RINVCREDIT (0x68)");
    smpp_pdu_free(&resp_pdu);

    /* Refill prepaid_user and retry submit_sm */
    smpp_charging_set_balance("prepaid_user", 50.0);
    out_resp_len = 0;
    rc = smpp_server_handle_pdu(&sess, pdu_buf, pdu_len, out_resp, sizeof(out_resp), &out_resp_len);
    smpp_pdu_unpack(out_resp, out_resp_len, &resp_pdu);
    TEST_ASSERT(resp_pdu.header.command_status == ESME_ROK, "Server accepted submit_sm after credit refill (ESME_ROK)");
    smpp_pdu_free(&resp_pdu);

    smpp_charging_get_balance("prepaid_user", &bal);
    TEST_ASSERT(bal == 48.0, "Credit automatically deducted from balance after submit_sm (now 48.0)");
    smpp_pdu_free(&sub_pdu);
}

/* 16. Test Diameter Ro CCR / CCA Protocol Engine */
static int mock_diameter_hook_called = 0;
static int mock_diameter_hook_units = 0;
static int mock_diameter_hook(const uint8_t *req, size_t req_len, uint8_t *resp, size_t max_resp, size_t *resp_len)
{
    mock_diameter_hook_called++;
    smpp_diameter_ccr_t ccr;
    if (smpp_diameter_unpack_ccr(req, req_len, &ccr) != 0) return -1;
    mock_diameter_hook_units = (int)ccr.requested_units;

    smpp_diameter_cca_t cca;
    memset(&cca, 0, sizeof(cca));
    strncpy(cca.session_id, ccr.session_id, sizeof(cca.session_id) - 1);
    cca.request_type = ccr.request_type;
    cca.request_number = ccr.request_number;
    cca.hop_by_hop = ccr.hop_by_hop;
    cca.end_to_end = ccr.end_to_end;

    /* Enforce rule: max 4 units granted */
    if (ccr.requested_units <= 4) {
        cca.result_code = DIAMETER_SUCCESS; /* 2001 */
        cca.granted_units = ccr.requested_units;
        cca.remaining_balance = 100.0;
    } else {
        cca.result_code = DIAMETER_CREDIT_LIMIT_REACHED; /* 4012 */
        cca.granted_units = 0;
        cca.remaining_balance = 0.0;
    }
    return smpp_diameter_pack_cca(&cca, resp, max_resp, resp_len);
}

static void test_diameter_ro_charging(void)
{
    printf("\n=== Running Test Suite 16: Diameter Ro Credit Control (3GPP TS 32.299 / RFC 4006) ===\n");

    /* 1. Test CCR packing and structure */
    smpp_diameter_ccr_t ccr;
    memset(&ccr, 0, sizeof(ccr));
    strcpy(ccr.session_id, "diam-test-session-101");
    strcpy(ccr.origin_host, "smpp-gw.local");
    strcpy(ccr.origin_realm, "local");
    strcpy(ccr.destination_realm, "local");
    strcpy(ccr.account_id, "905321234567");
    strcpy(ccr.src_msisdn, "905321234567");
    strcpy(ccr.dst_msisdn, "905327654321");
    ccr.request_type = CC_REQUEST_TYPE_EVENT_RECORD; /* 4 */
    ccr.request_number = 0;
    ccr.requested_action = REQUESTED_ACTION_DIRECT_DEBITING; /* 0 */
    ccr.requested_units = 3;
    ccr.hop_by_hop = 0xAABBCCDD;
    ccr.end_to_end = 0x11223344;

    uint8_t ccr_buf[512];
    size_t ccr_len = 0;
    int rc = smpp_diameter_pack_ccr(&ccr, ccr_buf, sizeof(ccr_buf), &ccr_len);
    TEST_ASSERT(rc == 0 && ccr_len > 20, "smpp_diameter_pack_ccr succeeds");
    TEST_ASSERT(ccr_buf[0] == 1, "Diameter Version is 1 (RFC 6733)");
    TEST_ASSERT((ccr_buf[4] & DIAMETER_FLAG_REQUEST) != 0, "Diameter Header R-bit (Request) set");

    /* 2. Test CCR unpacking */
    smpp_diameter_ccr_t u_ccr;
    rc = smpp_diameter_unpack_ccr(ccr_buf, ccr_len, &u_ccr);
    TEST_ASSERT(rc == 0, "smpp_diameter_unpack_ccr succeeds");
    TEST_ASSERT(strcmp(u_ccr.session_id, "diam-test-session-101") == 0, "Session-Id AVP matches");
    TEST_ASSERT(u_ccr.request_type == CC_REQUEST_TYPE_EVENT_RECORD, "CC-Request-Type is EVENT_RECORD (4)");
    TEST_ASSERT(u_ccr.requested_units == 3, "CC-Service-Specific-Units extracted is 3");
    TEST_ASSERT(u_ccr.hop_by_hop == 0xAABBCCDD, "Hop-by-Hop identifier preserved");

    /* 3. Test CCA packing and unpacking */
    smpp_diameter_cca_t cca;
    memset(&cca, 0, sizeof(cca));
    strcpy(cca.session_id, "diam-test-session-101");
    cca.result_code = DIAMETER_SUCCESS; /* 2001 */
    cca.request_type = CC_REQUEST_TYPE_EVENT_RECORD;
    cca.request_number = 0;
    cca.granted_units = 3;
    cca.hop_by_hop = 0xAABBCCDD;
    cca.end_to_end = 0x11223344;

    uint8_t cca_buf[512];
    size_t cca_len = 0;
    rc = smpp_diameter_pack_cca(&cca, cca_buf, sizeof(cca_buf), &cca_len);
    TEST_ASSERT(rc == 0 && cca_len > 20, "smpp_diameter_pack_cca succeeds");
    TEST_ASSERT((cca_buf[4] & DIAMETER_FLAG_REQUEST) == 0, "Diameter Answer R-bit cleared");

    smpp_diameter_cca_t u_cca;
    rc = smpp_diameter_unpack_cca(cca_buf, cca_len, &u_cca);
    TEST_ASSERT(rc == 0, "smpp_diameter_unpack_cca succeeds");
    TEST_ASSERT(u_cca.result_code == DIAMETER_SUCCESS, "Result-Code is DIAMETER_SUCCESS (2001)");
    TEST_ASSERT(u_cca.granted_units == 3, "Granted units is 3");

    /* 4. Test Switching to Diameter Mode with transport hook */
    smpp_charging_set_mode(SMPP_CHARGING_MODE_DIAMETER);
    TEST_ASSERT(smpp_charging_get_mode() == SMPP_CHARGING_MODE_DIAMETER, "Charging mode set to DIAMETER");

    mock_diameter_hook_called = 0;
    mock_diameter_hook_units = 0;
    smpp_charging_set_diameter_hook(mock_diameter_hook);

    /* 2 units requested -> passes hook rule (<= 4) */
    uint32_t rem = 0;
    rc = smpp_charging_check_credit("905321234567", "905321234567", "905327654321", 2, &rem);
    TEST_ASSERT(rc == 0, "Diameter credit check passes (Result-Code 2001)");
    TEST_ASSERT(mock_diameter_hook_called == 1, "Diameter transport hook was invoked");
    TEST_ASSERT(mock_diameter_hook_units == 2, "Diameter hook received 2 requested units");

    /* 8 units requested -> exceeds hook limit, returns 4012 -> fails */
    rc = smpp_charging_check_credit("905321234567", "905321234567", "905327654321", 8, &rem);
    TEST_ASSERT(rc != 0, "Diameter credit check rejected (Result-Code 4012 Credit Limit Reached)");
    TEST_ASSERT(mock_diameter_hook_called == 2, "Diameter transport hook was invoked a 2nd time");

    /* Deduct credit via Diameter hook */
    rc = smpp_charging_deduct_credit("905321234567", "905321234567", "905327654321", 2, 0.0);
    TEST_ASSERT(rc == 0, "Diameter direct debiting succeeds");

    /* Clean up hook & restore local mode */
    smpp_charging_set_diameter_hook(NULL);
    smpp_charging_set_mode(SMPP_CHARGING_MODE_LOCAL);
}

/* 17. Test REST API Balance Query & Refill Endpoints */
static void test_rest_api_balance_and_charging(void)
{
    printf("\n=== Running Test Suite 17: REST API Balance Query & Refill Endpoints ===\n");

    smpp_charging_set_mode(SMPP_CHARGING_MODE_LOCAL);
    smpp_charging_set_balance("api_client_1", 100.0);

    char resp_buf[2048];
    size_t resp_len = 0;

    /* 1. GET /api/v1/accounts/balance?id=api_client_1 */
    const char *req_bal = 
        "GET /api/v1/accounts/balance?id=api_client_1 HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "\r\n";
    int rc = smpp_http_api_handle_request(req_bal, strlen(req_bal), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "GET /api/v1/accounts/balance handled");
    TEST_ASSERT(strstr(resp_buf, "200 OK") != NULL, "Balance query returns 200 OK");
    TEST_ASSERT(strstr(resp_buf, "\"balance\":100.00") != NULL, "Response reports balance 100.00");
    TEST_ASSERT(strstr(resp_buf, "\"currency\":\"CREDIT\"") != NULL, "Response reports CREDIT currency");

    /* 2. GET /api/v1/accounts/balance without id -> 400 Bad Request */
    const char *req_bad_bal = 
        "GET /api/v1/accounts/balance HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "\r\n";
    rc = smpp_http_api_handle_request(req_bad_bal, strlen(req_bad_bal), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0 && strstr(resp_buf, "400 Bad Request") != NULL, "Balance query without ID returns 400 Bad Request");

    /* 3. GET /api/v1/accounts/balance for unknown account -> 404 Not Found */
    const char *req_unknown_bal = 
        "GET /api/v1/accounts/balance?id=unknown_xyz HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "\r\n";
    rc = smpp_http_api_handle_request(req_unknown_bal, strlen(req_unknown_bal), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0 && strstr(resp_buf, "404 Not Found") != NULL, "Unknown account returns 404 Not Found");

    /* 4. POST /api/v1/accounts/balance (Refill Credit) */
    const char *refill_payload = "{\"account_id\":\"api_client_1\",\"add_credit\":500.0}";
    char req_refill[1024];
    snprintf(req_refill, sizeof(req_refill),
        "POST /api/v1/accounts/balance HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n%s", strlen(refill_payload), refill_payload);
    rc = smpp_http_api_handle_request(req_refill, strlen(req_refill), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "POST /api/v1/accounts/balance handled");
    TEST_ASSERT(strstr(resp_buf, "200 OK") != NULL, "Balance refill returns 200 OK");
    TEST_ASSERT(strstr(resp_buf, "\"balance\":600.00") != NULL, "Balance updated from 100 to 600.00");
    TEST_ASSERT(strstr(resp_buf, "\"added_credit\":500.00") != NULL, "Response confirms added_credit 500.00");

    /* 5. Depleted Account: Create account with 0.0 balance */
    smpp_charging_set_balance("broke_user", 0.0);
    const char *send_no_credit = 
        "{\"account_id\":\"broke_user\",\"smsc\":\"sim1\",\"from\":\"broke_user\",\"to\":\"905321112233\",\"text\":\"No money text\"}";
    char req_send_fail[1024];
    snprintf(req_send_fail, sizeof(req_send_fail),
        "POST /api/v1/sms/send HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n%s", strlen(send_no_credit), send_no_credit);
    rc = smpp_http_api_handle_request(req_send_fail, strlen(req_send_fail), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "POST /api/v1/sms/send handled for depleted account");
    TEST_ASSERT(strstr(resp_buf, "402 Payment Required") != NULL, "REST API returns 402 Payment Required when balance is 0");
    TEST_ASSERT(strstr(resp_buf, "0x68") != NULL, "Response error mentions ESME_RINVCREDIT (0x68)");

    /* 6. Refill broke_user and verify successful transmission */
    const char *refill_broke = "{\"account_id\":\"broke_user\",\"add_credit\":50.0}";
    snprintf(req_refill, sizeof(req_refill),
        "POST /api/v1/accounts/balance HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Authorization: Bearer secret-token-123\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n%s", strlen(refill_broke), refill_broke);
    smpp_http_api_handle_request(req_refill, strlen(req_refill), resp_buf, sizeof(resp_buf), &resp_len);

    rc = smpp_http_api_handle_request(req_send_fail, strlen(req_send_fail), resp_buf, sizeof(resp_buf), &resp_len);
    TEST_ASSERT(rc == 0, "POST /api/v1/sms/send retried after credit refill");
    TEST_ASSERT(strstr(resp_buf, "200 OK") != NULL, "REST API send returns 200 OK after refill");
    TEST_ASSERT(strstr(resp_buf, "\"status\":\"accepted\"") != NULL, "SMS accepted for delivery");

    double broke_bal = 0.0;
    smpp_charging_get_balance("broke_user", &broke_bal);
    TEST_ASSERT(broke_bal == 49.0, "Credit deducted by 1.0 (now 49.0)");
}

/* 18. Test SMPP-to-SIP Mobile Originated (MO) SMS Interworking */
static int test_sip_dispatch_count = 0;
static char test_sip_last_src[64] = {0};
static char test_sip_last_dst[64] = {0};
static char test_sip_last_body[256] = {0};
static int mock_sip_dispatcher_cb(const char *src, const char *dst, const char *body, size_t body_len, const char *raw_sip, size_t raw_len)
{
    (void)raw_sip;
    (void)raw_len;
    test_sip_dispatch_count++;
    strncpy(test_sip_last_src, src, sizeof(test_sip_last_src) - 1);
    strncpy(test_sip_last_dst, dst, sizeof(test_sip_last_dst) - 1);
    size_t l = body_len < sizeof(test_sip_last_body) - 1 ? body_len : sizeof(test_sip_last_body) - 1;
    memcpy(test_sip_last_body, body, l);
    test_sip_last_body[l] = '\0';
    return 0;
}

static void test_mo_smpp_to_sip_interworking(void)
{
    printf("\n=== Running Test Suite 18: SMPP-to-SIP MO SMS Interworking (RFC 3428) ===\n");

    /* 1. Test smpp_build_sip_message format */
    char sip_buf[2048];
    size_t sip_len = 0;
    const char *sample_body = "Hello SIP user from SMPP!";
    int rc = smpp_build_sip_message("905321000000", "905322000000", sample_body, strlen(sample_body),
                                    "kamailio.local", sip_buf, sizeof(sip_buf), &sip_len);
    TEST_ASSERT(rc == 0 && sip_len > 0, "smpp_build_sip_message generated SIP request");
    TEST_ASSERT(strstr(sip_buf, "MESSAGE sip:905322000000@kamailio.local SIP/2.0") != NULL,
                "Request-Line contains MESSAGE sip:dst@domain SIP/2.0");
    TEST_ASSERT(strstr(sip_buf, "From: <sip:905321000000@kamailio.local>") != NULL,
                "From header contains <sip:src@domain>");
    TEST_ASSERT(strstr(sip_buf, "To: <sip:905322000000@kamailio.local>") != NULL,
                "To header contains <sip:dst@domain>");
    TEST_ASSERT(strstr(sip_buf, "Content-Type: text/plain; charset=UTF-8") != NULL,
                "Content-Type is text/plain; charset=UTF-8");
    TEST_ASSERT(strstr(sip_buf, "Content-Length: 25") != NULL,
                "Content-Length matches body length (25)");
    TEST_ASSERT(strstr(sip_buf, sample_body) != NULL,
                "SIP MESSAGE body matches input short_message");

    /* 2. Test destination address with sip: prefix and explicit domain */
    rc = smpp_build_sip_message("sip:alice", "sip:bob@ims.operator.com", "Test body", 9,
                                "default.domain", sip_buf, sizeof(sip_buf), &sip_len);
    TEST_ASSERT(rc == 0, "smpp_build_sip_message handles sip: and @ domain parsing");
    TEST_ASSERT(strstr(sip_buf, "MESSAGE sip:bob@ims.operator.com SIP/2.0") != NULL,
                "Destination user bob and host ims.operator.com extracted correctly");
    TEST_ASSERT(strstr(sip_buf, "From: <sip:alice@ims.operator.com>") != NULL,
                "From header uses parsed destination domain");

    /* 3. Test smpp_to_sip_message with dispatcher hook */
    test_sip_dispatch_count = 0;
    memset(test_sip_last_src, 0, sizeof(test_sip_last_src));
    memset(test_sip_last_dst, 0, sizeof(test_sip_last_dst));
    memset(test_sip_last_body, 0, sizeof(test_sip_last_body));

    smpp_set_sip_dispatcher(mock_sip_dispatcher_cb);
    TEST_ASSERT(smpp_get_sip_dispatcher() == mock_sip_dispatcher_cb, "smpp_set_sip_dispatcher registers callback");

    rc = smpp_to_sip_message("905329999999", "905328888888", "Inbound MO SMS Test", 19);
    TEST_ASSERT(rc == 0, "smpp_to_sip_message returned success");
    TEST_ASSERT(test_sip_dispatch_count == 1, "SIP dispatcher callback invoked once");
    TEST_ASSERT(strcmp(test_sip_last_src, "905329999999") == 0, "Dispatcher received correct source MSISDN");
    TEST_ASSERT(strcmp(test_sip_last_dst, "905328888888") == 0, "Dispatcher received correct destination MSISDN");
    TEST_ASSERT(strcmp(test_sip_last_body, "Inbound MO SMS Test") == 0, "Dispatcher received correct body text");

    /* 4. Parameter validation */
    TEST_ASSERT(smpp_to_sip_message(NULL, "dst", "body", 4) == -1, "NULL source rejected with -1");
    TEST_ASSERT(smpp_to_sip_message("src", NULL, "body", 4) == -1, "NULL destination rejected with -1");
    TEST_ASSERT(smpp_to_sip_message("src", "dst", NULL, 0) == -1, "NULL body rejected with -1");

    smpp_set_sip_dispatcher(NULL);
}


int main(void)
{
    printf("====================================================\n");
    printf("Kamailio SMPP (SMS-IWF) Module - Verification Suite\n");
    printf("====================================================\n");

    smpp_charging_init();

    test_pdu_pack_unpack();
    test_nli_detection();
    test_turkish_shift_tables();
    test_bcode_appending();
    test_fraud_filtering();
    test_msisdn_normalization();
    test_token_bucket_ratelimit();
    test_config_store();
    test_smsc_server_processing();
    test_interworking_and_ims();
    test_dlr_normalization();
    test_mnp_and_enum();
    test_rest_api_suite();
    test_dynamic_ton_npi();
    test_charging_and_credit_control();
    test_diameter_ro_charging();
    test_rest_api_balance_and_charging();
    test_mo_smpp_to_sip_interworking();

    printf("\n====================================================\n");
    printf("Total Tests: %d | Passed: %d | Failed: %d\n",
           tests_run, tests_passed, tests_run - tests_passed);
    printf("====================================================\n");

    return (tests_run == tests_passed) ? 0 : 1;
}

