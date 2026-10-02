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

char *smpp_msgid_format = "%PREFIX%-%TIMESTAMP%-%HEXSEQ%";

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

int main(void)
{
    printf("====================================================\n");
    printf("Kamailio SMPP (SMS-IWF) Module - Verification Suite\n");
    printf("====================================================\n");

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

    printf("\n====================================================\n");
    printf("Total Tests: %d | Passed: %d | Failed: %d\n",
           tests_run, tests_passed, tests_run - tests_passed);
    printf("====================================================\n");

    return (tests_run == tests_passed) ? 0 : 1;
}
