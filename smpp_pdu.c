/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - PDU Parser & Serializer Implementation
*/

#include "smpp_pdu.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* Helper to read null-terminated string safely */
static int read_cstring(const uint8_t *buf, size_t buf_len, size_t *offset, char *dest, size_t max_dest)
{
    size_t start = *offset;
    size_t i = start;
    while (i < buf_len && buf[i] != '\0') {
        i++;
    }
    if (i >= buf_len) return -1; /* Missing null terminator */

    size_t str_len = i - start;
    if (str_len >= max_dest) {
        str_len = max_dest - 1;
    }
    memcpy(dest, buf + start, str_len);
    dest[str_len] = '\0';
    *offset = i + 1; /* Skip null terminator */
    return 0;
}

/* Helper to write null-terminated string */
static int write_cstring(const char *src, uint8_t *buf, size_t buf_len, size_t *offset)
{
    size_t len = strlen(src) + 1;
    if (*offset + len > buf_len) return -1;
    memcpy(buf + *offset, src, len);
    *offset += len;
    return 0;
}

void smpp_header_init(smpp_header_t *hdr, uint32_t cmd_id, uint32_t cmd_status, uint32_t seq)
{
    if (!hdr) return;
    hdr->command_length = SMPP_HEADER_LEN;
    hdr->command_id = cmd_id;
    hdr->command_status = cmd_status;
    hdr->sequence_number = seq;
}

int smpp_pdu_unpack_header(const uint8_t *buf, size_t len, smpp_header_t *hdr)
{
    if (!buf || len < SMPP_HEADER_LEN || !hdr) return -1;

    hdr->command_length = ntohl(*(uint32_t *)(buf + 0));
    hdr->command_id = ntohl(*(uint32_t *)(buf + 4));
    hdr->command_status = ntohl(*(uint32_t *)(buf + 8));
    hdr->sequence_number = ntohl(*(uint32_t *)(buf + 12));

    if (hdr->command_length < SMPP_HEADER_LEN || hdr->command_length > SMPP_MAX_PDU_LEN) {
        return -2; /* Invalid command length */
    }
    return 0;
}

int smpp_pdu_pack_header(const smpp_header_t *hdr, uint8_t *buf, size_t len)
{
    if (!hdr || !buf || len < SMPP_HEADER_LEN) return -1;

    uint32_t net_len = htonl(hdr->command_length);
    uint32_t net_id = htonl(hdr->command_id);
    uint32_t net_status = htonl(hdr->command_status);
    uint32_t net_seq = htonl(hdr->sequence_number);

    memcpy(buf + 0, &net_len, 4);
    memcpy(buf + 4, &net_id, 4);
    memcpy(buf + 8, &net_status, 4);
    memcpy(buf + 12, &net_seq, 4);
    return 0;
}

int smpp_pdu_unpack(const uint8_t *buf, size_t len, smpp_pdu_t *pdu)
{
    if (!buf || !pdu) return -1;
    memset(pdu, 0, sizeof(smpp_pdu_t));

    int rc = smpp_pdu_unpack_header(buf, len, &pdu->header);
    if (rc < 0) return rc;

    if (len < pdu->header.command_length) {
        return -3; /* Partial PDU */
    }

    size_t offset = SMPP_HEADER_LEN;
    size_t pdu_end = pdu->header.command_length;

    switch (pdu->header.command_id) {
    case SMPP_CMD_BIND_TRANSMITTER:
    case SMPP_CMD_BIND_RECEIVER:
    case SMPP_CMD_BIND_TRANSCEIVER:
        if (read_cstring(buf, pdu_end, &offset, pdu->body.bind_req.system_id, sizeof(pdu->body.bind_req.system_id)) < 0) return -4;
        if (read_cstring(buf, pdu_end, &offset, pdu->body.bind_req.password, sizeof(pdu->body.bind_req.password)) < 0) return -4;
        if (read_cstring(buf, pdu_end, &offset, pdu->body.bind_req.system_type, sizeof(pdu->body.bind_req.system_type)) < 0) return -4;
        if (offset + 3 > pdu_end) return -4;
        pdu->body.bind_req.interface_version = buf[offset++];
        pdu->body.bind_req.addr_ton = buf[offset++];
        pdu->body.bind_req.addr_npi = buf[offset++];
        if (read_cstring(buf, pdu_end, &offset, pdu->body.bind_req.address_range, sizeof(pdu->body.bind_req.address_range)) < 0) return -4;
        break;

    case SMPP_CMD_BIND_TRANSMITTER_RESP:
    case SMPP_CMD_BIND_RECEIVER_RESP:
    case SMPP_CMD_BIND_TRANSCEIVER_RESP:
        if (pdu->header.command_status == ESME_ROK) {
            if (offset < pdu_end) {
                if (read_cstring(buf, pdu_end, &offset, pdu->body.bind_resp.system_id, sizeof(pdu->body.bind_resp.system_id)) < 0) return -4;
            }
            if (offset < pdu_end) {
                smpp_tlv_parse(buf + offset, pdu_end - offset, &pdu->body.bind_resp.tlvs);
            }
        }
        break;

    case SMPP_CMD_SUBMIT_SM:
    case SMPP_CMD_DELIVER_SM:
        if (read_cstring(buf, pdu_end, &offset, pdu->body.msg.service_type, sizeof(pdu->body.msg.service_type)) < 0) return -4;
        if (offset + 2 > pdu_end) return -4;
        pdu->body.msg.source_addr_ton = buf[offset++];
        pdu->body.msg.source_addr_npi = buf[offset++];
        if (read_cstring(buf, pdu_end, &offset, pdu->body.msg.source_addr, sizeof(pdu->body.msg.source_addr)) < 0) return -4;
        if (offset + 2 > pdu_end) return -4;
        pdu->body.msg.dest_addr_ton = buf[offset++];
        pdu->body.msg.dest_addr_npi = buf[offset++];
        if (read_cstring(buf, pdu_end, &offset, pdu->body.msg.destination_addr, sizeof(pdu->body.msg.destination_addr)) < 0) return -4;
        if (offset + 3 > pdu_end) return -4;
        pdu->body.msg.esm_class = buf[offset++];
        pdu->body.msg.protocol_id = buf[offset++];
        pdu->body.msg.priority_flag = buf[offset++];
        if (read_cstring(buf, pdu_end, &offset, pdu->body.msg.schedule_delivery_time, sizeof(pdu->body.msg.schedule_delivery_time)) < 0) return -4;
        if (read_cstring(buf, pdu_end, &offset, pdu->body.msg.validity_period, sizeof(pdu->body.msg.validity_period)) < 0) return -4;
        if (offset + 5 > pdu_end) return -4;
        pdu->body.msg.registered_delivery = buf[offset++];
        pdu->body.msg.replace_if_present_flag = buf[offset++];
        pdu->body.msg.data_coding = buf[offset++];
        pdu->body.msg.sm_default_msg_id = buf[offset++];
        pdu->body.msg.sm_length = buf[offset++];

        if (pdu->body.msg.sm_length > 0) {
            if (offset + pdu->body.msg.sm_length > pdu_end) return -4;
            memcpy(pdu->body.msg.short_message, buf + offset, pdu->body.msg.sm_length);
            offset += pdu->body.msg.sm_length;
        }

        /* Parse optional TLVs */
        if (offset < pdu_end) {
            smpp_tlv_parse(buf + offset, pdu_end - offset, &pdu->body.msg.tlvs);
        }
        break;

    case SMPP_CMD_SUBMIT_SM_RESP:
    case SMPP_CMD_DELIVER_SM_RESP:
        if (pdu->header.command_status == ESME_ROK) {
            if (offset < pdu_end) {
                if (read_cstring(buf, pdu_end, &offset, pdu->body.msg_resp.message_id, sizeof(pdu->body.msg_resp.message_id)) < 0) return -4;
            }
            if (offset < pdu_end) {
                smpp_tlv_parse(buf + offset, pdu_end - offset, &pdu->body.msg_resp.tlvs);
            }
        }
        break;

    case SMPP_CMD_ENQUIRE_LINK:
    case SMPP_CMD_ENQUIRE_LINK_RESP:
    case SMPP_CMD_UNBIND:
    case SMPP_CMD_UNBIND_RESP:
    case SMPP_CMD_GENERIC_NACK:
        /* Header-only PDUs */
        break;

    default:
        /* Unknown or extended PDU, leave body unparsed */
        break;
    }

    return 0;
}

int smpp_pdu_pack(const smpp_pdu_t *pdu, uint8_t *buf, size_t buf_len, size_t *out_len)
{
    if (!pdu || !buf || buf_len < SMPP_HEADER_LEN) return -1;

    size_t offset = SMPP_HEADER_LEN;

    switch (pdu->header.command_id) {
    case SMPP_CMD_BIND_TRANSMITTER:
    case SMPP_CMD_BIND_RECEIVER:
    case SMPP_CMD_BIND_TRANSCEIVER:
        if (write_cstring(pdu->body.bind_req.system_id, buf, buf_len, &offset) < 0) return -1;
        if (write_cstring(pdu->body.bind_req.password, buf, buf_len, &offset) < 0) return -1;
        if (write_cstring(pdu->body.bind_req.system_type, buf, buf_len, &offset) < 0) return -1;
        if (offset + 3 > buf_len) return -1;
        buf[offset++] = pdu->body.bind_req.interface_version;
        buf[offset++] = pdu->body.bind_req.addr_ton;
        buf[offset++] = pdu->body.bind_req.addr_npi;
        if (write_cstring(pdu->body.bind_req.address_range, buf, buf_len, &offset) < 0) return -1;
        break;

    case SMPP_CMD_BIND_TRANSMITTER_RESP:
    case SMPP_CMD_BIND_RECEIVER_RESP:
    case SMPP_CMD_BIND_TRANSCEIVER_RESP:
        if (pdu->header.command_status == ESME_ROK) {
            if (write_cstring(pdu->body.bind_resp.system_id, buf, buf_len, &offset) < 0) return -1;
            if (pdu->body.bind_resp.tlvs) {
                size_t tlv_written = 0;
                if (smpp_tlv_serialize(pdu->body.bind_resp.tlvs, buf + offset, buf_len - offset, &tlv_written) < 0) return -1;
                offset += tlv_written;
            }
        }
        break;

    case SMPP_CMD_SUBMIT_SM:
    case SMPP_CMD_DELIVER_SM:
        if (write_cstring(pdu->body.msg.service_type, buf, buf_len, &offset) < 0) return -1;
        if (offset + 2 > buf_len) return -1;
        buf[offset++] = pdu->body.msg.source_addr_ton;
        buf[offset++] = pdu->body.msg.source_addr_npi;
        if (write_cstring(pdu->body.msg.source_addr, buf, buf_len, &offset) < 0) return -1;
        if (offset + 2 > buf_len) return -1;
        buf[offset++] = pdu->body.msg.dest_addr_ton;
        buf[offset++] = pdu->body.msg.dest_addr_npi;
        if (write_cstring(pdu->body.msg.destination_addr, buf, buf_len, &offset) < 0) return -1;
        if (offset + 3 > buf_len) return -1;
        buf[offset++] = pdu->body.msg.esm_class;
        buf[offset++] = pdu->body.msg.protocol_id;
        buf[offset++] = pdu->body.msg.priority_flag;
        if (write_cstring(pdu->body.msg.schedule_delivery_time, buf, buf_len, &offset) < 0) return -1;
        if (write_cstring(pdu->body.msg.validity_period, buf, buf_len, &offset) < 0) return -1;
        if (offset + 5 > buf_len) return -1;
        buf[offset++] = pdu->body.msg.registered_delivery;
        buf[offset++] = pdu->body.msg.replace_if_present_flag;
        buf[offset++] = pdu->body.msg.data_coding;
        buf[offset++] = pdu->body.msg.sm_default_msg_id;
        buf[offset++] = pdu->body.msg.sm_length;

        if (pdu->body.msg.sm_length > 0) {
            if (offset + pdu->body.msg.sm_length > buf_len) return -1;
            memcpy(buf + offset, pdu->body.msg.short_message, pdu->body.msg.sm_length);
            offset += pdu->body.msg.sm_length;
        }

        if (pdu->body.msg.tlvs) {
            size_t tlv_written = 0;
            if (smpp_tlv_serialize(pdu->body.msg.tlvs, buf + offset, buf_len - offset, &tlv_written) < 0) return -1;
            offset += tlv_written;
        }
        break;

    case SMPP_CMD_SUBMIT_SM_RESP:
    case SMPP_CMD_DELIVER_SM_RESP:
        if (pdu->header.command_status == ESME_ROK) {
            if (write_cstring(pdu->body.msg_resp.message_id, buf, buf_len, &offset) < 0) return -1;
            if (pdu->body.msg_resp.tlvs) {
                size_t tlv_written = 0;
                if (smpp_tlv_serialize(pdu->body.msg_resp.tlvs, buf + offset, buf_len - offset, &tlv_written) < 0) return -1;
                offset += tlv_written;
            }
        }
        break;

    default:
        /* Header-only PDUs (enquire_link, generic_nack, unbind) */
        break;
    }

    /* Complete header length */
    smpp_header_t hdr = pdu->header;
    hdr.command_length = (uint32_t)offset;
    smpp_pdu_pack_header(&hdr, buf, SMPP_HEADER_LEN);

    if (out_len) *out_len = offset;
    return 0;
}

void smpp_pdu_free(smpp_pdu_t *pdu)
{
    if (!pdu) return;
    switch (pdu->header.command_id) {
    case SMPP_CMD_BIND_TRANSMITTER_RESP:
    case SMPP_CMD_BIND_RECEIVER_RESP:
    case SMPP_CMD_BIND_TRANSCEIVER_RESP:
        if (pdu->body.bind_resp.tlvs) {
            smpp_tlv_free_list(pdu->body.bind_resp.tlvs);
            pdu->body.bind_resp.tlvs = NULL;
        }
        break;
    case SMPP_CMD_SUBMIT_SM:
    case SMPP_CMD_DELIVER_SM:
        if (pdu->body.msg.tlvs) {
            smpp_tlv_free_list(pdu->body.msg.tlvs);
            pdu->body.msg.tlvs = NULL;
        }
        break;
    case SMPP_CMD_SUBMIT_SM_RESP:
    case SMPP_CMD_DELIVER_SM_RESP:
        if (pdu->body.msg_resp.tlvs) {
            smpp_tlv_free_list(pdu->body.msg_resp.tlvs);
            pdu->body.msg_resp.tlvs = NULL;
        }
        break;
    default:
        break;
    }
}

int smpp_make_enquire_link(smpp_pdu_t *pdu, uint32_t seq)
{
    if (!pdu) return -1;
    memset(pdu, 0, sizeof(smpp_pdu_t));
    smpp_header_init(&pdu->header, SMPP_CMD_ENQUIRE_LINK, ESME_ROK, seq);
    return 0;
}

int smpp_make_enquire_link_resp(smpp_pdu_t *pdu, uint32_t seq)
{
    if (!pdu) return -1;
    memset(pdu, 0, sizeof(smpp_pdu_t));
    smpp_header_init(&pdu->header, SMPP_CMD_ENQUIRE_LINK_RESP, ESME_ROK, seq);
    return 0;
}

int smpp_make_generic_nack(smpp_pdu_t *pdu, uint32_t seq, uint32_t status)
{
    if (!pdu) return -1;
    memset(pdu, 0, sizeof(smpp_pdu_t));
    smpp_header_init(&pdu->header, SMPP_CMD_GENERIC_NACK, status, seq);
    return 0;
}

int smpp_make_unbind(smpp_pdu_t *pdu, uint32_t seq)
{
    if (!pdu) return -1;
    memset(pdu, 0, sizeof(smpp_pdu_t));
    smpp_header_init(&pdu->header, SMPP_CMD_UNBIND, ESME_ROK, seq);
    return 0;
}

int smpp_make_unbind_resp(smpp_pdu_t *pdu, uint32_t seq)
{
    if (!pdu) return -1;
    memset(pdu, 0, sizeof(smpp_pdu_t));
    smpp_header_init(&pdu->header, SMPP_CMD_UNBIND_RESP, ESME_ROK, seq);
    return 0;
}
