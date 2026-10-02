/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - TLV Implementation
*/

#include "smpp_tlv.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

smpp_tlv_t *smpp_tlv_create(uint16_t tag, uint16_t length, const uint8_t *val)
{
    smpp_tlv_t *tlv = (smpp_tlv_t *)malloc(sizeof(smpp_tlv_t));
    if (!tlv) return NULL;

    tlv->tag = tag;
    tlv->length = length;
    tlv->next = NULL;

    if (length > 0 && val) {
        tlv->value = (uint8_t *)malloc(length);
        if (!tlv->value) {
            free(tlv);
            return NULL;
        }
        memcpy(tlv->value, val, length);
    } else {
        tlv->value = NULL;
    }

    return tlv;
}

int smpp_tlv_add(smpp_tlv_t **head, uint16_t tag, uint16_t length, const uint8_t *val)
{
    smpp_tlv_t *node = smpp_tlv_create(tag, length, val);
    if (!node) return -1;

    if (!*head) {
        *head = node;
    } else {
        smpp_tlv_t *curr = *head;
        while (curr->next) curr = curr->next;
        curr->next = node;
    }
    return 0;
}

smpp_tlv_t *smpp_tlv_find(const smpp_tlv_t *head, uint16_t tag)
{
    const smpp_tlv_t *curr = head;
    while (curr) {
        if (curr->tag == tag) return (smpp_tlv_t *)curr;
        curr = curr->next;
    }
    return NULL;
}

void smpp_tlv_free_list(smpp_tlv_t *head)
{
    while (head) {
        smpp_tlv_t *tmp = head->next;
        if (head->value) free(head->value);
        free(head);
        head = tmp;
    }
}

size_t smpp_tlv_calc_size(const smpp_tlv_t *head)
{
    size_t total = 0;
    const smpp_tlv_t *curr = head;
    while (curr) {
        total += 4 + curr->length; /* 2 bytes tag + 2 bytes len + value */
        curr = curr->next;
    }
    return total;
}

int smpp_tlv_serialize(const smpp_tlv_t *head, uint8_t *buf, size_t buf_len, size_t *out_len)
{
    size_t needed = smpp_tlv_calc_size(head);
    if (buf_len < needed) return -1;

    size_t offset = 0;
    const smpp_tlv_t *curr = head;
    while (curr) {
        uint16_t net_tag = htons(curr->tag);
        uint16_t net_len = htons(curr->length);

        memcpy(buf + offset, &net_tag, 2);
        offset += 2;
        memcpy(buf + offset, &net_len, 2);
        offset += 2;

        if (curr->length > 0 && curr->value) {
            memcpy(buf + offset, curr->value, curr->length);
            offset += curr->length;
        }
        curr = curr->next;
    }

    if (out_len) *out_len = offset;
    return 0;
}

int smpp_tlv_parse(const uint8_t *buf, size_t buf_len, smpp_tlv_t **out_head)
{
    if (!buf || !out_head) return -1;
    *out_head = NULL;

    size_t offset = 0;
    while (offset + 4 <= buf_len) {
        uint16_t tag = ntohs(*(uint16_t *)(buf + offset));
        offset += 2;
        uint16_t len = ntohs(*(uint16_t *)(buf + offset));
        offset += 2;

        if (offset + len > buf_len) {
            /* Truncated TLV */
            smpp_tlv_free_list(*out_head);
            *out_head = NULL;
            return -1;
        }

        const uint8_t *val_ptr = (len > 0) ? (buf + offset) : NULL;
        if (smpp_tlv_add(out_head, tag, len, val_ptr) < 0) {
            smpp_tlv_free_list(*out_head);
            *out_head = NULL;
            return -1;
        }
        offset += len;
    }

    return 0;
}
