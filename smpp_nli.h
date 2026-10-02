/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - 3GPP TS 23.038 National Language Identifier (NLI)
# Supporting All 13 3GPP Languages, Turkish Shift Tables, and Auto-Detection
*/

#ifndef _SMPP_NLI_H_
#define _SMPP_NLI_H_

#include <stdint.h>
#include <stddef.h>

/* 3GPP TS 23.038 Table 6.2.1.2.4.1 National Language Codes */
#define SMPP_NLI_NONE               0x00
#define SMPP_NLI_TURKISH            0x01 /* Clause A.2.1 & A.3.1 */
#define SMPP_NLI_SPANISH            0x02 /* Clause A.2.2 */
#define SMPP_NLI_PORTUGUESE         0x03 /* Clause A.2.3 & A.3.3 */
#define SMPP_NLI_BENGALI            0x04 /* Clause A.2.4 & A.3.4 */
#define SMPP_NLI_GUJARATI           0x05 /* Clause A.2.5 & A.3.5 */
#define SMPP_NLI_HINDI              0x06 /* Clause A.2.6 & A.3.6 */
#define SMPP_NLI_KANNADA            0x07 /* Clause A.2.7 & A.3.7 */
#define SMPP_NLI_MALAYALAM          0x08 /* Clause A.2.8 & A.3.8 */
#define SMPP_NLI_ORIYA              0x09 /* Clause A.2.9 & A.3.9 */
#define SMPP_NLI_PUNJABI            0x0A /* Clause A.2.10 & A.3.10 */
#define SMPP_NLI_TAMIL              0x0B /* Clause A.2.11 & A.3.11 */
#define SMPP_NLI_TELUGU             0x0C /* Clause A.2.12 & A.3.12 */
#define SMPP_NLI_URDU               0x0D /* Clause A.2.13 & A.3.13 */

/* 3GPP TS 23.040 UDH Information Element Identifiers */
#define SMPP_UDH_IEI_SINGLE_SHIFT   0x24 /* Decimal 36 */
#define SMPP_UDH_IEI_LOCKING_SHIFT  0x25 /* Decimal 37 */

/* Shift Modes */
#define SMPP_NLI_SHIFT_AUTO         0
#define SMPP_NLI_SHIFT_SINGLE       1
#define SMPP_NLI_SHIFT_LOCKING      2
#define SMPP_NLI_SHIFT_BOTH         3

/* GSM 7-bit Escape Octet */
#define GSM_ESCAPE_CHAR             0x1B

/* Language Profile */
typedef struct smpp_nli_lang {
    uint8_t code;
    const char *name;
    const char *iso;
    uint8_t has_single;
    uint8_t has_locking;
} smpp_nli_lang_t;

const smpp_nli_lang_t *smpp_nli_get_lang(uint8_t code);
uint8_t smpp_nli_code_by_iso(const char *iso);

/* Core Detection & Translation */
uint8_t smpp_nli_detect_encoding(const char *utf8_text, uint8_t *detected_nli);

int smpp_nli_build_udh(uint8_t nli_code, uint8_t shift_mode, uint8_t *udh_buf, size_t *udh_len);

int smpp_nli_encode_turkish_single(const char *utf8_text, uint8_t *out_buf, size_t max_out, size_t *out_len);
int smpp_nli_encode_turkish_locking(const char *utf8_text, uint8_t *out_buf, size_t max_out, size_t *out_len);

int smpp_utf8_to_ucs2(const char *utf8_str, uint8_t *ucs2_buf, size_t max_out, size_t *out_len);
int smpp_ucs2_to_utf8(const uint8_t *ucs2_buf, size_t ucs2_len, char *utf8_buf, size_t max_out);

int smpp_nli_transliterate(const char *in_utf8, char *out_ascii, size_t max_out);

#endif /* _SMPP_NLI_H_ */
