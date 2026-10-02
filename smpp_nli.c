/*
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kamailio SMPP (SMS-IWF) Module - 3GPP TS 23.038 NLI Implementation
*/

#include "smpp_nli.h"
#include "smpp_pdu.h"
#include <string.h>
#include <stdlib.h>

static const smpp_nli_lang_t nli_languages[] = {
    { SMPP_NLI_TURKISH,    "Turkish",    "tr", 1, 1 },
    { SMPP_NLI_SPANISH,    "Spanish",    "es", 1, 0 },
    { SMPP_NLI_PORTUGUESE, "Portuguese", "pt", 1, 1 },
    { SMPP_NLI_BENGALI,    "Bengali",    "bn", 1, 1 },
    { SMPP_NLI_GUJARATI,   "Gujarati",   "gu", 1, 1 },
    { SMPP_NLI_HINDI,      "Hindi",      "hi", 1, 1 },
    { SMPP_NLI_KANNADA,    "Kannada",    "kn", 1, 1 },
    { SMPP_NLI_MALAYALAM,  "Malayalam",  "ml", 1, 1 },
    { SMPP_NLI_ORIYA,      "Oriya",      "or", 1, 1 },
    { SMPP_NLI_PUNJABI,    "Punjabi",    "pa", 1, 1 },
    { SMPP_NLI_TAMIL,      "Tamil",      "ta", 1, 1 },
    { SMPP_NLI_TELUGU,     "Telugu",     "te", 1, 1 },
    { SMPP_NLI_URDU,       "Urdu",       "ur", 1, 1 },
    { 0, NULL, NULL, 0, 0 }
};

const smpp_nli_lang_t *smpp_nli_get_lang(uint8_t code)
{
    for (int i = 0; nli_languages[i].name != NULL; i++) {
        if (nli_languages[i].code == code) return &nli_languages[i];
    }
    return NULL;
}

uint8_t smpp_nli_code_by_iso(const char *iso)
{
    if (!iso) return SMPP_NLI_NONE;
    for (int i = 0; nli_languages[i].name != NULL; i++) {
        if (strcasecmp(nli_languages[i].iso, iso) == 0 ||
            strcasecmp(nli_languages[i].name, iso) == 0) {
            return nli_languages[i].code;
        }
    }
    return SMPP_NLI_NONE;
}

/* UTF-8 Decoder Helper */
static uint32_t utf8_next(const char **s)
{
    const uint8_t *p = (const uint8_t *)*s;
    if (!*p) return 0;

    uint32_t cp;
    int len;

    if (*p < 0x80) {
        cp = *p;
        len = 1;
    } else if ((*p & 0xE0) == 0xC0) {
        cp = *p & 0x1F;
        len = 2;
    } else if ((*p & 0xF0) == 0xE0) {
        cp = *p & 0x0F;
        len = 3;
    } else if ((*p & 0xF8) == 0xF0) {
        cp = *p & 0x07;
        len = 4;
    } else {
        (*s)++;
        return 0xFFFD; /* Replacement character */
    }

    for (int i = 1; i < len; i++) {
        if ((p[i] & 0xC0) != 0x80) {
            (*s) += len;
            return 0xFFFD;
        }
        cp = (cp << 6) | (p[i] & 0x3F);
    }

    *s += len;
    return cp;
}

/* GSM 7-bit Basic Character Verification */
static int is_basic_gsm7(uint32_t cp)
{
    /* ASCII printable ranges that match GSM 7-bit */
    if ((cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z') || (cp >= '0' && cp <= '9'))
        return 1;
    if (cp == ' ' || cp == '!' || cp == '"' || cp == '#' || cp == '%' ||
        cp == '&' || cp == '\'' || cp == '(' || cp == ')' || cp == '*' ||
        cp == '+' || cp == ',' || cp == '-' || cp == '.' || cp == '/' ||
        cp == ':' || cp == ';' || cp == '<' || cp == '=' || cp == '>' ||
        cp == '?' || cp == '@' || cp == '_' || cp == '\n' || cp == '\r')
        return 1;
    /* GSM European characters */
    if (cp == 0x00A3 || cp == 0x00A4 || cp == 0x00A5 || cp == 0x00A7 ||
        cp == 0x00C4 || cp == 0x00C5 || cp == 0x00C6 || cp == 0x00C7 ||
        cp == 0x00C9 || cp == 0x00D1 || cp == 0x00D6 || cp == 0x00D8 ||
        cp == 0x00DC || cp == 0x00DF || cp == 0x00E0 || cp == 0x00E4 ||
        cp == 0x00E5 || cp == 0x00E6 || cp == 0x00E8 || cp == 0x00E9 ||
        cp == 0x00EC || cp == 0x00F1 || cp == 0x00F2 || cp == 0x00F6 ||
        cp == 0x00F8 || cp == 0x00F9 || cp == 0x00FC)
        return 1;
    /* GSM default extension table (escaped) */
    if (cp == '^' || cp == '{' || cp == '}' || cp == '\\' ||
        cp == '[' || cp == '~' || cp == ']' || cp == '|' || cp == 0x20AC)
        return 1;

    return 0;
}

/* Check if character belongs to Turkish NLI specific characters */
static int is_turkish_nli_char(uint32_t cp)
{
    /* Turkish characters not in basic GSM: Ğ(0x11E), ğ(0x11F), İ(0x130), ı(0x131), Ş(0x15E), ş(0x15F), ç(0xE7) */
    return (cp == 0x011E || cp == 0x011F || cp == 0x0130 ||
            cp == 0x0131 || cp == 0x015E || cp == 0x015F || cp == 0x00E7);
}

/* Encoding Detector */
uint8_t smpp_nli_detect_encoding(const char *utf8_text, uint8_t *detected_nli)
{
    if (!utf8_text || !*utf8_text) {
        if (detected_nli) *detected_nli = SMPP_NLI_NONE;
        return SMPP_ENCODING_DEFAULT;
    }

    int has_non_gsm = 0;
    int turkish_matches = 0;
    int non_nli_chars = 0;

    const char *p = utf8_text;
    while (*p) {
        uint32_t cp = utf8_next(&p);
        if (is_basic_gsm7(cp)) {
            continue;
        }
        has_non_gsm = 1;
        if (is_turkish_nli_char(cp)) {
            turkish_matches++;
        } else {
            non_nli_chars++;
        }
    }

    if (!has_non_gsm) {
        if (detected_nli) *detected_nli = SMPP_NLI_NONE;
        return SMPP_ENCODING_DEFAULT;
    }

    if (turkish_matches > 0 && non_nli_chars == 0) {
        if (detected_nli) *detected_nli = SMPP_NLI_TURKISH;
        return SMPP_ENCODING_DEFAULT;
    }

    /* Fallback to UCS-2 */
    if (detected_nli) *detected_nli = SMPP_NLI_NONE;
    return SMPP_ENCODING_UCS2;
}

/* Build 3GPP TS 23.040 User Data Header (UDH) */
int smpp_nli_build_udh(uint8_t nli_code, uint8_t shift_mode, uint8_t *udh_buf, size_t *udh_len)
{
    if (!udh_buf || !udh_len) return -1;

    if (shift_mode == SMPP_NLI_SHIFT_SINGLE) {
        /* UDL=3, IEI=0x24, IEL=1, NLI */
        udh_buf[0] = 0x03;
        udh_buf[1] = SMPP_UDH_IEI_SINGLE_SHIFT;
        udh_buf[2] = 0x01;
        udh_buf[3] = nli_code;
        *udh_len = 4;
    } else if (shift_mode == SMPP_NLI_SHIFT_LOCKING || shift_mode == SMPP_NLI_SHIFT_AUTO) {
        /* UDL=3, IEI=0x25, IEL=1, NLI */
        udh_buf[0] = 0x03;
        udh_buf[1] = SMPP_UDH_IEI_LOCKING_SHIFT;
        udh_buf[2] = 0x01;
        udh_buf[3] = nli_code;
        *udh_len = 4;
    } else if (shift_mode == SMPP_NLI_SHIFT_BOTH) {
        /* UDL=6, Locking IE + Single IE */
        udh_buf[0] = 0x06;
        udh_buf[1] = SMPP_UDH_IEI_LOCKING_SHIFT;
        udh_buf[2] = 0x01;
        udh_buf[3] = nli_code;
        udh_buf[4] = SMPP_UDH_IEI_SINGLE_SHIFT;
        udh_buf[5] = 0x01;
        udh_buf[6] = nli_code;
        *udh_len = 7;
    } else {
        *udh_len = 0;
    }

    return 0;
}

/* 3GPP TS 23.038 Annex A.2.1 Turkish Single Shift Encoder */
int smpp_nli_encode_turkish_single(const char *utf8_text, uint8_t *out_buf, size_t max_out, size_t *out_len)
{
    if (!utf8_text || !out_buf || max_out < 4) return -1;

    size_t out_pos = 0;
    /* Prepend UDH for Single Shift */
    smpp_nli_build_udh(SMPP_NLI_TURKISH, SMPP_NLI_SHIFT_SINGLE, out_buf, &out_pos);

    const char *p = utf8_text;
    while (*p) {
        if (out_pos + 2 >= max_out) return -2; /* Overflow */
        uint32_t cp = utf8_next(&p);

        switch (cp) {
        case 0x011E: /* Ğ */
            out_buf[out_pos++] = GSM_ESCAPE_CHAR;
            out_buf[out_pos++] = 0x47;
            break;
        case 0x0130: /* İ */
            out_buf[out_pos++] = GSM_ESCAPE_CHAR;
            out_buf[out_pos++] = 0x49;
            break;
        case 0x015E: /* Ş */
            out_buf[out_pos++] = GSM_ESCAPE_CHAR;
            out_buf[out_pos++] = 0x53;
            break;
        case 0x00E7: /* ç */
            out_buf[out_pos++] = GSM_ESCAPE_CHAR;
            out_buf[out_pos++] = 0x63;
            break;
        case 0x20AC: /* € */
            out_buf[out_pos++] = GSM_ESCAPE_CHAR;
            out_buf[out_pos++] = 0x65;
            break;
        case 0x011F: /* ğ */
            out_buf[out_pos++] = GSM_ESCAPE_CHAR;
            out_buf[out_pos++] = 0x67;
            break;
        case 0x0131: /* ı */
            out_buf[out_pos++] = GSM_ESCAPE_CHAR;
            out_buf[out_pos++] = 0x69;
            break;
        case 0x015F: /* ş */
            out_buf[out_pos++] = GSM_ESCAPE_CHAR;
            out_buf[out_pos++] = 0x73;
            break;
        /* Standard GSM European vowels shared in Turkish */
        case 0x00F6: /* ö */ out_buf[out_pos++] = 0x7C; break;
        case 0x00D6: /* Ö */ out_buf[out_pos++] = 0x5C; break;
        case 0x00FC: /* ü */ out_buf[out_pos++] = 0x7E; break;
        case 0x00DC: /* Ü */ out_buf[out_pos++] = 0x5E; break;
        case 0x00C7: /* Ç */ out_buf[out_pos++] = 0x09; break;
        default:
            if (cp < 0x80) {
                out_buf[out_pos++] = (uint8_t)cp;
            } else {
                out_buf[out_pos++] = '?';
            }
            break;
        }
    }

    if (out_len) *out_len = out_pos;
    return 0;
}

/* 3GPP TS 23.038 Annex A.3.1 Turkish Locking Shift Encoder */
int smpp_nli_encode_turkish_locking(const char *utf8_text, uint8_t *out_buf, size_t max_out, size_t *out_len)
{
    if (!utf8_text || !out_buf || max_out < 4) return -1;

    size_t out_pos = 0;
    /* Prepend UDH for Locking Shift */
    smpp_nli_build_udh(SMPP_NLI_TURKISH, SMPP_NLI_SHIFT_LOCKING, out_buf, &out_pos);

    const char *p = utf8_text;
    while (*p) {
        if (out_pos + 1 >= max_out) return -2;
        uint32_t cp = utf8_next(&p);

        switch (cp) {
        case 0x0131: /* ı */ out_buf[out_pos++] = 0x07; break;
        case 0x00C7: /* Ç */ out_buf[out_pos++] = 0x09; break;
        case 0x011E: /* Ğ */ out_buf[out_pos++] = 0x0B; break;
        case 0x011F: /* ğ */ out_buf[out_pos++] = 0x0C; break;
        case 0x015E: /* Ş */ out_buf[out_pos++] = 0x1C; break;
        case 0x015F: /* ş */ out_buf[out_pos++] = 0x1D; break;
        case 0x0130: /* İ */ out_buf[out_pos++] = 0x40; break;
        case 0x00E7: /* ç */ out_buf[out_pos++] = 0x60; break;
        case 0x00D6: /* Ö */ out_buf[out_pos++] = 0x5C; break;
        case 0x00F6: /* ö */ out_buf[out_pos++] = 0x7C; break;
        case 0x00DC: /* Ü */ out_buf[out_pos++] = 0x5E; break;
        case 0x00FC: /* ü */ out_buf[out_pos++] = 0x7E; break;
        default:
            if (cp < 0x80) {
                out_buf[out_pos++] = (uint8_t)cp;
            } else {
                out_buf[out_pos++] = '?';
            }
            break;
        }
    }

    if (out_len) *out_len = out_pos;
    return 0;
}

/* UTF-8 to UCS-2 (Big-Endian) Converter */
int smpp_utf8_to_ucs2(const char *utf8_str, uint8_t *ucs2_buf, size_t max_out, size_t *out_len)
{
    if (!utf8_str || !ucs2_buf || max_out < 2) return -1;

    size_t out_pos = 0;
    const char *p = utf8_str;
    while (*p) {
        if (out_pos + 2 > max_out) return -2;
        uint32_t cp = utf8_next(&p);
        if (cp > 0xFFFF) cp = '?'; /* BMP only for UCS-2 */

        ucs2_buf[out_pos++] = (uint8_t)((cp >> 8) & 0xFF);
        ucs2_buf[out_pos++] = (uint8_t)(cp & 0xFF);
    }

    if (out_len) *out_len = out_pos;
    return 0;
}

/* UCS-2 (Big-Endian) to UTF-8 Converter */
int smpp_ucs2_to_utf8(const uint8_t *ucs2_buf, size_t ucs2_len, char *utf8_buf, size_t max_out)
{
    if (!ucs2_buf || !utf8_buf || max_out < 1) return -1;

    size_t out_pos = 0;
    for (size_t i = 0; i + 1 < ucs2_len; i += 2) {
        uint32_t cp = (ucs2_buf[i] << 8) | ucs2_buf[i + 1];

        if (cp < 0x80) {
            if (out_pos + 1 >= max_out) break;
            utf8_buf[out_pos++] = (char)cp;
        } else if (cp < 0x800) {
            if (out_pos + 2 >= max_out) break;
            utf8_buf[out_pos++] = (char)(0xC0 | (cp >> 6));
            utf8_buf[out_pos++] = (char)(0x80 | (cp & 0x3F));
        } else {
            if (out_pos + 3 >= max_out) break;
            utf8_buf[out_pos++] = (char)(0xE0 | (cp >> 12));
            utf8_buf[out_pos++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            utf8_buf[out_pos++] = (char)(0x80 | (cp & 0x3F));
        }
    }
    utf8_buf[out_pos] = '\0';
    return (int)out_pos;
}

/* Transliteration Engine: Fold Accents and Regional Chars to Safe ASCII */
int smpp_nli_transliterate(const char *in_utf8, char *out_ascii, size_t max_out)
{
    if (!in_utf8 || !out_ascii || max_out < 1) return -1;

    size_t out_pos = 0;
    const char *p = in_utf8;
    while (*p) {
        if (out_pos + 1 >= max_out) break;
        uint32_t cp = utf8_next(&p);

        switch (cp) {
        /* Turkish */
        case 0x011E: out_ascii[out_pos++] = 'G'; break;
        case 0x011F: out_ascii[out_pos++] = 'g'; break;
        case 0x0130: out_ascii[out_pos++] = 'I'; break;
        case 0x0131: out_ascii[out_pos++] = 'i'; break;
        case 0x015E: out_ascii[out_pos++] = 'S'; break;
        case 0x015F: out_ascii[out_pos++] = 's'; break;
        case 0x00C7: out_ascii[out_pos++] = 'C'; break;
        case 0x00E7: out_ascii[out_pos++] = 'c'; break;
        case 0x00D6: out_ascii[out_pos++] = 'O'; break;
        case 0x00F6: out_ascii[out_pos++] = 'o'; break;
        case 0x00DC: out_ascii[out_pos++] = 'U'; break;
        case 0x00FC: out_ascii[out_pos++] = 'u'; break;
        /* Spanish / Portuguese */
        case 0x00D1: out_ascii[out_pos++] = 'N'; break;
        case 0x00F1: out_ascii[out_pos++] = 'n'; break;
        case 0x00C1: case 0x00C0: case 0x00C2: case 0x00C3: out_ascii[out_pos++] = 'A'; break;
        case 0x00E1: case 0x00E0: case 0x00E2: case 0x00E3: out_ascii[out_pos++] = 'a'; break;
        case 0x00C9: case 0x00CA: out_ascii[out_pos++] = 'E'; break;
        case 0x00E9: case 0x00EA: out_ascii[out_pos++] = 'e'; break;
        case 0x00CD: out_ascii[out_pos++] = 'I'; break;
        case 0x00ED: out_ascii[out_pos++] = 'i'; break;
        case 0x00D3: case 0x00D4: case 0x00D5: out_ascii[out_pos++] = 'O'; break;
        case 0x00F3: case 0x00F4: case 0x00F5: out_ascii[out_pos++] = 'o'; break;
        case 0x00DA: out_ascii[out_pos++] = 'U'; break;
        case 0x00FA: out_ascii[out_pos++] = 'u'; break;
        default:
            if (cp < 0x80) {
                out_ascii[out_pos++] = (char)cp;
            } else {
                out_ascii[out_pos++] = '?';
            }
            break;
        }
    }
    out_ascii[out_pos] = '\0';
    return (int)out_pos;
}
