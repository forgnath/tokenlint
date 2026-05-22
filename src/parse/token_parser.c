/*
 * src/parse/token_parser.c
 *
 * JWT string → token_t.
 *
 * Parses a compact-serialized JWT (header.payload.signature) into the
 * normalised token_t struct.  This is the only parse-layer file that performs
 * base64url decoding (via mbedTLS) and minimal JSON field extraction.
 *
 * After this file, all evaluation code works exclusively against token_t.
 * No raw JWT strings, no base64 decoding, no JSON traversal in eval/.
 *
 * JSON parsing: hand-rolled minimal extractor — JWT headers/payloads are
 * small, well-constrained JSON objects; we only need specific well-known fields.
 *
 * Error handling:
 *   Structural failure  → add TL-V000 to fs, return TL_ERR_TOKEN.
 *   alg=none            → add TL-S001 to fs, return TL_ERR_TOKEN.
 *   alg absent          → add TL-V001 to fs, return TL_ERR_TOKEN.
 *   alg unrecognized    → add TL-V002 to fs, return TL_ERR_TOKEN.
 *   Individual missing claims do NOT fail parse — they produce findings
 *   during evaluation (eval_validate).
 *
 * mbedTLS and str.h are permitted in src/parse/ per the architecture.
 */

#define _POSIX_C_SOURCE 200809L

#include "tokenlint.h"
#include "str.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"    /* CLAIM_* bitmask constants */
#include "token.h"

#include <mbedtls/base64.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ── alg string → alg_id_t ──────────────────────────────────────────────── */

static alg_id_t alg_from_str(const char *s, size_t n) {
    static const struct { const char *name; alg_id_t id; } map[] = {
        {"RS256", ALG_RS256}, {"RS384", ALG_RS384}, {"RS512", ALG_RS512},
        {"PS256", ALG_PS256}, {"PS384", ALG_PS384}, {"PS512", ALG_PS512},
        {"ES256", ALG_ES256}, {"ES384", ALG_ES384}, {"ES512", ALG_ES512},
        {"EdDSA", ALG_ECDSA_EDDSA},
        {"HS256", ALG_HS256}, {"HS384", ALG_HS384}, {"HS512", ALG_HS512},
    };
    for (size_t i = 0; i < sizeof(map)/sizeof(map[0]); i++) {
        if (strlen(map[i].name) == n && memcmp(map[i].name, s, n) == 0)
            return map[i].id;
    }
    return ALG_NONE_ALG;
}

/* ── finding helper ─────────────────────────────────────────────────────── */

static void add_finding_lit(finding_set_t *fs, arena_t *arena,
                              const char *id, const char *title,
                              severity_t sev, const char *detail)
{
    finding_t f;
    memset(&f, 0, sizeof f);
    f.id       = str_from_cstr(id);
    f.title    = str_from_cstr(title);
    f.detail   = str_from_cstr(detail);
    f.severity = sev;
    f.status   = FINDING_ACTIVE;
    int added = findings_add(fs, &f, arena, NULL, 0);
    TL_UNUSED(added);
}

/* ── base64url decode ───────────────────────────────────────────────────── */

/*
 * Decode a base64url string (no padding) into the arena.
 * Returns 1 on success, 0 on failure.
 */
static int b64url_decode(arena_t *arena, const char *in, size_t in_len,
                          uint8_t **out, size_t *out_len)
{
    if (in_len == 0) {
        *out     = NULL;
        *out_len = 0;
        return 1;
    }

    /* Convert base64url → standard base64 with padding in arena */
    size_t padded_cap = in_len + 4;
    char *tmp = (char *)arena_alloc(arena, padded_cap, 1);
    if (!tmp) return 0;

    memcpy(tmp, in, in_len);
    for (size_t i = 0; i < in_len; i++) {
        if (tmp[i] == '-') tmp[i] = '+';
        else if (tmp[i] == '_') tmp[i] = '/';
    }
    size_t padded = in_len;
    switch (in_len % 4) {
        case 2: tmp[padded++] = '='; tmp[padded++] = '='; break;
        case 3: tmp[padded++] = '='; break;
        default: break;
    }
    tmp[padded] = '\0';

    /* Probe for output length */
    size_t decoded_len = 0;
    int rc = mbedtls_base64_decode(NULL, 0, &decoded_len,
                                    (const unsigned char *)tmp, padded);
    /* mbedtls returns MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL when dst==NULL */
    if (rc != 0 && decoded_len == 0) return 0;

    uint8_t *buf = (uint8_t *)arena_alloc(arena, decoded_len, 1);
    if (!buf) return 0;

    if (mbedtls_base64_decode(buf, decoded_len, out_len,
                               (const unsigned char *)tmp, padded) != 0)
        return 0;

    *out = buf;
    return 1;
}

/* ── minimal JSON field extractor ───────────────────────────────────────── */

static size_t json_skip_ws(const char *s, size_t i, size_t n) {
    while (i < n && (s[i] == ' ' || s[i] == '\t' ||
                     s[i] == '\r' || s[i] == '\n')) i++;
    return i;
}

/* Parse a JSON string starting at s[i] (i must point to opening '"').
 * Writes unescaped bytes into buf (NUL-terminated).
 * Returns index past closing '"', or (size_t)-1 on error. */
static size_t json_parse_string(const char *s, size_t i, size_t n,
                                  char *buf, size_t buf_cap, size_t *len_out)
{
    if (i >= n || s[i] != '"') return (size_t)-1;
    i++;
    size_t out = 0;
    while (i < n && s[i] != '"') {
        char ch;
        if (s[i] == '\\') {
            i++;
            if (i >= n) return (size_t)-1;
            switch (s[i]) {
                case '"':  ch = '"';  break;
                case '\\': ch = '\\'; break;
                case '/':  ch = '/';  break;
                case 'n':  ch = '\n'; break;
                case 'r':  ch = '\r'; break;
                case 't':  ch = '\t'; break;
                default:   ch = s[i]; break;
            }
        } else {
            ch = s[i];
        }
        if (buf && out + 1 < buf_cap) buf[out] = ch;
        out++;
        i++;
    }
    if (i >= n) return (size_t)-1;
    if (buf && out < buf_cap) buf[out] = '\0';
    if (len_out) *len_out = out;
    return i + 1;
}

/* Skip a JSON value (string, number, bool, null, or nested object/array). */
static size_t json_skip_value(const char *s, size_t i, size_t n)
{
    i = json_skip_ws(s, i, n);
    if (i >= n) return (size_t)-1;
    if (s[i] == '"') {
        char tmp[4096];
        return json_parse_string(s, i, n, tmp, sizeof(tmp), NULL);
    }
    if (s[i] == '{' || s[i] == '[') {
        char open = s[i], close = (s[i] == '{') ? '}' : ']';
        int depth = 1; i++;
        while (i < n && depth > 0) {
            if (s[i] == open) depth++;
            else if (s[i] == close) depth--;
            else if (s[i] == '"') {
                /* skip string inside */
                char tmp[4096];
                size_t ni = json_parse_string(s, i, n, tmp, sizeof(tmp), NULL);
                if (ni == (size_t)-1) return (size_t)-1;
                i = ni;
                continue;
            }
            i++;
        }
        return i;
    }
    /* number, true, false, null */
    while (i < n && s[i] != ',' && s[i] != '}' && s[i] != ']' &&
           s[i] != ' ' && s[i] != '\t' && s[i] != '\r' && s[i] != '\n')
        i++;
    return i;
}

/*
 * json_get_string — extract a top-level string field.
 * Returns 1 on success, 0 on not-found / wrong type.
 */
static int json_get_string(const char *json, size_t json_len,
                             const char *key,
                             char *val_buf, size_t val_cap,
                             size_t *val_len_out)
{
    size_t key_len = strlen(key);
    size_t i = json_skip_ws(json, 0, json_len);
    if (i >= json_len || json[i] != '{') return 0;
    i++;

    while (i < json_len) {
        i = json_skip_ws(json, i, json_len);
        if (i >= json_len || json[i] == '}') break;
        if (json[i] == ',') { i++; continue; }

        char kbuf[256]; size_t klen = 0;
        size_t ni = json_parse_string(json, i, json_len, kbuf, sizeof(kbuf), &klen);
        if (ni == (size_t)-1) return 0;
        i = ni;

        i = json_skip_ws(json, i, json_len);
        if (i >= json_len || json[i] != ':') return 0;
        i++;
        i = json_skip_ws(json, i, json_len);

        if (klen == key_len && memcmp(kbuf, key, klen) == 0) {
            if (i >= json_len || json[i] != '"') return 0;
            ni = json_parse_string(json, i, json_len, val_buf, val_cap, val_len_out);
            return ni != (size_t)-1 ? 1 : 0;
        }

        size_t skip = json_skip_value(json, i, json_len);
        if (skip == (size_t)-1) return 0;
        i = skip;
    }
    return 0;
}

/*
 * json_get_int64 — extract a top-level integer field.
 * Returns 1 on success, 0 on not-found / wrong type.
 */
static int json_get_int64(const char *json, size_t json_len,
                           const char *key, int64_t *out)
{
    size_t key_len = strlen(key);
    size_t i = json_skip_ws(json, 0, json_len);
    if (i >= json_len || json[i] != '{') return 0;
    i++;

    while (i < json_len) {
        i = json_skip_ws(json, i, json_len);
        if (i >= json_len || json[i] == '}') break;
        if (json[i] == ',') { i++; continue; }

        char kbuf[256]; size_t klen = 0;
        size_t ni = json_parse_string(json, i, json_len, kbuf, sizeof(kbuf), &klen);
        if (ni == (size_t)-1) return 0;
        i = ni;

        i = json_skip_ws(json, i, json_len);
        if (i >= json_len || json[i] != ':') return 0;
        i++;
        i = json_skip_ws(json, i, json_len);

        if (klen == key_len && memcmp(kbuf, key, klen) == 0) {
            /* Collect raw number bytes */
            char nbuf[32];
            size_t nlen = 0;
            size_t j = i;
            if (j < json_len && json[j] == '-') { nbuf[nlen++] = json[j++]; }
            while (j < json_len && json[j] >= '0' && json[j] <= '9') {
                if (nlen + 1 < sizeof(nbuf)) nbuf[nlen++] = json[j];
                j++;
            }
            if (nlen == 0) return 0;
            str_t s;
            s.data = nbuf;
            s.len  = nlen;
            return str_to_i64(s, out);
        }

        size_t skip = json_skip_value(json, i, json_len);
        if (skip == (size_t)-1) return 0;
        i = skip;
    }
    return 0;
}

/*
 * json_get_aud — extract the "aud" claim (string or string array).
 * Returns 1 on success, 0 on not-found / wrong type.
 */
static int json_get_aud(const char *json, size_t json_len, arena_t *arena,
                          str_t **vals_out, size_t *count_out)
{
    size_t i = json_skip_ws(json, 0, json_len);
    if (i >= json_len || json[i] != '{') return 0;
    i++;

    while (i < json_len) {
        i = json_skip_ws(json, i, json_len);
        if (i >= json_len || json[i] == '}') break;
        if (json[i] == ',') { i++; continue; }

        char kbuf[256]; size_t klen = 0;
        size_t ni = json_parse_string(json, i, json_len, kbuf, sizeof(kbuf), &klen);
        if (ni == (size_t)-1) return 0;
        i = ni;

        i = json_skip_ws(json, i, json_len);
        if (i >= json_len || json[i] != ':') return 0;
        i++;
        i = json_skip_ws(json, i, json_len);

        if (klen == 3 && memcmp(kbuf, "aud", 3) == 0) {
            if (json[i] == '"') {
                /* Single string */
                char vbuf[2048]; size_t vlen = 0;
                ni = json_parse_string(json, i, json_len, vbuf, sizeof(vbuf), &vlen);
                if (ni == (size_t)-1) return 0;
                str_t *arr = ARENA_ALLOC_ARRAY(arena, str_t, 1);
                if (!arr) return 0;
                arr[0]     = arena_strdup(arena, (str_t){ vbuf, vlen });
                *vals_out  = arr;
                *count_out = 1;
                return 1;
            } else if (json[i] == '[') {
                /* Array */
                i++; /* skip '[' */
                /* Two-pass: count, then fill */
                size_t save = i;
                size_t count = 0;
                while (i < json_len && json[i] != ']') {
                    i = json_skip_ws(json, i, json_len);
                    if (i >= json_len || json[i] == ']') break;
                    if (json[i] == ',') { i++; continue; }
                    if (json[i] != '"') return 0;
                    char tmp[2048];
                    ni = json_parse_string(json, i, json_len, tmp, sizeof(tmp), NULL);
                    if (ni == (size_t)-1) return 0;
                    i = ni; count++;
                }
                if (count == 0) {
                    *vals_out = NULL; *count_out = 0; return 1;
                }
                str_t *arr = ARENA_ALLOC_ARRAY(arena, str_t, count);
                if (!arr) return 0;
                i = save; size_t idx = 0;
                while (i < json_len && json[i] != ']') {
                    i = json_skip_ws(json, i, json_len);
                    if (i >= json_len || json[i] == ']') break;
                    if (json[i] == ',') { i++; continue; }
                    char vbuf[2048]; size_t vlen = 0;
                    ni = json_parse_string(json, i, json_len, vbuf, sizeof(vbuf), &vlen);
                    if (ni == (size_t)-1) return 0;
                    arr[idx++] = arena_strdup(arena, (str_t){ vbuf, vlen });
                    i = ni;
                }
                *vals_out = arr; *count_out = count;
                return 1;
            }
            return 0;
        }

        size_t skip = json_skip_value(json, i, json_len);
        if (skip == (size_t)-1) return 0;
        i = skip;
    }
    return 0;
}

/* ── token_parse ─────────────────────────────────────────────────────────── */

tl_error_t token_parse(arena_t       *arena,
                        str_t          raw_jwt,
                        finding_set_t *fs,
                        token_t      **out)
{
    /* Guard: empty or null JWT */
    if (STR_IS_NULL(raw_jwt) || raw_jwt.len == 0) {
        add_finding_lit(fs, arena, "TL-V000", "TOKEN_UNPARSEABLE",
                         SEV_FAIL, "JWT is empty or null");
        return tl_error(TL_ERR_TOKEN, "empty JWT", STR_NULL);
    }

    /* Split on '.' — must have exactly three parts */
    str_t header_b64, payload_b64, sig_b64;
    {
        size_t dot1 = (size_t)-1, dot2 = (size_t)-1;
        for (size_t i = 0; i < raw_jwt.len; i++) {
            if (raw_jwt.data[i] == '.') {
                if (dot1 == (size_t)-1)      dot1 = i;
                else if (dot2 == (size_t)-1) { dot2 = i; break; }
            }
        }
        if (dot1 == (size_t)-1 || dot2 == (size_t)-1) {
            add_finding_lit(fs, arena, "TL-V000", "TOKEN_UNPARSEABLE",
                             SEV_FAIL, "JWT does not have three parts");
            return tl_error(TL_ERR_TOKEN, "malformed JWT", STR_NULL);
        }
        header_b64.data  = raw_jwt.data;
        header_b64.len   = dot1;
        payload_b64.data = raw_jwt.data + dot1 + 1;
        payload_b64.len  = dot2 - dot1 - 1;
        sig_b64.data     = raw_jwt.data + dot2 + 1;
        sig_b64.len      = raw_jwt.len - dot2 - 1;
    }

    /* Decode header */
    uint8_t *header_bytes = NULL; size_t header_len = 0;
    if (!b64url_decode(arena, header_b64.data, header_b64.len,
                        &header_bytes, &header_len)) {
        add_finding_lit(fs, arena, "TL-V000", "TOKEN_UNPARSEABLE",
                         SEV_FAIL, "JWT header base64url decode failed");
        return tl_error(TL_ERR_TOKEN, "header decode failed", STR_NULL);
    }

    /* Decode payload */
    uint8_t *payload_bytes = NULL; size_t payload_len = 0;
    if (!b64url_decode(arena, payload_b64.data, payload_b64.len,
                        &payload_bytes, &payload_len)) {
        add_finding_lit(fs, arena, "TL-V000", "TOKEN_UNPARSEABLE",
                         SEV_FAIL, "JWT payload base64url decode failed");
        return tl_error(TL_ERR_TOKEN, "payload decode failed", STR_NULL);
    }

    /* Decode signature */
    uint8_t *sig_bytes = NULL; size_t sig_len = 0;
    if (sig_b64.len > 0) {
        if (!b64url_decode(arena, sig_b64.data, sig_b64.len,
                            &sig_bytes, &sig_len)) {
            add_finding_lit(fs, arena, "TL-V000", "TOKEN_UNPARSEABLE",
                             SEV_FAIL, "JWT signature base64url decode failed");
            return tl_error(TL_ERR_TOKEN, "signature decode failed", STR_NULL);
        }
    }

    const char *header_json  = (const char *)header_bytes;
    const char *payload_json = (const char *)payload_bytes;

    /* ── alg ── */
    char alg_str[32]; size_t alg_len = 0;
    if (!json_get_string(header_json, header_len,
                          "alg", alg_str, sizeof(alg_str), &alg_len)) {
        add_finding_lit(fs, arena, "TL-V001", "TOKEN_ALG_ABSENT",
                         SEV_FAIL, "JWT header missing 'alg' field");
        return tl_error(TL_ERR_TOKEN, "alg absent", STR_NULL);
    }

    /* alg=none check (case-insensitive) */
    if (alg_len == 4 &&
        (alg_str[0]|32) == 'n' && (alg_str[1]|32) == 'o' &&
        (alg_str[2]|32) == 'n' && (alg_str[3]|32) == 'e') {
        add_finding_lit(fs, arena, "TL-S001", "TOKEN_ALG_NONE",
                         SEV_CRITICAL, "alg=none is forbidden");
        return tl_error(TL_ERR_TOKEN, "alg=none", STR_NULL);
    }

    alg_id_t alg = alg_from_str(alg_str, alg_len);
    if (alg == ALG_NONE_ALG) {
        add_finding_lit(fs, arena, "TL-V002", "TOKEN_ALG_UNRECOGNIZED",
                         SEV_FAIL, "JWT alg is not a recognized algorithm");
        return tl_error(TL_ERR_TOKEN, "unrecognized alg", STR_NULL);
    }

    /* ── kid ── */
    char kid_str[512]; size_t kid_len = 0;
    int has_kid = json_get_string(header_json, header_len,
                                   "kid", kid_str, sizeof(kid_str), &kid_len);

    /* ── Allocate token_t ── */
    token_t *tok = ARENA_ALLOC_ONE(arena, token_t);
    TL_RETURN_IF_NULL(tok, "arena exhausted allocating token_t");

    tok->alg = alg;
    tok->kid = (has_kid && kid_len > 0)
               ? arena_strdup(arena, (str_t){ kid_str, kid_len })
               : STR_NULL;

    /* ── Registered claims ── */
    char tmp[2048]; size_t tmp_len = 0;

    if (json_get_string(payload_json, payload_len, "iss", tmp, sizeof(tmp), &tmp_len)) {
        tok->iss = arena_strdup(arena, (str_t){ tmp, tmp_len });
        tok->present_claims |= CLAIM_ISS;
    }
    if (json_get_string(payload_json, payload_len, "sub", tmp, sizeof(tmp), &tmp_len)) {
        tok->sub = arena_strdup(arena, (str_t){ tmp, tmp_len });
        tok->present_claims |= CLAIM_SUB;
    }

    str_t *aud_vals = NULL; size_t aud_count = 0;
    if (json_get_aud(payload_json, payload_len, arena, &aud_vals, &aud_count)) {
        tok->aud       = aud_vals;
        tok->aud_count = aud_count;
        if (aud_count > 0) tok->present_claims |= CLAIM_AUD;
    }

    { int64_t v = 0;
      if (json_get_int64(payload_json, payload_len, "exp", &v)) {
          tok->exp = v; tok->present_claims |= CLAIM_EXP; } }
    { int64_t v = 0;
      if (json_get_int64(payload_json, payload_len, "nbf", &v)) {
          tok->nbf = v; tok->present_claims |= CLAIM_NBF; } }
    { int64_t v = 0;
      if (json_get_int64(payload_json, payload_len, "iat", &v)) {
          tok->iat = v; tok->present_claims |= CLAIM_IAT; } }

    if (json_get_string(payload_json, payload_len, "jti", tmp, sizeof(tmp), &tmp_len)) {
        tok->jti = arena_strdup(arena, (str_t){ tmp, tmp_len });
        tok->present_claims |= CLAIM_JTI;
    }

    /* ── Signing input: "header_b64.payload_b64" ── */
    size_t si_len = header_b64.len + 1 + payload_b64.len;
    uint8_t *si   = (uint8_t *)arena_alloc(arena, si_len, 1);
    TL_RETURN_IF_NULL(si, "arena exhausted for signing_input");
    memcpy(si, header_b64.data, header_b64.len);
    si[header_b64.len] = '.';
    memcpy(si + header_b64.len + 1, payload_b64.data, payload_b64.len);

    tok->signing_input     = si;
    tok->signing_input_len = si_len;
    tok->sig               = sig_bytes;
    tok->sig_len           = sig_len;

    *out = tok;
    return TL_OK;
}
