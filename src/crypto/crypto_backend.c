/*
 * src/crypto/crypto_backend.c
 *
 * mbedTLS crypto adapter for tokenlint v1.
 *
 * This is the ONLY file in the project that includes mbedTLS headers.
 * No mbedTLS types or symbols appear outside this file.
 *
 * Exposes two symbols:
 *   tl_verify_signature()   — JWT signature verification
 *   tl_base64url_decode()   — base64url decoding (arena-allocated)
 *
 * Algorithm support:
 *   RS256/384/512  — RSASSA-PKCS1-v1_5 via mbedtls_pk_verify
 *   PS256/384/512  — RSASSA-PSS via mbedtls_rsa_set_padding + pk_verify
 *   ES256/384/512  — ECDSA via mbedtls_pk_verify
 *   EdDSA          — Ed25519 unsupported in mbedTLS 2.28 → TL_VERIFY_UNSUPPORTED
 *   HS256/384/512  — HMAC via mbedtls_md_hmac
 *   Ed448          — TL_VERIFY_UNSUPPORTED (per algorithm-contract.md)
 *
 * Key material:
 *   key->key_material is a NUL-terminated JWK JSON object (set by jwks_parser.c).
 *   We parse the relevant b64url fields (n/e for RSA, x/y for EC, k for oct)
 *   and import into an mbedtls_pk_context or use HMAC directly.
 *
 * Security:
 *   All mbedtls contexts are freed on every exit path (success and error).
 *   Temporary decode buffers live in the arena and are not explicitly zeroed
 *   here; arena_free() zeroes them at run exit (per arena.c design).
 */

#define _POSIX_C_SOURCE 200809L

#include "tokenlint.h"
#include "alg.h"
#include "jwks.h"
#include "crypto_backend.h"

/* mbedTLS headers — confined to this translation unit */
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/bignum.h>
#include <mbedtls/error.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* Compile-time assertions from architecture.md */
_Static_assert(ALG_COUNT_ <= 32,
    "alg_id_t exceeds bitmask capacity of alg_allowset_t");


/* =========================================================================
 * Internal: base64url → standard base64 conversion
 * ========================================================================= */

/*
 * b64url_to_bytes — decode a base64url string (no padding) to raw bytes.
 * Decodes into a temporary buffer allocated from the arena.
 * Returns decoded byte count on success, 0 on failure.
 */
static size_t b64url_to_bytes(arena_t *arena,
                               const char *in, size_t in_len,
                               uint8_t **out)
{
    if (in_len == 0) { *out = NULL; return 0; }

    /* Convert base64url to standard base64 with padding */
    size_t cap = in_len + 4;
    char *tmp = (char *)arena_alloc(arena, cap, 1);
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
    /* mbedTLS returns BUFFER_TOO_SMALL when dst==NULL; that's expected */
    if (rc != 0 && decoded_len == 0) return 0;

    uint8_t *buf = (uint8_t *)arena_alloc(arena, decoded_len, 1);
    if (!buf) return 0;

    size_t actual = 0;
    if (mbedtls_base64_decode(buf, decoded_len, &actual,
                              (const unsigned char *)tmp, padded) != 0)
        return 0;

    *out = buf;
    return actual;
}


/* =========================================================================
 * Public: tl_base64url_decode
 * ========================================================================= */

tl_error_t tl_base64url_decode(arena_t    *arena,
                                const char *input,
                                size_t      input_len,
                                uint8_t   **out,
                                size_t     *out_len)
{
    size_t n = b64url_to_bytes(arena, input, input_len, out);
    if (n == 0 && input_len > 0)
        return tl_error_internal("base64url decode failed");
    *out_len = n;
    return TL_OK;
}


/* =========================================================================
 * Internal: minimal JWK field extractor
 *
 * key_material is NUL-terminated JWK JSON; we need individual b64url fields.
 * This is intentionally minimal — no full JSON parser needed.
 * ========================================================================= */

/*
 * jwk_get_field — extract a string field value from JWK JSON.
 * Returns 1 on success, 0 if field absent.
 * buf/buf_cap: caller-provided temporary buffer.
 */
static int jwk_get_field(const char *json, size_t json_len,
                          const char *field,
                          char *buf, size_t buf_cap,
                          size_t *val_len)
{
    /* Search for "field": "value" */
    size_t field_len = strlen(field);
    size_t i = 0;

    while (i + field_len + 4 < json_len) {
        /* Find '"' */
        if (json[i] != '"') { i++; continue; }
        /* Check if key matches */
        if (i + 1 + field_len + 1 < json_len &&
            memcmp(json + i + 1, field, field_len) == 0 &&
            json[i + 1 + field_len] == '"') {
            /* Skip past key and colon */
            size_t j = i + 1 + field_len + 1;
            while (j < json_len &&
                   (json[j] == ' ' || json[j] == '\t' ||
                    json[j] == '\r' || json[j] == '\n' || json[j] == ':'))
                j++;
            if (j >= json_len || json[j] != '"') { i++; continue; }
            j++; /* skip opening quote */
            size_t start = j;
            while (j < json_len && json[j] != '"') j++;
            if (j >= json_len) return 0;
            size_t vlen = j - start;
            if (vlen >= buf_cap) return 0;
            memcpy(buf, json + start, vlen);
            buf[vlen] = '\0';
            *val_len = vlen;
            return 1;
        }
        i++;
    }
    return 0;
}

/*
 * decode_jwk_field — decode a b64url field from JWK JSON into arena bytes.
 * Returns byte count on success, 0 on failure.
 */
static size_t decode_jwk_field(arena_t *arena,
                                const char *json, size_t json_len,
                                const char *field,
                                uint8_t **out)
{
    char buf[8192];
    size_t vlen = 0;
    if (!jwk_get_field(json, json_len, field, buf, sizeof(buf), &vlen))
        return 0;
    return b64url_to_bytes(arena, buf, vlen, out);
}


/* =========================================================================
 * Internal: map alg_id_t → mbedtls_md_type_t
 * ========================================================================= */

static mbedtls_md_type_t alg_to_md(alg_id_t alg)
{
    switch (alg) {
        case ALG_RS256: case ALG_PS256: case ALG_ES256: case ALG_HS256:
            return MBEDTLS_MD_SHA256;
        case ALG_RS384: case ALG_PS384: case ALG_ES384: case ALG_HS384:
            return MBEDTLS_MD_SHA384;
        case ALG_RS512: case ALG_PS512: case ALG_ES512: case ALG_HS512:
            return MBEDTLS_MD_SHA512;
        default:
            return MBEDTLS_MD_NONE;
    }
}


/* =========================================================================
 * Internal: hash signing_input
 * ========================================================================= */

static int compute_hash(mbedtls_md_type_t md_type,
                         const uint8_t *data, size_t data_len,
                         uint8_t *hash_out, size_t *hash_len)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    if (!md_info) return 0;
    size_t sz = mbedtls_md_get_size(md_info);
    if (mbedtls_md(md_info, data, data_len, hash_out) != 0) return 0;
    *hash_len = sz;
    return 1;
}


/* =========================================================================
 * Internal: import RSA key from JWK JSON and verify
 * ========================================================================= */

static tl_verify_result_t verify_rsa(arena_t *arena,
                                      alg_id_t alg,
                                      const char *json, size_t json_len,
                                      const uint8_t *signing_input,
                                      size_t signing_input_len,
                                      const uint8_t *sig, size_t sig_len)
{
    uint8_t *n_bytes = NULL, *e_bytes = NULL;
    size_t n_len = decode_jwk_field(arena, json, json_len, "n", &n_bytes);
    size_t e_len = decode_jwk_field(arena, json, json_len, "e", &e_bytes);

    if (n_len == 0 || e_len == 0) return TL_VERIFY_ERROR;

    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

    tl_verify_result_t result = TL_VERIFY_ERROR;

    mbedtls_mpi N, E;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&E);

    if (mbedtls_mpi_read_binary(&N, n_bytes, n_len) != 0) goto cleanup_mpi;
    if (mbedtls_mpi_read_binary(&E, e_bytes, e_len) != 0) goto cleanup_mpi;
    if (mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E) != 0) goto cleanup_mpi;
    if (mbedtls_rsa_complete(&rsa) != 0) goto cleanup_mpi;

    /* Set padding mode */
    if (alg == ALG_PS256 || alg == ALG_PS384 || alg == ALG_PS512) {
        mbedtls_md_type_t md = alg_to_md(alg);
        mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, md);
    }

    /* Hash the signing input */
    mbedtls_md_type_t md_type = alg_to_md(alg);
    uint8_t hash[64]; /* SHA-512 max */
    size_t hash_len = 0;
    if (!compute_hash(md_type, signing_input, signing_input_len, hash, &hash_len))
        goto cleanup_mpi;

    /* Verify */
    int ret;
    if (alg == ALG_PS256 || alg == ALG_PS384 || alg == ALG_PS512) {
        ret = mbedtls_rsa_rsassa_pss_verify(&rsa, NULL, NULL,
                                            MBEDTLS_RSA_PUBLIC,
                                            md_type, (unsigned)hash_len,
                                            hash, sig);
    } else {
        ret = mbedtls_rsa_rsassa_pkcs1_v15_verify(&rsa, NULL, NULL,
                                                   MBEDTLS_RSA_PUBLIC,
                                                   md_type,
                                                   (unsigned)hash_len,
                                                   hash, sig);
    }
    result = (ret == 0) ? TL_VERIFY_OK : TL_VERIFY_FAIL;

cleanup_mpi:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    mbedtls_rsa_free(&rsa);
    TL_UNUSED(sig_len);
    return result;
}


/* =========================================================================
 * Internal: import EC key from JWK JSON and verify (ECDSA)
 * ========================================================================= */

static tl_verify_result_t verify_ec(arena_t *arena,
                                     alg_id_t alg,
                                     crv_t crv,
                                     const char *json, size_t json_len,
                                     const uint8_t *signing_input,
                                     size_t signing_input_len,
                                     const uint8_t *sig, size_t sig_len)
{
    /* Map crv to mbedtls group */
    mbedtls_ecp_group_id grp_id;
    switch (crv) {
        case CRV_P256:  grp_id = MBEDTLS_ECP_DP_SECP256R1; break;
        case CRV_P384:  grp_id = MBEDTLS_ECP_DP_SECP384R1; break;
        case CRV_P521:  grp_id = MBEDTLS_ECP_DP_SECP521R1; break;
        default: return TL_VERIFY_ERROR;
    }

    uint8_t *x_bytes = NULL, *y_bytes = NULL;
    size_t x_len = decode_jwk_field(arena, json, json_len, "x", &x_bytes);
    size_t y_len = decode_jwk_field(arena, json, json_len, "y", &y_bytes);
    if (x_len == 0 || y_len == 0) return TL_VERIFY_ERROR;

    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa);

    tl_verify_result_t result = TL_VERIFY_ERROR;

    if (mbedtls_ecp_group_load(&ecdsa.grp, grp_id) != 0) goto cleanup_ec;

    /* Import Q = (x, y) */
    if (mbedtls_mpi_read_binary(&ecdsa.Q.X, x_bytes, x_len) != 0) goto cleanup_ec;
    if (mbedtls_mpi_read_binary(&ecdsa.Q.Y, y_bytes, y_len) != 0) goto cleanup_ec;
    if (mbedtls_mpi_lset(&ecdsa.Q.Z, 1) != 0) goto cleanup_ec;

    /* Validate the public key point */
    if (mbedtls_ecp_check_pubkey(&ecdsa.grp, &ecdsa.Q) != 0) goto cleanup_ec;

    /* Hash signing input */
    mbedtls_md_type_t md_type = alg_to_md(alg);
    uint8_t hash[64];
    size_t hash_len = 0;
    if (!compute_hash(md_type, signing_input, signing_input_len, hash, &hash_len))
        goto cleanup_ec;

    /* Verify DER-encoded ECDSA signature */
    int ret = mbedtls_ecdsa_read_signature(&ecdsa, hash, hash_len, sig, sig_len);
    result = (ret == 0) ? TL_VERIFY_OK : TL_VERIFY_FAIL;

cleanup_ec:
    mbedtls_ecdsa_free(&ecdsa);
    return result;
}


/* =========================================================================
 * Internal: HMAC verification (HS256/384/512)
 * ========================================================================= */

static tl_verify_result_t verify_hmac(arena_t *arena,
                                       alg_id_t alg,
                                       const char *json, size_t json_len,
                                       const uint8_t *signing_input,
                                       size_t signing_input_len,
                                       const uint8_t *sig, size_t sig_len)
{
    /* Decode the "k" field (symmetric key) */
    uint8_t *key_bytes = NULL;
    size_t key_len = decode_jwk_field(arena, json, json_len, "k", &key_bytes);
    if (key_len == 0) return TL_VERIFY_ERROR;

    mbedtls_md_type_t md_type = alg_to_md(alg);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    if (!md_info) return TL_VERIFY_ERROR;

    size_t mac_size = mbedtls_md_get_size(md_info);
    if (sig_len != mac_size) return TL_VERIFY_FAIL;

    uint8_t mac[64]; /* SHA-512 max */
    if (mbedtls_md_hmac(md_info, key_bytes, key_len,
                        signing_input, signing_input_len, mac) != 0)
        return TL_VERIFY_ERROR;

    /* Constant-time comparison */
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < mac_size; i++)
        diff |= (mac[i] ^ sig[i]);

    return (diff == 0) ? TL_VERIFY_OK : TL_VERIFY_FAIL;
}


/* =========================================================================
 * Public: tl_verify_signature
 * ========================================================================= */

tl_verify_result_t tl_verify_signature(
    arena_t            *arena,
    alg_id_t            alg,
    const jwks_key_t   *key,
    const uint8_t      *signing_input,
    size_t              signing_input_len,
    const uint8_t      *sig,
    size_t              sig_len)
{
    const char *json     = (const char *)key->key_material;
    size_t      json_len = key->key_material_len;

    switch (alg) {
        case ALG_RS256:
        case ALG_RS384:
        case ALG_RS512:
        case ALG_PS256:
        case ALG_PS384:
        case ALG_PS512:
            if (key->kty != KTY_RSA) return TL_VERIFY_ERROR;
            return verify_rsa(arena, alg, json, json_len,
                              signing_input, signing_input_len,
                              sig, sig_len);

        case ALG_ES256:
        case ALG_ES384:
        case ALG_ES512:
            if (key->kty != KTY_EC) return TL_VERIFY_ERROR;
            return verify_ec(arena, alg, key->crv, json, json_len,
                             signing_input, signing_input_len,
                             sig, sig_len);

        case ALG_ECDSA_EDDSA:
            /* Ed448: recognized in v1 but unsupported */
            if (key->crv == CRV_ED448) return TL_VERIFY_UNSUPPORTED;
            /* Ed25519: mbedTLS 2.28 lacks native EdDSA support */
            return TL_VERIFY_UNSUPPORTED;

        case ALG_HS256:
        case ALG_HS384:
        case ALG_HS512:
            if (key->kty != KTY_OCT) return TL_VERIFY_ERROR;
            return verify_hmac(arena, alg, json, json_len,
                               signing_input, signing_input_len,
                               sig, sig_len);

        default:
            return TL_VERIFY_UNSUPPORTED;
    }
}
