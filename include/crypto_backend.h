/*
 * include/crypto_backend.h
 *
 * Public interface for the crypto backend (src/crypto/crypto_backend.c).
 *
 * This is a strict firewall. Only two symbols cross the boundary:
 *   tl_verify_signature()   — verify a JWT signature against a JWKS key
 *   tl_base64url_decode()   — base64url → raw bytes (arena-allocated)
 *
 * No mbedTLS types appear in this header. No mbedTLS headers are included
 * here. All mbedTLS symbols are confined to crypto_backend.c.
 *
 * Include order: tokenlint.h → alg.h → jwks.h → crypto_backend.h
 *
 * C11 required.
 */

#ifndef TOKENLINT_CRYPTO_BACKEND_H
#define TOKENLINT_CRYPTO_BACKEND_H

#include "tokenlint.h"
#include "alg.h"
#include "jwks.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * tl_verify_result_t — result of a signature verification attempt
 * ========================================================================= */

typedef enum {
    TL_VERIFY_OK          = 0,  /* signature is valid                        */
    TL_VERIFY_FAIL        = 1,  /* signature is invalid (bad sig)            */
    TL_VERIFY_UNSUPPORTED = 2,  /* alg/curve not supported in v1 (e.g. Ed448)*/
    TL_VERIFY_ERROR       = 3   /* internal error (OOM, key parse failure)   */
} tl_verify_result_t;


/* =========================================================================
 * tl_verify_signature — verify a JWT signature
 *
 * Parameters:
 *   arena           — run arena; used for temporary allocations during
 *                     key parsing and hash computation
 *   alg             — the algorithm declared in the token header
 *   key             — the candidate JWKS key
 *   signing_input   — the raw bytes of "header.payload" (ASCII, not decoded)
 *   signing_input_len — byte length of signing_input
 *   sig             — the decoded signature bytes
 *   sig_len         — byte length of sig
 *
 * Returns:
 *   TL_VERIFY_OK          — signature verified
 *   TL_VERIFY_FAIL        — verification failed (wrong sig)
 *   TL_VERIFY_UNSUPPORTED — algorithm or curve not supported in v1
 *   TL_VERIFY_ERROR       — key parse failed, OOM, or other internal error
 *
 * Callers (eval_alg.c) map the result to findings:
 *   FAIL        → TL-V006 TOKEN_SIG_INVALID
 *   UNSUPPORTED → TL-V002 TOKEN_ALG_UNRECOGNIZED
 *   ERROR       → TL_ERR_INTERNAL propagated
 *
 * The function is pure from the caller's perspective — no global state.
 * Ed448 returns TL_VERIFY_UNSUPPORTED (mbedTLS 2.x does not support it).
 *
 * TL_NONNULL(1,3,5,7): arena, key, signing_input, sig must not be NULL.
 */
TL_NODISCARD TL_NONNULL(1, 3, 4, 6)
tl_verify_result_t tl_verify_signature(
    arena_t            *arena,
    alg_id_t            alg,
    const jwks_key_t   *key,
    const uint8_t      *signing_input,
    size_t              signing_input_len,
    const uint8_t      *sig,
    size_t              sig_len
);


/* =========================================================================
 * tl_base64url_decode — decode a base64url string into the arena
 *
 * input/input_len: base64url-encoded data (no padding required)
 * out/out_len:     receives pointer and length of decoded bytes
 *
 * Returns TL_OK on success; TL_ERR_INTERNAL on decode failure or OOM.
 * *out and *out_len are set only on success.
 *
 * TL_NONNULL(1, 2, 4, 5): all non-size parameters must not be NULL.
 */
TL_NODISCARD TL_NONNULL(1, 2, 4, 5)
tl_error_t tl_base64url_decode(
    arena_t        *arena,
    const char     *input,
    size_t          input_len,
    uint8_t       **out,
    size_t         *out_len
);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKENLINT_CRYPTO_BACKEND_H */
