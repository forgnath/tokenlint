/*
 * include/token.h
 *
 * Normalised JWT representation for tokenlint v1.
 *
 * token_t is the output of token_parse() (src/parse/token_parser.c).
 * After parsing, evaluation code works exclusively against token_t —
 * no raw JWT strings, no base64 decoding, no JSON traversal.
 *
 * Design notes:
 *   - alg is always a resolved alg_id_t, never a raw string
 *   - aud is always an array (normalized from string or array in the JWT)
 *   - Time claims (exp, nbf, iat) use int64_t Unix epoch seconds; 0 = absent
 *   - present_claims is a bitmask using CLAIM_* constants from policy.h;
 *     it allows O(1) "is claim X present?" tests in the evaluator
 *   - sig and signing_input point into the arena; they are raw bytes ready
 *     for the crypto backend (no ownership, no copy needed)
 *
 * Claim presence bitmask:
 *   CLAIM_ISS  (1u << 0)
 *   CLAIM_SUB  (1u << 1)
 *   CLAIM_AUD  (1u << 2)
 *   CLAIM_EXP  (1u << 3)
 *   CLAIM_NBF  (1u << 4)
 *   CLAIM_IAT  (1u << 5)
 *   CLAIM_JTI  (1u << 6)
 * These constants are defined in policy.h and shared with the required-claims
 * bitmask in policy_t.  Both use the same bit positions.
 *
 * Dependencies:
 *   tokenlint.h   — str_t, arena_t, tl_error_t, TL_NODISCARD, TL_NONNULL
 *   alg.h         — alg_id_t
 *   findings.h    — finding_set_t (for token_parse signature)
 *
 * Include order: tokenlint.h → alg.h → findings.h → token.h
 *
 * No vendor headers included here.  Safe to include from src/eval/.
 *
 * C11 required.
 */

#ifndef TOKENLINT_TOKEN_H
#define TOKENLINT_TOKEN_H

#include "tokenlint.h"
#include "alg.h"
#include "findings.h"

#include <stdint.h>   /* int64_t, uint8_t, uint32_t */
#include <stddef.h>   /* size_t                      */

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * token_t — normalised JWT
 *
 * Produced by token_parse().  All fields are arena-owned; the token_t
 * pointer itself is also arena-allocated (via ARENA_ALLOC_ONE).
 *
 * Header fields:
 *   alg       — resolved algorithm; ALG_NONE_ALG if absent (TL-V001)
 *   kid       — key ID from header; STR_NULL if absent
 *
 * Registered claims:
 *   iss       — issuer; STR_NULL if absent
 *   sub       — subject; STR_NULL if absent
 *   aud       — audience array; always normalised from string or array form
 *   aud_count — number of aud values (0 if claim absent)
 *   exp       — expiration Unix epoch seconds; 0 if absent
 *   nbf       — not-before Unix epoch seconds; 0 if absent
 *   iat       — issued-at Unix epoch seconds; 0 if absent
 *   jti       — JWT ID; STR_NULL if absent
 *
 * Presence bitmask:
 *   present_claims — OR of CLAIM_* bits for each claim actually present in
 *                    the token.  Use this for O(1) presence tests rather than
 *                    checking str_blank()/zero on individual fields.
 *
 * Signature verification inputs (set by token_parse; used by crypto backend):
 *   sig              — raw decoded signature bytes (arena pointer)
 *   sig_len          — byte length of sig
 *   signing_input    — raw bytes of "header.payload" (ASCII, arena pointer)
 *   signing_input_len — byte length of signing_input
 * ========================================================================= */

typedef struct {
    /* JWT header */
    alg_id_t   alg;
    str_t      kid;

    /* Registered claims */
    str_t      iss;
    str_t      sub;
    str_t     *aud;       /* arena-allocated array of str_t; never NULL when
                             aud_count > 0 */
    size_t     aud_count;
    int64_t    exp;       /* Unix epoch seconds; 0 = absent */
    int64_t    nbf;       /* Unix epoch seconds; 0 = absent */
    int64_t    iat;       /* Unix epoch seconds; 0 = absent */
    str_t      jti;

    /* Claim presence bitmask — CLAIM_* bits from policy.h */
    uint32_t   present_claims;

    /* Raw bytes for signature verification */
    const uint8_t *sig;
    size_t         sig_len;
    const uint8_t *signing_input;    /* points to "header.payload" in arena */
    size_t         signing_input_len;
} token_t;


/* =========================================================================
 * token_parse — parse a raw JWT string into a token_t
 *
 * Declared here; implemented in src/parse/token_parser.c.
 *
 * Parses the three-part base64url-encoded JWT in raw_jwt.  Validates
 * structure and populates *out with a pointer to an arena-allocated token_t.
 *
 * On structural failure (unparseable JWT):
 *   Adds TL-V000 to fs and returns TL_ERR_TOKEN.
 *   *out is not modified.
 *
 * On success:
 *   Returns TL_OK.
 *   *out points to a fully-populated, arena-owned token_t.
 *   Individual missing claims do NOT cause an error here — they produce
 *   findings during evaluation (eval_validate).
 *
 * Parameters:
 *   arena   — run arena; all allocations made here
 *   raw_jwt — the raw JWT string (does not need to be NUL-terminated)
 *   fs      — finding set; TL-V000 added on structural failure
 *   out     — receives pointer to parsed token_t on success
 *
 * TL_NONNULL(1, 3, 4): arena, fs, out must not be NULL.
 * raw_jwt may be STR_NULL (will immediately return TL_ERR_TOKEN).
 */
TL_NODISCARD TL_NONNULL(1, 3, 4)
tl_error_t token_parse(arena_t       *arena,
                        str_t          raw_jwt,
                        finding_set_t *fs,
                        token_t      **out);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKENLINT_TOKEN_H */
