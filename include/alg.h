/*
 * include/alg.h
 *
 * Algorithm identity types for tokenlint v1.
 *
 * Defines alg_id_t (the canonical internal representation of a JWT algorithm
 * string) and alg_allowset_t (a bitmask over alg_id_t used in policy_t).
 *
 * Design:
 *   - alg_id_t values are dense integers starting at 0, enabling O(1) bitmask
 *     lookups in the policy allowset.
 *   - ALG_NONE_ALG (0) is the sentinel for "absent / not set". It is distinct
 *     from the forbidden "none" algorithm string — that case is caught at parse
 *     time and never reaches evaluation.  ALG_NONE_ALG is used in jwks_key_t
 *     to signal that the key entry has no explicit alg field.
 *   - ALG_COUNT_ is the count sentinel; it must remain <= 32 so that
 *     alg_allowset_t fits in a uint32_t.  A _Static_assert in
 *     src/crypto/crypto_backend.c enforces this at compile time.
 *
 * Recognized algorithm strings (from algorithm-contract.md):
 *   RS256 RS384 RS512     — RSASSA-PKCS1-v1_5
 *   PS256 PS384 PS512     — RSASSA-PSS
 *   ES256 ES384 ES512     — ECDSA (P-256 / P-384 / P-521)
 *   EdDSA                 — Ed25519 (Ed448 recognized but FAIL TL-V002 in v1)
 *   HS256 HS384 HS512     — HMAC (prod: FAIL TL-A005; non-prod: WARN)
 *
 * The string "none" is never represented as an alg_id_t. Token or policy
 * parsers that encounter it emit TL-S001 / TL-S002 and halt immediately.
 *
 * Dependencies: tokenlint.h (for portability macros, _Static_assert)
 * Include order: #include "tokenlint.h" before this header.
 *
 * No vendor headers included here.  Safe to include from src/eval/.
 *
 * C11 required.
 */

#ifndef TOKENLINT_ALG_H
#define TOKENLINT_ALG_H

#include "tokenlint.h"

#include <stdint.h>   /* uint32_t */

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * alg_id_t — canonical algorithm identifier
 *
 * 0 (ALG_NONE_ALG) means "not set" / absent.  It is the zero value of the
 * type so that zero-initialised structs start in a safe state.
 *
 * Values are used as bit positions in alg_allowset_t.bits, so they must
 * remain contiguous integers starting at 0.  Do not reorder without updating
 * all switch statements in eval_alg.c and crypto_backend.c.
 * ========================================================================= */

typedef enum {
    ALG_NONE_ALG    = 0,   /* sentinel: absent / not set; never a real alg */

    /* RSA PKCS1-v1_5 */
    ALG_RS256       = 1,
    ALG_RS384       = 2,
    ALG_RS512       = 3,

    /* RSA-PSS */
    ALG_PS256       = 4,
    ALG_PS384       = 5,
    ALG_PS512       = 6,

    /* ECDSA */
    ALG_ES256       = 7,
    ALG_ES384       = 8,
    ALG_ES512       = 9,

    /* Edwards-curve (Ed25519 supported; Ed448 recognized but FAIL TL-V002) */
    ALG_ECDSA_EDDSA = 10,

    /* HMAC — symmetric; prod: FAIL TL-A005; non-prod: WARN */
    ALG_HS256       = 11,
    ALG_HS384       = 12,
    ALG_HS512       = 13,

    /* Sentinel — must be last; used for bitmask capacity assertion */
    ALG_COUNT_      = 14
} alg_id_t;

/* Bitmask capacity check — enforced again in src/crypto/crypto_backend.c */
_Static_assert(ALG_COUNT_ <= 32,
    "alg_id_t exceeds bitmask capacity of alg_allowset_t (uint32_t)");


/* =========================================================================
 * alg_allowset_t — policy algorithm allowlist as a bitmask
 *
 * Each bit position corresponds to an alg_id_t value.
 * Bit 0 (ALG_NONE_ALG) must never be set in a valid allowset.
 *
 * Usage:
 *   ALLOWSET_ADD(set, ALG_RS256);             // add RS256
 *   ALLOWSET_CONTAINS(set, ALG_RS256);        // query RS256 → 1 or 0
 *   set.bits == 0                             // empty set test
 * ========================================================================= */

typedef struct {
    uint32_t bits;
} alg_allowset_t;

/*
 * ALLOWSET_CONTAINS — test whether alg is in the allowset.
 * alg must be a valid alg_id_t value (not ALG_NONE_ALG, not ALG_COUNT_).
 */
#define ALLOWSET_CONTAINS(set, alg) \
    (((set).bits & (1u << (unsigned)(alg))) != 0u)

/*
 * ALLOWSET_ADD — add alg to the allowset.
 * Intended for use during policy parsing only.
 */
#define ALLOWSET_ADD(set, alg) \
    ((set).bits |= (1u << (unsigned)(alg)))

/* The empty (zero) allowset */
#define ALLOWSET_EMPTY ((alg_allowset_t){ 0u })


/* =========================================================================
 * Inline predicates
 * ========================================================================= */

/*
 * alg_is_symmetric — returns 1 for HS256/HS384/HS512, 0 for all others.
 * Used by eval_audit to check TL-A005 (symmetric alg in prod policy).
 */
static inline int alg_is_symmetric(alg_id_t alg) {
    return alg == ALG_HS256 || alg == ALG_HS384 || alg == ALG_HS512;
}

/*
 * alg_is_recognized — returns 1 for any valid algorithm (not NONE, not COUNT).
 * ALG_NONE_ALG means "absent" and is not a recognized algorithm string.
 */
static inline int alg_is_recognized(alg_id_t alg) {
    return alg > ALG_NONE_ALG && alg < ALG_COUNT_;
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKENLINT_ALG_H */
