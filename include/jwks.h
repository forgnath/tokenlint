/*
 * include/jwks.h
 *
 * JWKS (JSON Web Key Set) types for tokenlint v1.
 *
 * jwks_t is the output of jwks_load() (src/parse/jwks_parser.c).
 * It is a frozen keyset snapshot loaded once at startup and never mutated
 * during a run.  This guarantees reproducibility and forensic integrity.
 *
 * jwks_key_t is the normalised representation of a single JWKS key entry.
 * The crypto backend (src/crypto/crypto_backend.c) receives jwks_key_t
 * pointers directly; it is the only code that interprets key_material.
 *
 * Key type enums (kty_t, crv_t, key_use_t) are defined here and used in
 * eval_alg.c for key-compatibility checks (TL-V004, TL-V005).
 *
 * Design:
 *   - key_material is opaque bytes in the arena; only crypto_backend.c
 *     interprets it.  No mbedTLS types are visible in this header.
 *   - declared_alg is ALG_NONE_ALG when the JWKS key has no "alg" field.
 *     When set, it is a hard constraint: token alg must match exactly.
 *   - kid is STR_NULL when the key entry has no "kid" field.
 *
 * Dependencies:
 *   tokenlint.h   — str_t, arena_t, tl_error_t, TL_NODISCARD, TL_NONNULL
 *   alg.h         — alg_id_t
 *   findings.h    — finding_set_t (for jwks_load signature)
 *
 * Include order: tokenlint.h → alg.h → findings.h → jwks.h
 *
 * No vendor headers included here.  Safe to include from src/eval/.
 *
 * C11 required.
 */

#ifndef TOKENLINT_JWKS_H
#define TOKENLINT_JWKS_H

#include "tokenlint.h"
#include "alg.h"
#include "findings.h"

#include <stddef.h>   /* size_t */

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * kty_t — key type (from "kty" field in JWKS entry)
 *
 * KTY_UNKNOWN is used when the "kty" field is present but not recognised.
 * Such keys are kept in the set (not silently dropped) but will fail
 * TL-V004 (key incompatibility) for any token alg.
 * ========================================================================= */

typedef enum {
    KTY_RSA     = 0,   /* "RSA" — used for RS* and PS* algorithms */
    KTY_EC      = 1,   /* "EC"  — used for ES* algorithms         */
    KTY_OKP     = 2,   /* "OKP" — used for EdDSA                  */
    KTY_OCT     = 3,   /* "oct" — used for HS* algorithms         */
    KTY_UNKNOWN = 4    /* unrecognised kty value                   */
} kty_t;


/* =========================================================================
 * crv_t — elliptic curve (from "crv" field in JWKS entry)
 *
 * CRV_UNSET means the key entry has no "crv" field (valid for RSA/oct keys).
 * Curve mismatch (e.g. ES256 with P-384 key) → FAIL TL-V004.
 * Ed448 is recognised but FAIL TL-V002 in v1 (mbedTLS support limited).
 * ========================================================================= */

typedef enum {
    CRV_UNSET   = 0,   /* no crv field (RSA / oct keys)       */
    CRV_P256    = 1,   /* "P-256" — required for ES256        */
    CRV_P384    = 2,   /* "P-384" — required for ES384        */
    CRV_P521    = 3,   /* "P-521" — required for ES512        */
    CRV_ED25519 = 4,   /* "Ed25519" — supported for EdDSA     */
    CRV_ED448   = 5    /* "Ed448" — recognised; FAIL TL-V002  */
} crv_t;


/* =========================================================================
 * key_use_t — key use (from "use" field in JWKS entry)
 *
 * KEY_USE_UNSET means the "use" field is absent; compatible assumed.
 * KEY_USE_ENC means the key is for encryption only → FAIL TL-V004.
 * ========================================================================= */

typedef enum {
    KEY_USE_UNSET = 0,   /* "use" field absent — compatible assumed */
    KEY_USE_SIG   = 1,   /* "sig" — signature use; compatible       */
    KEY_USE_ENC   = 2    /* "enc" — encryption only → TL-V004       */
} key_use_t;


/* =========================================================================
 * jwks_key_t — normalised representation of one JWKS key entry
 *
 * All str_t fields point into the run arena.
 * key_material points into the arena; interpreted only by crypto_backend.c.
 *
 * Fields:
 *   kid            — key ID; STR_NULL if the entry has no "kid" field
 *   kty            — key type enum
 *   crv            — curve enum; CRV_UNSET for non-EC/OKP keys
 *   use            — key use enum; KEY_USE_UNSET if "use" field absent
 *   key_ops_verify — 1 if "key_ops" contains "verify" or "key_ops" absent;
 *                    0 if "key_ops" is present but does not contain "verify"
 *                    (0 → FAIL TL-V004)
 *   declared_alg   — alg_id_t if the entry has an explicit "alg" field;
 *                    ALG_NONE_ALG if absent (no hard constraint)
 *   key_material   — raw key bytes; opaque to all code outside crypto_backend
 *   key_material_len — byte length of key_material
 * ========================================================================= */

typedef struct {
    str_t      kid;
    kty_t      kty;
    crv_t      crv;
    key_use_t  use;
    int        key_ops_verify;    /* 1 = verify ok; 0 = verify disallowed  */
    alg_id_t   declared_alg;     /* ALG_NONE_ALG if no "alg" in JWKS entry */
    const void *key_material;
    size_t      key_material_len;
} jwks_key_t;


/* =========================================================================
 * jwks_t — frozen keyset
 *
 * Loaded once by jwks_load(); never mutated during a run.
 * keys is an arena-allocated array of jwks_key_t.
 * ========================================================================= */

typedef struct {
    jwks_key_t *keys;
    size_t      count;
} jwks_t;


/* =========================================================================
 * jwks_load — load and validate a JWKS file into a jwks_t
 *
 * Declared here; implemented in src/parse/jwks_parser.c.
 *
 * Reads the JWKS JSON file at path, validates structure, and returns a
 * frozen keyset via *out on success.
 *
 * Structural failures (missing keys array, empty keyset, malformed entries):
 *   Adds the appropriate TL-S finding to fs.
 *   Returns TL_ERR_JWKS.
 *   *out is not modified.
 *
 * File unreadable:
 *   Returns TL_ERR_IO immediately.  No finding added.
 *
 * On success:
 *   Returns TL_OK.
 *   *out points to an arena-allocated, fully-populated jwks_t.
 *
 * Parameters:
 *   arena — run arena; all allocations made here
 *   path  — NUL-terminated path to the JWKS JSON file
 *   fs    — finding set; structural findings added here
 *   out   — receives pointer to loaded jwks_t on success
 *
 * TL_NONNULL(1, 2, 3, 4): all parameters must not be NULL.
 */
TL_NODISCARD TL_NONNULL(1, 2, 3, 4)
tl_error_t jwks_load(arena_t       *arena,
                      const char    *path,
                      finding_set_t *fs,
                      jwks_t       **out);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKENLINT_JWKS_H */
