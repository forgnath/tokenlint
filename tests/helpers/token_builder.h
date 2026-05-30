/*
 * tests/helpers/token_builder.h
 *
 * Construct token_t directly in tests without going through token_parse().
 * Arena-allocated; safe to use in any unit or integration test.
 *
 * Usage:
 *
 *   arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
 *   token_builder_t b = token_builder_new(arena);
 *   token_builder_alg(&b, ALG_RS256);
 *   token_builder_kid(&b, "key-2026-01");
 *   token_builder_iss(&b, "https://auth.example.com");
 *   token_builder_aud_single(&b, "payments-api");
 *   token_builder_exp(&b, reference_time + 3600);
 *   token_builder_iat(&b, reference_time);
 *   token_t *t = token_builder_build(&b);
 *
 * All char* arguments are intern'd into the arena via arena_strdup().
 * The built token_t is also arena-allocated.
 * Never used in production code — test helpers only.
 */

#ifndef TOKEN_BUILDER_H
#define TOKEN_BUILDER_H

#include "../../include/tokenlint.h"
#include "../../include/alg.h"
#include "../../include/findings.h"
#include "../../include/policy.h"
#include "../../include/token.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * token_builder_t — mutable builder that accumulates token fields
 * ========================================================================= */

typedef struct {
    arena_t  *arena;
    token_t   tok;          /* the token being built; returned by reference */
} token_builder_t;


/* =========================================================================
 * token_builder_new — initialise a builder with a zeroed token_t
 * ========================================================================= */

static inline token_builder_t token_builder_new(arena_t *arena)
{
    token_builder_t b;
    b.arena = arena;
    memset(&b.tok, 0, sizeof(b.tok));
    /* Sensible defaults */
    b.tok.alg = ALG_NONE_ALG;
    b.tok.kid = STR_NULL;
    b.tok.iss = STR_NULL;
    b.tok.sub = STR_NULL;
    b.tok.jti = STR_NULL;
    b.tok.aud = NULL;
    b.tok.aud_count = 0;
    b.tok.present_claims = 0;
    b.tok.sig = NULL;
    b.tok.sig_len = 0;
    b.tok.signing_input = NULL;
    b.tok.signing_input_len = 0;
    return b;
}


/* =========================================================================
 * Setter helpers
 * ========================================================================= */

static inline void token_builder_alg(token_builder_t *b, alg_id_t alg)
{
    b->tok.alg = alg;
}

static inline void token_builder_kid(token_builder_t *b, const char *kid_cstr)
{
    b->tok.kid = arena_strdup(b->arena, str_from_cstr(kid_cstr));
}

static inline void token_builder_iss(token_builder_t *b, const char *iss_cstr)
{
    b->tok.iss = arena_strdup(b->arena, str_from_cstr(iss_cstr));
    b->tok.present_claims |= CLAIM_ISS;
}

static inline void token_builder_sub(token_builder_t *b, const char *sub_cstr)
{
    b->tok.sub = arena_strdup(b->arena, str_from_cstr(sub_cstr));
    b->tok.present_claims |= CLAIM_SUB;
}

static inline void token_builder_jti(token_builder_t *b, const char *jti_cstr)
{
    b->tok.jti = arena_strdup(b->arena, str_from_cstr(jti_cstr));
    b->tok.present_claims |= CLAIM_JTI;
}

/* Single audience value */
static inline void token_builder_aud_single(token_builder_t *b,
                                             const char      *aud_cstr)
{
    str_t *arr = (str_t *)arena_alloc(b->arena, sizeof(str_t),
                                       _Alignof(str_t));
    if (!arr) return;  /* arena exhausted; test will fail elsewhere */
    arr[0] = arena_strdup(b->arena, str_from_cstr(aud_cstr));
    b->tok.aud       = arr;
    b->tok.aud_count = 1;
    b->tok.present_claims |= CLAIM_AUD;
}

/* Multiple audience values; n must be >= 1 */
static inline void token_builder_aud_multi(token_builder_t *b,
                                            const char     **aud_cstrs,
                                            size_t           n)
{
    str_t *arr = (str_t *)arena_alloc(b->arena, sizeof(str_t) * n,
                                       _Alignof(str_t));
    if (!arr) return;
    for (size_t i = 0; i < n; i++) {
        arr[i] = arena_strdup(b->arena, str_from_cstr(aud_cstrs[i]));
    }
    b->tok.aud       = arr;
    b->tok.aud_count = n;
    b->tok.present_claims |= CLAIM_AUD;
}

static inline void token_builder_exp(token_builder_t *b, int64_t exp)
{
    b->tok.exp = exp;
    b->tok.present_claims |= CLAIM_EXP;
}

static inline void token_builder_nbf(token_builder_t *b, int64_t nbf)
{
    b->tok.nbf = nbf;
    b->tok.present_claims |= CLAIM_NBF;
}

static inline void token_builder_iat(token_builder_t *b, int64_t iat)
{
    b->tok.iat = iat;
    b->tok.present_claims |= CLAIM_IAT;
}

/* Set raw signature bytes (for crypto tests; most unit tests leave NULL) */
static inline void token_builder_sig(token_builder_t *b,
                                      const uint8_t   *sig,
                                      size_t           sig_len)
{
    b->tok.sig     = sig;
    b->tok.sig_len = sig_len;
}

/* Set signing input (for crypto tests) */
static inline void token_builder_signing_input(token_builder_t   *b,
                                                const uint8_t     *input,
                                                size_t             input_len)
{
    b->tok.signing_input     = input;
    b->tok.signing_input_len = input_len;
}


/* =========================================================================
 * token_builder_build — copy the accumulated token into the arena and
 * return a pointer to it.
 *
 * Returns NULL on arena exhaustion.
 * ========================================================================= */

static inline token_t *token_builder_build(token_builder_t *b)
{
    token_t *t = (token_t *)arena_alloc(b->arena, sizeof(token_t),
                                         _Alignof(token_t));
    if (!t) return NULL;
    *t = b->tok;
    return t;
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKEN_BUILDER_H */
