/*
 * tests/helpers/policy_builder.h
 *
 * Construct policy_t directly in tests without touching the YAML parser.
 * Arena-allocated; safe to use in any unit or integration test.
 *
 * Usage:
 *
 *   arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
 *   policy_builder_t b = policy_builder_new(arena);
 *   policy_builder_environment(&b, ENV_PROD);
 *   policy_builder_issuer_exact(&b, "https://auth.example.com");
 *   policy_builder_audience_exact(&b, "payments-api");
 *   policy_builder_algorithm(&b, ALG_RS256);
 *   policy_builder_require_claims(&b, CLAIM_EXP | CLAIM_ISS | CLAIM_AUD);
 *   policy_builder_max_ttl(&b, 3600);
 *   policy_t *p = policy_builder_build(&b);
 *
 * Never used in production code — test helpers only.
 */

#ifndef POLICY_BUILDER_H
#define POLICY_BUILDER_H

#include "../../include/tokenlint.h"
#include "../../include/alg.h"
#include "../../include/findings.h"
#include "../../include/policy.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * Internal array capacity limits (generous; tests won't exceed these)
 * ========================================================================= */

#define PB_MAX_ISSUERS       8
#define PB_MAX_AUDIENCES     8
#define PB_MAX_SUPPRESSIONS  8


/* =========================================================================
 * policy_builder_t — accumulates policy fields before building
 * ========================================================================= */

typedef struct {
    arena_t  *arena;
    policy_t  pol;

    /* staging arrays (arena-allocated on build) */
    str_t     iss_buf[PB_MAX_ISSUERS];
    size_t    iss_count;

    str_t     aud_buf[PB_MAX_AUDIENCES];
    size_t    aud_count;

    suppression_t supp_buf[PB_MAX_SUPPRESSIONS];
    size_t    supp_count;
} policy_builder_t;


/* =========================================================================
 * policy_builder_new — initialise a builder with a sensible default policy
 *
 * Defaults:
 *   environment   = ENV_PROD
 *   validator_id  = "test-policy"
 *   schema_version = "tokenlint.validator.v1"
 *   max_clock_skew = 60
 *   max_ttl       = 0 (unset — TL-A007 will fire unless overridden)
 *   algorithms    = none (must be added explicitly)
 *   issuers       = none
 *   audiences     = none
 *   require_kid   = 0
 * ========================================================================= */

static inline policy_builder_t policy_builder_new(arena_t *arena)
{
    policy_builder_t b;
    memset(&b, 0, sizeof(b));
    b.arena = arena;

    memset(&b.pol, 0, sizeof(b.pol));
    b.pol.environment      = ENV_PROD;
    b.pol.validator_id     = STR_LIT("test-policy");
    b.pol.schema_version   = STR_LIT("tokenlint.validator.v1");
    b.pol.time_limits.max_clock_skew_seconds = 60;
    b.pol.time_limits.max_ttl_seconds        = 0;
    b.pol.issuers.mode     = ISSUER_MODE_EXACT;
    b.pol.audiences.mode   = AUDIENCE_MODE_EXACT;

    return b;
}


/* =========================================================================
 * Setter helpers
 * ========================================================================= */

static inline void policy_builder_environment(policy_builder_t *b,
                                               environment_t     env)
{
    b->pol.environment = env;
}

static inline void policy_builder_validator_id(policy_builder_t *b,
                                                const char       *id_cstr)
{
    b->pol.validator_id = arena_strdup(b->arena, str_from_cstr(id_cstr));
}

static inline void policy_builder_issuer_exact(policy_builder_t *b,
                                                const char       *iss_cstr)
{
    if (b->iss_count >= PB_MAX_ISSUERS) return;
    b->iss_buf[b->iss_count++] =
        arena_strdup(b->arena, str_from_cstr(iss_cstr));
}

static inline void policy_builder_audience_exact(policy_builder_t *b,
                                                   const char       *aud_cstr)
{
    if (b->aud_count >= PB_MAX_AUDIENCES) return;
    b->aud_buf[b->aud_count++] =
        arena_strdup(b->arena, str_from_cstr(aud_cstr));
}

static inline void policy_builder_algorithm(policy_builder_t *b, alg_id_t alg)
{
    ALLOWSET_ADD(b->pol.algorithms, alg);
}

static inline void policy_builder_require_claims(policy_builder_t *b,
                                                   uint32_t          mask)
{
    b->pol.required_registered_claims |= mask;
}

static inline void policy_builder_max_ttl(policy_builder_t *b, int64_t secs)
{
    b->pol.time_limits.max_ttl_seconds = secs;
}

static inline void policy_builder_max_clock_skew(policy_builder_t *b,
                                                   int64_t           secs)
{
    b->pol.time_limits.max_clock_skew_seconds = secs;
}

static inline void policy_builder_require_kid(policy_builder_t *b, int val)
{
    b->pol.jwks_policy.require_kid = val;
}

static inline void policy_builder_jwks_source(policy_builder_t *b,
                                               const char       *path_cstr)
{
    b->pol.jwks_policy.source =
        arena_strdup(b->arena, str_from_cstr(path_cstr));
}

/* Add a suppression entry (policy-level) */
static inline void policy_builder_add_suppression(policy_builder_t *b,
                                                   const char       *finding_id,
                                                   const char       *reason,
                                                   const char       *owner)
{
    if (b->supp_count >= PB_MAX_SUPPRESSIONS) return;
    suppression_t *s = &b->supp_buf[b->supp_count++];
    memset(s, 0, sizeof(*s));
    s->finding_id = arena_strdup(b->arena, str_from_cstr(finding_id));
    s->reason     = arena_strdup(b->arena, str_from_cstr(reason));
    s->owner      = arena_strdup(b->arena, str_from_cstr(owner));
    s->ticket     = STR_NULL;
    s->expires    = STR_NULL;
}

/* Add a suppression with an expiry (ISO 8601 date string and epoch) */
static inline void policy_builder_add_suppression_expires(
    policy_builder_t *b,
    const char       *finding_id,
    const char       *reason,
    const char       *owner,
    const char       *expires_iso,
    int64_t           expires_epoch)
{
    if (b->supp_count >= PB_MAX_SUPPRESSIONS) return;
    suppression_t *s = &b->supp_buf[b->supp_count++];
    memset(s, 0, sizeof(*s));
    s->finding_id    = arena_strdup(b->arena, str_from_cstr(finding_id));
    s->reason        = arena_strdup(b->arena, str_from_cstr(reason));
    s->owner         = arena_strdup(b->arena, str_from_cstr(owner));
    s->ticket        = STR_NULL;
    s->expires       = arena_strdup(b->arena, str_from_cstr(expires_iso));
    s->expires_epoch = expires_epoch;
}


/* =========================================================================
 * policy_builder_build — copy accumulated data into arena-allocated arrays
 * and return a pointer to the built policy_t.
 *
 * Returns NULL on arena exhaustion.
 * ========================================================================= */

static inline policy_t *policy_builder_build(policy_builder_t *b)
{
    /* Copy issuer array into arena */
    if (b->iss_count > 0) {
        str_t *iss_arr = (str_t *)arena_alloc(
            b->arena, sizeof(str_t) * b->iss_count, _Alignof(str_t));
        if (!iss_arr) return NULL;
        memcpy(iss_arr, b->iss_buf, sizeof(str_t) * b->iss_count);
        b->pol.issuers.values = iss_arr;
        b->pol.issuers.count  = b->iss_count;
    }

    /* Copy audience array into arena */
    if (b->aud_count > 0) {
        str_t *aud_arr = (str_t *)arena_alloc(
            b->arena, sizeof(str_t) * b->aud_count, _Alignof(str_t));
        if (!aud_arr) return NULL;
        memcpy(aud_arr, b->aud_buf, sizeof(str_t) * b->aud_count);
        b->pol.audiences.values = aud_arr;
        b->pol.audiences.count  = b->aud_count;
    }

    /* Copy suppression array into arena */
    if (b->supp_count > 0) {
        suppression_t *supp_arr = (suppression_t *)arena_alloc(
            b->arena, sizeof(suppression_t) * b->supp_count,
            _Alignof(suppression_t));
        if (!supp_arr) return NULL;
        memcpy(supp_arr, b->supp_buf,
               sizeof(suppression_t) * b->supp_count);
        b->pol.suppressions       = supp_arr;
        b->pol.suppression_count  = b->supp_count;
    }

    /* Allocate the policy_t in the arena */
    policy_t *p = (policy_t *)arena_alloc(b->arena, sizeof(policy_t),
                                            _Alignof(policy_t));
    if (!p) return NULL;
    *p = b->pol;
    return p;
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* POLICY_BUILDER_H */
