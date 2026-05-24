/*
 * src/eval/eval_audit.c
 *
 * Audit mode evaluation for tokenlint v1.
 *
 * Implements eval_audit(ctx) — runs TL-A findings against policy_t alone.
 * No token, no JWKS required.  Called by eval_validate() before token checks,
 * and directly for `tokenlint audit` mode.
 *
 * Findings emitted:
 *   TL-A002  ISSUER_HTTP_PROD           http:// issuer in prod
 *   TL-A003  ISSUER_LOCALHOST_PROD      localhost/127.0.0.1/::1 issuer in prod
 *   TL-A004  AUDIENCE_WILDCARD          * or empty string in audience values
 *   TL-A005  POLICY_ALG_SYMMETRIC_PROD  HS* in prod policy
 *   TL-A007  TTL_UNBOUNDED              max_ttl_seconds absent
 *   TL-A014  REQUIRED_CLAIM_MISSING     exp/iss/aud absent from requires.claims
 *
 * No vendor headers. No raw string comparisons beyond str_has_prefix/str_eq.
 */

#include "tokenlint.h"
#include "str.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"
#include "eval_ctx.h"

#include <string.h>   /* memset */
#include <stddef.h>


/* =========================================================================
 * Internal helpers
 * ========================================================================= */

static void emit(eval_ctx_t *ctx,
                 const char *id, const char *title,
                 severity_t sev, const char *detail)
{
    finding_t f;
    memset(&f, 0, sizeof(f));
    f.id       = str_from_cstr(id);
    f.title    = str_from_cstr(title);
    f.detail   = str_from_cstr(detail);
    f.severity = sev;
    f.status   = FINDING_ACTIVE;

    int _r = findings_add(ctx->findings, &f, ctx->arena,
                          ctx->policy->suppressions,
                          ctx->policy->suppression_count);
    TL_UNUSED(_r);
}

/* prod_or_unknown — returns 1 for environments treated as prod */
static int prod_or_unknown(environment_t env)
{
    return env == ENV_PROD || env == ENV_UNKNOWN;
}


/* =========================================================================
 * TL-A002: ISSUER_HTTP_PROD
 * TL-A003: ISSUER_LOCALHOST_PROD
 *
 * Iterate over accepted issuer values.  In prod, http:// scheme is FAIL
 * and localhost/127.0.0.1/::1 as host is FAIL.
 * ========================================================================= */

static void check_issuers(eval_ctx_t *ctx)
{
    if (!prod_or_unknown(ctx->policy->environment)) return;

    const issuer_matcher_t *m = &ctx->policy->issuers;
    str_t http_prefix  = STR_LIT("http://");
    str_t localhost    = STR_LIT("localhost");
    str_t loopback4    = STR_LIT("127.0.0.1");
    str_t loopback6    = STR_LIT("::1");

    for (size_t i = 0; i < m->count; i++) {
        str_t v = m->values[i];

        /* TL-A002: http:// scheme */
        if (str_has_prefix(v, http_prefix)) {
            emit(ctx, "TL-A002", "ISSUER_HTTP_PROD",
                 SEV_CRITICAL,
                 "http:// scheme issuer declared in prod policy — non-TLS issuer cannot be trusted");
            /* don't double-emit A003 for same entry if also localhost */
            continue;
        }

        /* TL-A003: localhost / loopback host
         * Issuer is a URI; host appears after scheme (https://).
         * We check if the issuer contains a localhost hostname. */
        if (str_contains(v, '/')) {
            /* look for "://host" pattern by checking remainder after scheme */
            str_t head, tail;
            if (str_split_first(v, '/', &head, &tail)) {
                /* tail now starts after first '/'; skip the second '/' */
                if (tail.len > 0 && tail.data[0] == '/') {
                    str_t after_slashes = str_slice(tail, 1, tail.len - 1);
                    /* extract host (up to next '/' or ':') */
                    str_t host, rest;
                    if (!str_split_first(after_slashes, '/', &host, &rest)) {
                        host = after_slashes;
                    }
                    /* strip port */
                    str_t host_no_port, port;
                    if (!str_split_first(host, ':', &host_no_port, &port)) {
                        host_no_port = host;
                    }
                    if (str_eq(host_no_port, localhost) ||
                        str_eq(host_no_port, loopback4) ||
                        str_eq(host_no_port, loopback6)) {
                        emit(ctx, "TL-A003", "ISSUER_LOCALHOST_PROD",
                             SEV_CRITICAL,
                             "localhost or loopback issuer declared in prod policy");
                    }
                }
            }
        } else {
            /* plain string (no slashes) — check directly */
            if (str_eq(v, localhost) ||
                str_eq(v, loopback4) ||
                str_eq(v, loopback6)) {
                emit(ctx, "TL-A003", "ISSUER_LOCALHOST_PROD",
                     SEV_CRITICAL,
                     "localhost or loopback issuer declared in prod policy");
            }
        }
    }
}


/* =========================================================================
 * TL-A004: AUDIENCE_WILDCARD
 * "*" or empty string in accepts.audiences.values — any environment
 * ========================================================================= */

static void check_audiences(eval_ctx_t *ctx)
{
    const audience_matcher_t *m = &ctx->policy->audiences;
    str_t wildcard = STR_LIT("*");

    for (size_t i = 0; i < m->count; i++) {
        str_t v = m->values[i];
        if (str_eq(v, wildcard) || v.len == 0) {
            emit(ctx, "TL-A004", "AUDIENCE_WILDCARD",
                 SEV_CRITICAL,
                 "Wildcard or empty string in accepted audiences — any audience accepted");
        }
    }
}


/* =========================================================================
 * TL-A005: POLICY_ALG_SYMMETRIC_PROD
 * HS256/HS384/HS512 in accepts.algorithms in prod → critical
 * ========================================================================= */

static void check_algorithms(eval_ctx_t *ctx)
{
    if (!prod_or_unknown(ctx->policy->environment)) return;

    alg_allowset_t set = ctx->policy->algorithms;
    if (ALLOWSET_CONTAINS(set, ALG_HS256) ||
        ALLOWSET_CONTAINS(set, ALG_HS384) ||
        ALLOWSET_CONTAINS(set, ALG_HS512)) {
        emit(ctx, "TL-A005", "POLICY_ALG_SYMMETRIC_PROD",
             SEV_CRITICAL,
             "Symmetric algorithm (HS256/HS384/HS512) in accepts.algorithms for prod environment");
    }
}


/* =========================================================================
 * TL-A007: TTL_UNBOUNDED
 * max_ttl_seconds absent (== 0) → fail
 * ========================================================================= */

static void check_ttl_bounded(eval_ctx_t *ctx)
{
    if (ctx->policy->time_limits.max_ttl_seconds == 0) {
        emit(ctx, "TL-A007", "TTL_UNBOUNDED",
             SEV_FAIL,
             "limits.max_ttl_seconds absent — token lifetime is unconstrained");
    }
}


/* =========================================================================
 * TL-A014: REQUIRED_CLAIM_MISSING
 * exp, iss, or aud absent from requires.claims → fail
 * ========================================================================= */

static void check_required_claims(eval_ctx_t *ctx)
{
    uint32_t req = ctx->policy->required_registered_claims;

    if (!(req & CLAIM_EXP)) {
        emit(ctx, "TL-A014", "REQUIRED_CLAIM_MISSING",
             SEV_FAIL,
             "'exp' absent from requires.claims — expiration not enforced");
    }
    if (!(req & CLAIM_ISS)) {
        emit(ctx, "TL-A014", "REQUIRED_CLAIM_MISSING",
             SEV_FAIL,
             "'iss' absent from requires.claims — issuer not enforced");
    }
    if (!(req & CLAIM_AUD)) {
        emit(ctx, "TL-A014", "REQUIRED_CLAIM_MISSING",
             SEV_FAIL,
             "'aud' absent from requires.claims — audience not enforced");
    }
}


/* =========================================================================
 * eval_audit — entry point (declared in eval_ctx.h)
 * ========================================================================= */

void eval_audit(eval_ctx_t *ctx)
{
    check_issuers(ctx);
    check_audiences(ctx);
    check_algorithms(ctx);
    check_ttl_bounded(ctx);
    check_required_claims(ctx);
}
