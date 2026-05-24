/*
 * src/eval/eval_time.c
 *
 * Time-sensitive claim evaluation for tokenlint v1.
 *
 * Implements time-contract.md evaluation order steps 2–8:
 *   TL-V020  IAT_ABSENT_TTL_UNVERIFIABLE  (suppressible)
 *   TL-V021  EXP_ABSENT_TTL_UNVERIFIABLE  (suppressible)
 *   TL-V022  TOKEN_EXPIRED                (non-suppressible)
 *   TL-V023  TOKEN_NOT_YET_VALID          (suppressible)
 *   TL-V024  TOKEN_TTL_INVALID            (non-suppressible)
 *   TL-V025  TOKEN_TTL_EXCEEDED           (suppressible)
 *
 * Clock skew applies to nbf only, never to exp.
 * Evaluation order: all checks are independent, no short-circuit between them.
 *
 * No vendor headers. No strlen().
 */

#include "tokenlint.h"
#include "findings.h"
#include "policy.h"
#include "token.h"
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


/* =========================================================================
 * eval_time — entry point
 *
 * Evaluates all time-sensitive claims against reference_time.
 * Called from eval_validate() after token and policy are loaded.
 * ========================================================================= */

void eval_time(eval_ctx_t *ctx)
{
    const token_t       *tok   = ctx->token;
    const time_limits_t *lim   = &ctx->policy->time_limits;
    int64_t              now   = ctx->reference_time;
    int64_t              skew  = lim->max_clock_skew_seconds;

    /* Step 2+3: exp check */
    int has_exp = (tok->present_claims & CLAIM_EXP) != 0;
    if (has_exp) {
        /* TL-V022: reference_time >= exp → expired (no skew ever) */
        if (now >= tok->exp) {
            emit(ctx, "TL-V022", "TOKEN_EXPIRED",
                 SEV_FAIL,
                 "Token has expired (reference_time >= exp)");
        }
    }

    /* Step 4+5: nbf check */
    int has_nbf = (tok->present_claims & CLAIM_NBF) != 0;
    if (has_nbf) {
        /* TL-V023: reference_time < nbf - skew */
        if (now < tok->nbf - skew) {
            emit(ctx, "TL-V023", "TOKEN_NOT_YET_VALID",
                 SEV_FAIL,
                 "Token not yet valid (reference_time < nbf - clock_skew)");
        }
    }

    /* Steps 6+7: iat and TTL verification */
    int has_iat = (tok->present_claims & CLAIM_IAT) != 0;
    int has_ttl = lim->max_ttl_seconds > 0;

    if (has_ttl) {
        /* TL-V020: iat absent + max_ttl_seconds set */
        if (!has_iat) {
            emit(ctx, "TL-V020", "IAT_ABSENT_TTL_UNVERIFIABLE",
                 SEV_FAIL,
                 "iat absent; max_ttl_seconds set — token lifetime unverifiable");
        }
        /* TL-V021: exp absent + max_ttl_seconds set */
        if (!has_exp) {
            emit(ctx, "TL-V021", "EXP_ABSENT_TTL_UNVERIFIABLE",
                 SEV_FAIL,
                 "exp absent; max_ttl_seconds set — token lifetime unverifiable");
        }
    }

    /* TTL computation: only when both exp and iat are present */
    if (has_exp && has_iat) {
        int64_t ttl = tok->exp - tok->iat;

        if (ttl <= 0) {
            /* TL-V024: exp - iat <= 0: malformed */
            emit(ctx, "TL-V024", "TOKEN_TTL_INVALID",
                 SEV_FAIL,
                 "Token TTL invalid: exp - iat <= 0 (expired at or before issuance)");
        } else if (has_ttl && ttl > lim->max_ttl_seconds) {
            /* TL-V025: TTL exceeds policy limit */
            emit(ctx, "TL-V025", "TOKEN_TTL_EXCEEDED",
                 SEV_FAIL,
                 "Token TTL exceeds policy max_ttl_seconds");
        }
    }
}
