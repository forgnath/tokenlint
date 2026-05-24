/*
 * src/eval/eval_validate.c
 *
 * Validate mode evaluation for tokenlint v1.
 *
 * eval_validate(ctx) runs:
 *   1. eval_audit(ctx)        — policy-level findings (TL-A)
 *   2. Required claim checks  — from requires.claims bitmask
 *   3. eval_alg(ctx)          — algorithm + key checks (TL-V001..TL-V012)
 *   4. eval_time(ctx)         — time claim checks (TL-V020..TL-V025)
 *   5. Claim rule presence    — TL-C001 for required:true rules
 *
 * Signature verification (TL-V006) is invoked via the crypto backend
 * (Layer 7); that call is stubbed here until Layer 7 is wired.
 *
 * No vendor headers. No raw string parsing. Pure logic against compiled model.
 */

#include "tokenlint.h"
#include "findings.h"
#include "policy.h"
#include "token.h"
#include "jwks.h"
#include "eval_ctx.h"

#include <string.h>   /* memset */
#include <stddef.h>


/* Forward declarations for helpers in other eval files */
void eval_audit(eval_ctx_t *ctx);
void eval_alg(eval_ctx_t *ctx);
void eval_time(eval_ctx_t *ctx);


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
 * Required claim checks
 *
 * Cross-checks policy_t.required_registered_claims against
 * token_t.present_claims using the shared CLAIM_* bitmask.
 *
 * Any required claim that is absent → TL-V022 is NOT the right code.
 * The spec does not define a separate finding for "required claim absent"
 * in the validate path (that's TL-A014 at audit time for iss/exp/aud).
 * For required-claim absence detected at token eval time, we emit detail
 * via TL-C001 (claim absent, required:true) for custom claim rules, but
 * the registered-claim mandatory presence is enforced by the required_registered_claims
 * bitmask producing no explicit per-token finding in v1 beyond TL-A014.
 *
 * However, the spec does say that if iss/aud/exp are in requires.claims and
 * absent from the token, that's a validation failure.  We surface this as
 * a TL-V000-adjacent halt only for structural absence.  For value-level
 * checking (iss mismatch, aud mismatch), that's v2.
 *
 * In v1: emit a synthetic detail finding for each missing required claim.
 * We reuse TL-C001 with appropriate detail for missing registered claims.
 * ========================================================================= */

static void check_required_claims(eval_ctx_t *ctx)
{
    uint32_t required = ctx->policy->required_registered_claims;
    uint32_t present  = ctx->token->present_claims;
    uint32_t missing  = required & ~present;

    if (!missing) return;

    /* Emit one finding per missing required claim */
    static const struct {
        uint32_t    bit;
        const char *name;
    } claim_map[] = {
        { CLAIM_ISS, "iss" },
        { CLAIM_SUB, "sub" },
        { CLAIM_AUD, "aud" },
        { CLAIM_EXP, "exp" },
        { CLAIM_NBF, "nbf" },
        { CLAIM_IAT, "iat" },
        { CLAIM_JTI, "jti" },
    };

    for (size_t i = 0; i < sizeof(claim_map)/sizeof(claim_map[0]); i++) {
        if (missing & claim_map[i].bit) {
            emit(ctx, "TL-C001", "CLAIM_ABSENT_REQUIRED",
                 SEV_FAIL,
                 claim_map[i].name);
        }
    }
}


/* =========================================================================
 * Claim rule presence checks (v1: required:true only)
 *
 * For each claim_rule with required:true, check that the claim is present
 * in the token's payload.  In v1, only registered claims are in present_claims;
 * custom claims are not tracked.  The parser puts custom required claims in
 * policy_t.required_custom_claims.
 *
 * For v1 custom required claims: we cannot check token payload without a
 * JSON parser; this is deferred to v2.  Only registered required claims are
 * checked here.
 * ========================================================================= */

static void check_claim_rules(eval_ctx_t *ctx)
{
    /* Registered claims: already handled by check_required_claims() */
    /* Custom required claims: deferred to v2 */
    TL_UNUSED(ctx);
}


/* =========================================================================
 * eval_validate — entry point (declared in eval_ctx.h)
 * ========================================================================= */

void eval_validate(eval_ctx_t *ctx)
{
    /* 1. Audit pass (policy-level findings) */
    eval_audit(ctx);

    /* 2. Required claim checks */
    check_required_claims(ctx);

    /* 3. Algorithm + key checks */
    eval_alg(ctx);

    /* 4. Time claim checks */
    eval_time(ctx);

    /* 5. Claim rule presence checks (v1: registered claims only) */
    check_claim_rules(ctx);

    /* Signature verification (TL-V006) is performed by crypto_backend
     * (Layer 7).  When Layer 7 is wired, eval_validate will call
     * tl_verify_signature() after eval_alg() and emit TL-V006 on failure.
     * For now, the stub does nothing further. */
}
