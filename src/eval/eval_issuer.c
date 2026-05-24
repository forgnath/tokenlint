/*
 * src/eval/eval_issuer.c
 *
 * Issuer claim validation for tokenlint v1.
 *
 * Checks that the token's iss claim is present (if required) and matches
 * one of the policy's accepted issuers (exact mode in v1).
 *
 * Trailing-slash normalisation was done by the parser when building
 * policy_t.issuers.values — the evaluator compares directly.
 *
 * Findings emitted: none directly — issuer mismatch is part of
 * eval_validate's required-claim and value-check logic.  This file
 * handles the exact-match check that fires a finding in the validate path.
 *
 * In v1 there is no separate TL-V finding for issuer mismatch; the SPEC
 * defers that to v2 claim rule evaluation (TL-C002+).  The v1 behavior is:
 *   - If iss is in requires.claims and absent from token → TL-V finding
 *     (handled by required-claim check in eval_validate.c)
 *   - Issuer value checking is not a separate v1 finding code
 *
 * This file provides the issuer_matches() helper used by eval_validate.
 */

#include "tokenlint.h"
#include "policy.h"
#include "token.h"
#include "eval_ctx.h"

#include <stddef.h>


/*
 * issuer_matches — returns 1 if the token iss matches any policy issuer value.
 *
 * v1: exact mode only.  Both sides were trailing-slash normalised at parse time.
 * Returns 0 if token has no iss or no match found.
 */
int issuer_matches(const policy_t *policy, const token_t *tok)
{
    if (STR_IS_NULL(tok->iss) || tok->iss.len == 0) return 0;

    const issuer_matcher_t *m = &policy->issuers;
    for (size_t i = 0; i < m->count; i++) {
        if (str_eq(tok->iss, m->values[i])) return 1;
    }
    return 0;
}
