/*
 * src/eval/eval_audience.c
 *
 * Audience claim validation for tokenlint v1.
 *
 * Checks that the token's aud claim matches at least one of the policy's
 * accepted audiences (exact mode in v1).
 *
 * The token parser normalises aud to an array (token_t.aud[]) regardless
 * of whether the JWT had a string or array value.
 *
 * Like eval_issuer.c, this provides a helper used by eval_validate.
 * The v1 finding for audience mismatch is deferred to v2; required-claim
 * absence is handled by the required-claim check in eval_validate.c.
 */

#include "tokenlint.h"
#include "policy.h"
#include "token.h"
#include "eval_ctx.h"

#include <stddef.h>


/*
 * audience_matches — returns 1 if any token aud value matches any policy
 * audience value (exact, case-sensitive).
 *
 * Returns 0 if token has no aud or no intersection found.
 */
int audience_matches(const policy_t *policy, const token_t *tok)
{
    if (tok->aud_count == 0) return 0;

    const audience_matcher_t *m = &policy->audiences;
    for (size_t i = 0; i < tok->aud_count; i++) {
        for (size_t j = 0; j < m->count; j++) {
            if (str_eq(tok->aud[i], m->values[j])) return 1;
        }
    }
    return 0;
}
