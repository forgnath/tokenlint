/*
 * include/eval_ctx.h
 *
 * Evaluation context for tokenlint v1.
 *
 * eval_ctx_t is the complete universe of a single evaluation.  All eval_*
 * functions receive a pointer to eval_ctx_t and nothing else.  There is no
 * global state; the same evaluation code can be called multiple times with
 * different contexts (multi-token batch mode in v2) without interference.
 *
 * reftime_source_t records how reference_time was determined, for output in
 * the JSON envelope (time-contract.md §Output block):
 *
 *   system_clock   — --at absent; system clock used at invocation
 *   cli_at_now     — --at now; system clock used, source annotated
 *   cli_at         — --at <unix> or --at <ISO8601Z>
 *
 * Modes:
 *   audit    — token is NULL; eval_audit() runs against policy only
 *   validate — token is non-NULL; eval_validate() runs both policy and token
 *
 * Dependencies:
 *   tokenlint.h  — str_t, arena_t, TL_NONNULL
 *   alg.h        — alg_id_t (transitively via token.h / jwks.h)
 *   findings.h   — finding_set_t, suppression_t
 *   policy.h     — policy_t
 *   token.h      — token_t
 *   jwks.h       — jwks_t
 *
 * Include order:
 *   tokenlint.h → alg.h → findings.h → policy.h → token.h → jwks.h → eval_ctx.h
 *
 * No vendor headers included here.  Safe to include from src/eval/.
 *
 * C11 required.
 */

#ifndef TOKENLINT_EVAL_CTX_H
#define TOKENLINT_EVAL_CTX_H

#include "tokenlint.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"
#include "token.h"
#include "jwks.h"

#include <stdint.h>   /* int64_t */

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * reftime_source_t — how reference_time was determined
 *
 * Written to the JSON output envelope:
 *   REFTIME_SYSTEM_CLOCK → "system_clock"
 *   REFTIME_CLI_AT_NOW   → "cli_at_now"
 *   REFTIME_CLI_AT       → "cli_at"
 * ========================================================================= */

typedef enum {
    REFTIME_SYSTEM_CLOCK = 0,  /* --at absent; system clock at invocation   */
    REFTIME_CLI_AT_NOW   = 1,  /* --at now; system clock, annotated source  */
    REFTIME_CLI_AT       = 2   /* --at <unix> or --at <ISO8601Z>            */
} reftime_source_t;


/* =========================================================================
 * eval_ctx_t — evaluation context
 *
 * The complete, immutable (from evaluators' perspective) context for one
 * evaluation.  All eval_* functions take a pointer to this struct.
 *
 * Fields:
 *   policy          — normalised trust model; never NULL
 *   jwks            — frozen keyset; NULL during audit-only mode
 *   token           — normalised JWT; NULL during audit mode
 *   reference_time  — fixed Unix epoch seconds for all time checks;
 *                     set once before any evaluation, never changes
 *   reference_time_source — how reference_time was determined (for output)
 *   findings        — mutable; all eval_* functions append findings here
 *   arena           — run arena; eval_* may allocate detail strings here
 *
 * Invariants:
 *   - policy is always non-NULL
 *   - token is NULL iff mode is audit
 *   - jwks is NULL iff mode is audit (validate always has a jwks)
 *   - reference_time > 0 (enforced by CLI parsing via TL-I001)
 *   - findings is non-NULL
 *   - arena is non-NULL
 * ========================================================================= */

typedef struct {
    const policy_t    *policy;
    const jwks_t      *jwks;            /* NULL in audit mode               */
    const token_t     *token;           /* NULL in audit mode               */
    int64_t            reference_time;  /* fixed Unix epoch seconds         */
    reftime_source_t   reference_time_source;
    finding_set_t     *findings;
    arena_t           *arena;
} eval_ctx_t;


/* =========================================================================
 * Evaluator entry points
 *
 * Declared here; implemented in src/eval/eval_audit.c and
 * src/eval/eval_validate.c respectively.
 *
 * Both functions take only eval_ctx_t *ctx.  All inputs and outputs flow
 * through ctx.  Return type is void — findings are the output channel;
 * a tl_error_t is only returned by parse-layer functions.
 *
 * eval_audit:
 *   Evaluates policy alone.  Emits TL-A findings.
 *   ctx->token and ctx->jwks may be NULL.
 *   Safe to call with a NULL token/jwks.
 *
 * eval_validate:
 *   Evaluates a token against the policy and JWKS.
 *   Calls eval_audit internally (validate always includes an audit pass).
 *   ctx->token and ctx->jwks must be non-NULL.
 *   Emits TL-A, TL-V, TL-C findings as appropriate.
 *
 * TL_NONNULL(1): ctx must not be NULL.
 * ========================================================================= */

TL_NONNULL(1)
void eval_audit(eval_ctx_t *ctx);

TL_NONNULL(1)
void eval_validate(eval_ctx_t *ctx);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKENLINT_EVAL_CTX_H */
