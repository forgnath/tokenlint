/*
 * include/report.h
 *
 * Report generation API for tokenlint v1.
 *
 * Two formats: JSON (default) and text (--format text).
 *
 * tl_report_ctx_t bundles everything needed to produce the output envelope.
 * Both report_json() and report_text() accept it; main() fills it in.
 *
 * Dependencies:
 *   tokenlint.h  — str_t, tl_error_t
 *   findings.h   — finding_set_t
 *   policy.h     — policy_t
 *   token.h      — token_t
 *   jwks.h       — jwks_key_t (key_used)
 *   time_util.h  — tl_reference_time_t
 *   eval_ctx.h   — reftime_source_t
 *
 * Include order:
 *   tokenlint.h → alg.h → findings.h → policy.h → token.h → jwks.h
 *   → time_util.h → report.h
 *
 * No vendor headers. Safe to include from anywhere.
 * C11 required.
 */

#ifndef TOKENLINT_REPORT_H
#define TOKENLINT_REPORT_H

#include "tokenlint.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"
#include "token.h"
#include "jwks.h"
#include "time_util.h"

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * tl_mode_t — evaluation mode for output envelope
 * ========================================================================= */

typedef enum {
    TL_MODE_AUDIT    = 0,
    TL_MODE_VALIDATE = 1,
    TL_MODE_INSPECT  = 2
} tl_mode_t;


/* =========================================================================
 * tl_verdict_t — overall run verdict
 * ========================================================================= */

typedef enum {
    TL_VERDICT_PASS  = 0,
    TL_VERDICT_WARN  = 1,
    TL_VERDICT_FAIL  = 2,
    TL_VERDICT_ERROR = 3
} tl_verdict_t;


/* =========================================================================
 * tl_report_ctx_t — everything needed to emit a report
 *
 * Fields:
 *   mode            — audit | validate | inspect
 *   verdict         — computed from findings + error state
 *   exit_code       — 0/1/2/3/4 per output-contract.md
 *   reference_time  — fixed reference time for this run
 *   findings        — all findings collected during the run
 *   policy          — parsed policy (NULL if parse failed before completion)
 *   token           — parsed token (NULL in audit mode or parse failure)
 *   key_used        — key that verified the signature (NULL if not reached)
 *   error           — halt condition (TL_OK if no halt)
 *
 *   inputs:
 *     policy_path   — path of policy file, or STR_NULL
 *     jwks_path     — path of JWKS file, or STR_NULL
 *     token_path    — file path or STR_LIT("stdin"), or STR_NULL (audit)
 *     at_flag       — --at value as originally provided, or STR_NULL
 *
 *   color           — 1 if --color was passed; 0 (default) otherwise
 *   policy_audit_executed — 1 if policy audit ran before validate
 *   skip_policy_audit     — 1 if --skip-policy-audit was passed
 * ========================================================================= */

typedef struct {
    tl_mode_t              mode;
    tl_verdict_t           verdict;
    int                    exit_code;
    tl_reference_time_t    reference_time;

    const finding_set_t   *findings;
    const policy_t        *policy;
    const token_t         *token;
    const jwks_key_t      *key_used;    /* NULL if sig verification not reached */
    tl_error_t             error;

    /* inputs block */
    str_t  policy_path;
    str_t  jwks_path;
    str_t  token_path;
    str_t  at_flag;

    /* flags */
    int  color;
    int  policy_audit_executed;
    int  skip_policy_audit;
} tl_report_ctx_t;


/* =========================================================================
 * tl_compute_verdict — compute verdict and exit_code from findings + error.
 *
 * Sets ctx->verdict and ctx->exit_code based on:
 *   - error.kind != TL_ERR_NONE  → error verdict, exit 3
 *   - any active critical/fail   → fail verdict, exit 1
 *   - any active warn            → warn verdict, exit 2
 *   - otherwise                  → pass verdict, exit 0
 * ========================================================================= */

void tl_compute_verdict(tl_report_ctx_t *ctx);


/* =========================================================================
 * report_json — emit the full JSON envelope to fp.
 *
 * fp must be open for writing (typically stdout).
 * All findings, policy detail, and token detail are included.
 * ========================================================================= */

void report_json(const tl_report_ctx_t *ctx, FILE *fp);


/* =========================================================================
 * report_text — emit the human-readable text report to fp.
 *
 * fp must be open for writing (typically stdout).
 * Color codes are emitted only when ctx->color == 1.
 * ========================================================================= */

void report_text(const tl_report_ctx_t *ctx, FILE *fp);


/* =========================================================================
 * Helper: alg_id_t → string (e.g. ALG_RS256 → "RS256")
 *
 * Returns a string literal. Returns "unknown" for unrecognized values.
 * Defined in report_json.c, shared with report_text.c.
 * ========================================================================= */

const char *tl_alg_name(alg_id_t alg);


/* =========================================================================
 * Helper: environment_t → string
 * ========================================================================= */

const char *tl_env_name(environment_t env);



/* Shared string helpers (implemented in report_json.c) */
const char *mode_name(tl_mode_t m);
const char *verdict_name(tl_verdict_t v);
const char *err_kind_name(tl_err_kind_t k);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKENLINT_REPORT_H */
