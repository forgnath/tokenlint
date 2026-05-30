/*
 * src/main.c
 *
 * tokenlint entry point — CLI dispatch only, no business logic.
 *
 * Execution order for each mode:
 *
 *   audit:
 *     1. Parse CLI
 *     2. Resolve reference_time
 *     3. Parse policy (schema validation → TL-S findings)
 *     4. Run eval_audit()
 *     5. Compute verdict
 *     6. Emit report
 *     7. Exit
 *
 *   validate:
 *     1. Parse CLI
 *     2. Resolve reference_time
 *     3. Parse policy (schema validation → TL-S findings)
 *     4. Unless --skip-policy-audit: run eval_audit()
 *     5. Load JWKS
 *     6. Parse token
 *     7. Run eval_validate()
 *     8. Compute verdict
 *     9. Emit report
 *    10. Exit
 *
 *   inspect:
 *     1. Parse CLI
 *     2. Resolve reference_time
 *     3. Parse token
 *     4. Compute verdict (always pass if parsed)
 *     5. Emit report
 *     6. Exit
 *
 * All output goes to stdout.  Errors before the envelope is available go to
 * stderr.  In normal operation stderr is empty.
 *
 * Spec: docs/cli-contract.md, docs/build-contract.md, docs/output-contract.md
 * C11 required.
 */

#define _POSIX_C_SOURCE 200809L

#include "tokenlint.h"
#include "str.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"
#include "token.h"
#include "jwks.h"
#include "time_util.h"
#include "eval_ctx.h"
#include "report.h"
#include "cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── helpers ────────────────────────────────────────────────────────────── */

/*
 * apply_cli_suppressions — mark findings that match --suppress IDs as
 * FINDING_SUPPRESSED_CLI.
 *
 * This is a post-processing pass over the finding_set after all evaluation
 * is complete.  It does not use findings_add() (that's the arena path);
 * it directly mutates status for findings already in the set.
 *
 * Non-suppressible findings are never changed (the eval layer already marks
 * them correctly; we honour that by checking against the non-suppressible
 * list maintained in finding_registry.def).
 *
 * For v1 simplicity: we trust that eval code marks non-suppressible findings
 * with affects_exit=1 and we do not override those here.
 */
static void apply_cli_suppressions(finding_set_t *fs,
                                   const tl_cli_opts_t *opts) {
    if (!opts->suppress_ids || opts->suppress_count == 0) return;

    for (size_t i = 0; i < fs->count; i++) {
        finding_t *f = &fs->findings[i];
        if (f->status != FINDING_ACTIVE) continue;
        /* Non-suppressible: suppression.affects_exit == 1 and status ACTIVE
         * means it cannot be suppressed. We check: if it was already marked
         * with affects_exit=1 by the eval layer for a non-suppressible reason,
         * skip it.  (Non-suppressible findings have affects_exit=1 set by
         * findings.c.) */
        if (f->suppression.affects_exit) continue;

        /* Check if this finding's id matches any CLI suppress entry */
        if (STR_IS_NULL(f->id)) continue;
        char id_buf[32];
        if (f->id.len >= sizeof(id_buf)) continue;
        memcpy(id_buf, f->id.data, f->id.len);
        id_buf[f->id.len] = '\0';

        if (tl_cli_suppress_active(opts, id_buf)) {
            f->status = FINDING_SUPPRESSED_CLI;
            f->suppression.source = STR_LIT("cli");
            if (opts->suppress_affects_exit) {
                f->suppression.affects_exit = 0;
            }
        }
    }
}

/*
 * emit_early_error — emit an error envelope to stdout when we halt before
 * a full report is possible.
 */
static void emit_early_error(const tl_cli_opts_t *opts,
                              const tl_error_t *error,
                              const finding_set_t *fs,
                              const policy_t *policy,
                              tl_mode_t mode,
                              int format_json,
                              int color,
                              const tl_reference_time_t *reftime) {
    tl_report_ctx_t rctx;
    memset(&rctx, 0, sizeof(rctx));

    rctx.mode            = mode;
    rctx.verdict         = TL_VERDICT_ERROR;
    rctx.exit_code       = 3;
    rctx.findings        = fs;
    rctx.policy          = policy;
    rctx.error           = *error;
    rctx.color           = color;
    rctx.policy_audit_executed = 0;
    rctx.skip_policy_audit = opts ? opts->skip_policy_audit : 0;

    if (reftime) {
        rctx.reference_time = *reftime;
    } else {
        /* best-effort: try system clock */
        tl_reference_time_t rt;
        if (!tl_ok(tl_resolve_reference_time(&rt))) {
            rt.value  = 0;
            rt.source = TL_TIME_SRC_SYSTEM_CLOCK;
        }
        rctx.reference_time = rt;
    }

    if (opts) {
        rctx.policy_path  = str_from_cstr(opts->policy_path);
        rctx.jwks_path    = str_from_cstr(opts->jwks_path);
        rctx.token_path   = str_from_cstr(opts->token_path_display);
        rctx.at_flag      = str_from_cstr(opts->at_str);
    }

    if (format_json) {
        report_json(&rctx, stdout);
    } else {
        report_text(&rctx, stdout);
    }
}


/* =========================================================================
 * run_audit — execute the audit subcommand
 * ========================================================================= */

static int run_audit(const tl_cli_opts_t *opts) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    if (!arena) {
        fprintf(stderr, "tokenlint: fatal: arena allocation failed\n");
        return 4;
    }

    finding_set_t fs;
    findings_init(&fs);

    tl_reference_time_t reftime;
    tl_error_t err = tl_cli_resolve_reftime(opts, &reftime);
    if (!tl_ok(err)) {
        /* --at parse error: emit error envelope */
        emit_early_error(opts, &err, &fs, NULL, TL_MODE_AUDIT,
                         opts->format_json, opts->color, NULL);
        arena_free(arena);
        return 3;
    }

    /* Parse policy */
    policy_t *policy = NULL;
    err = policy_parse(arena, opts->policy_path, &fs, &policy);
    if (!tl_ok(err)) {
        emit_early_error(opts, &err, &fs, policy, TL_MODE_AUDIT,
                         opts->format_json, opts->color, &reftime);
        arena_free(arena);
        return 3;
    }

    /* Run audit */
    eval_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.policy               = policy;
    ctx.jwks                 = NULL;
    ctx.token                = NULL;
    ctx.reference_time       = reftime.value;
    ctx.reference_time_source = (reftime_source_t)reftime.source;
    ctx.findings             = &fs;
    ctx.arena                = arena;

    eval_audit(&ctx);

    /* Apply CLI suppressions */
    apply_cli_suppressions(&fs, opts);

    /* Build report context */
    tl_report_ctx_t rctx;
    memset(&rctx, 0, sizeof(rctx));
    rctx.mode                  = TL_MODE_AUDIT;
    rctx.reference_time        = reftime;
    rctx.findings              = &fs;
    rctx.policy                = policy;
    rctx.token                 = NULL;
    rctx.key_used              = NULL;
    rctx.error                 = TL_OK;
    rctx.policy_path           = str_from_cstr(opts->policy_path);
    rctx.jwks_path             = STR_NULL;
    rctx.token_path            = STR_NULL;
    rctx.at_flag               = str_from_cstr(opts->at_str);
    rctx.color                 = opts->color;
    rctx.policy_audit_executed = 1;
    rctx.skip_policy_audit     = 0;

    /* Handle finding overflow */
    if (fs.overflowed) {
        tl_error_t overflow_err = tl_error_internal(
            "Finding capacity exceeded (256). Report may be incomplete.");
        rctx.error = overflow_err;
        tl_compute_verdict(&rctx);
        if (rctx.exit_code < 3) rctx.exit_code = 3;
        rctx.verdict = TL_VERDICT_ERROR;
    } else {
        tl_compute_verdict(&rctx);
    }

    if (opts->format_json) {
        report_json(&rctx, stdout);
    } else {
        report_text(&rctx, stdout);
    }

    int exit_code = rctx.exit_code;
    arena_free(arena);
    return exit_code;
}


/* =========================================================================
 * run_validate — execute the validate subcommand
 * ========================================================================= */

static int run_validate(const tl_cli_opts_t *opts) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    if (!arena) {
        fprintf(stderr, "tokenlint: fatal: arena allocation failed\n");
        return 4;
    }

    finding_set_t fs;
    findings_init(&fs);

    tl_reference_time_t reftime;
    tl_error_t err = tl_cli_resolve_reftime(opts, &reftime);
    if (!tl_ok(err)) {
        emit_early_error(opts, &err, &fs, NULL, TL_MODE_VALIDATE,
                         opts->format_json, opts->color, NULL);
        arena_free(arena);
        return 3;
    }

    /* Parse policy */
    policy_t *policy = NULL;
    err = policy_parse(arena, opts->policy_path, &fs, &policy);
    if (!tl_ok(err)) {
        emit_early_error(opts, &err, &fs, policy, TL_MODE_VALIDATE,
                         opts->format_json, opts->color, &reftime);
        arena_free(arena);
        return 3;
    }

    /* Evaluate context (shared across audit + validate passes) */
    eval_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.policy               = policy;
    ctx.reference_time       = reftime.value;
    ctx.reference_time_source = (reftime_source_t)reftime.source;
    ctx.findings             = &fs;
    ctx.arena                = arena;

    int policy_audit_executed = 0;

    if (!opts->skip_policy_audit) {
        eval_audit(&ctx);
        policy_audit_executed = 1;
    }

    /* Load JWKS */
    jwks_t *jwks = NULL;
    err = jwks_load(arena, opts->jwks_path, &fs, &jwks);
    if (!tl_ok(err)) {
        /* Emit partial report: policy findings included, JWKS failed */
        apply_cli_suppressions(&fs, opts);

        tl_report_ctx_t rctx;
        memset(&rctx, 0, sizeof(rctx));
        rctx.mode                  = TL_MODE_VALIDATE;
        rctx.verdict               = TL_VERDICT_ERROR;
        rctx.exit_code             = 3;
        rctx.reference_time        = reftime;
        rctx.findings              = &fs;
        rctx.policy                = policy;
        rctx.error                 = err;
        rctx.policy_path           = str_from_cstr(opts->policy_path);
        rctx.jwks_path             = str_from_cstr(opts->jwks_path);
        rctx.token_path            = str_from_cstr(opts->token_path_display);
        rctx.at_flag               = str_from_cstr(opts->at_str);
        rctx.color                 = opts->color;
        rctx.policy_audit_executed = policy_audit_executed;
        rctx.skip_policy_audit     = opts->skip_policy_audit;

        if (opts->format_json) report_json(&rctx, stdout);
        else                   report_text(&rctx, stdout);

        arena_free(arena);
        return 3;
    }

    /* Parse token */
    str_t raw_jwt = str_from_cstr(opts->token_raw_heap);
    token_t *token = NULL;
    err = token_parse(arena, raw_jwt, &fs, &token);
    if (!tl_ok(err)) {
        /* Token unparseable: emit partial report */
        apply_cli_suppressions(&fs, opts);

        tl_report_ctx_t rctx;
        memset(&rctx, 0, sizeof(rctx));
        rctx.mode                  = TL_MODE_VALIDATE;
        rctx.reference_time        = reftime;
        rctx.findings              = &fs;
        rctx.policy                = policy;
        rctx.error                 = err;
        rctx.policy_path           = str_from_cstr(opts->policy_path);
        rctx.jwks_path             = str_from_cstr(opts->jwks_path);
        rctx.token_path            = str_from_cstr(opts->token_path_display);
        rctx.at_flag               = str_from_cstr(opts->at_str);
        rctx.color                 = opts->color;
        rctx.policy_audit_executed = policy_audit_executed;
        rctx.skip_policy_audit     = opts->skip_policy_audit;
        /* verdict: if TL-V000 is in findings, exit 1; if err kind == token → exit 1 */
        rctx.exit_code = 1;
        rctx.verdict   = TL_VERDICT_FAIL;

        if (opts->format_json) report_json(&rctx, stdout);
        else                   report_text(&rctx, stdout);

        arena_free(arena);
        return 1;
    }

    /* Full validate */
    ctx.jwks  = jwks;
    ctx.token = token;
    eval_validate(&ctx);

    /* Apply CLI suppressions */
    apply_cli_suppressions(&fs, opts);

    /* Key used: scan ctx for which key verified signature
     * (eval_validate stores this in the jwks_t or we leave NULL for now —
     * the report layer handles NULL gracefully) */
    const jwks_key_t *key_used = NULL;
    /* TODO v2: propagate key_used through eval_ctx_t */

    /* Build report context */
    tl_report_ctx_t rctx;
    memset(&rctx, 0, sizeof(rctx));
    rctx.mode                  = TL_MODE_VALIDATE;
    rctx.reference_time        = reftime;
    rctx.findings              = &fs;
    rctx.policy                = policy;
    rctx.token                 = token;
    rctx.key_used              = key_used;
    rctx.error                 = TL_OK;
    rctx.policy_path           = str_from_cstr(opts->policy_path);
    rctx.jwks_path             = str_from_cstr(opts->jwks_path);
    rctx.token_path            = str_from_cstr(opts->token_path_display);
    rctx.at_flag               = str_from_cstr(opts->at_str);
    rctx.color                 = opts->color;
    rctx.policy_audit_executed = policy_audit_executed;
    rctx.skip_policy_audit     = opts->skip_policy_audit;

    if (fs.overflowed) {
        tl_error_t overflow_err = tl_error_internal(
            "Finding capacity exceeded (256). Report may be incomplete.");
        rctx.error = overflow_err;
        tl_compute_verdict(&rctx);
        if (rctx.exit_code < 3) rctx.exit_code = 3;
        rctx.verdict = TL_VERDICT_ERROR;
    } else {
        tl_compute_verdict(&rctx);
    }

    if (opts->format_json) report_json(&rctx, stdout);
    else                   report_text(&rctx, stdout);

    int exit_code = rctx.exit_code;
    arena_free(arena);
    return exit_code;
}


/* =========================================================================
 * run_inspect — execute the inspect subcommand
 * ========================================================================= */

static int run_inspect(const tl_cli_opts_t *opts) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    if (!arena) {
        fprintf(stderr, "tokenlint: fatal: arena allocation failed\n");
        return 4;
    }

    finding_set_t fs;
    findings_init(&fs);

    tl_reference_time_t reftime;
    tl_error_t err = tl_cli_resolve_reftime(opts, &reftime);
    if (!tl_ok(err)) {
        emit_early_error(opts, &err, &fs, NULL, TL_MODE_INSPECT,
                         opts->format_json, opts->color, NULL);
        arena_free(arena);
        return 3;
    }

    str_t raw_jwt = str_from_cstr(opts->token_raw_heap);
    token_t *token = NULL;
    err = token_parse(arena, raw_jwt, &fs, &token);
    if (!tl_ok(err)) {
        tl_report_ctx_t rctx;
        memset(&rctx, 0, sizeof(rctx));
        rctx.mode           = TL_MODE_INSPECT;
        rctx.verdict        = TL_VERDICT_ERROR;
        rctx.exit_code      = 3;
        rctx.reference_time = reftime;
        rctx.findings       = &fs;
        rctx.error          = err;
        rctx.token_path     = str_from_cstr(opts->token_path_display);
        rctx.at_flag        = str_from_cstr(opts->at_str);
        rctx.color          = opts->color;

        if (opts->format_json) report_json(&rctx, stdout);
        else                   report_text(&rctx, stdout);

        arena_free(arena);
        return 3;
    }

    tl_report_ctx_t rctx;
    memset(&rctx, 0, sizeof(rctx));
    rctx.mode           = TL_MODE_INSPECT;
    rctx.reference_time = reftime;
    rctx.findings       = &fs;
    rctx.token          = token;
    rctx.error          = TL_OK;
    rctx.token_path     = str_from_cstr(opts->token_path_display);
    rctx.at_flag        = str_from_cstr(opts->at_str);
    rctx.color          = opts->color;
    /* inspect verdict is always pass if token parsed */
    rctx.verdict        = TL_VERDICT_PASS;
    rctx.exit_code      = 0;

    if (opts->format_json) report_json(&rctx, stdout);
    else                   report_text(&rctx, stdout);

    arena_free(arena);
    return 0;
}


/* =========================================================================
 * main
 * ========================================================================= */

int main(int argc, char **argv) {
    tl_cli_opts_t opts;
    tl_cli_result_t cli_result = tl_cli_parse(argc, argv, &opts);

    switch (cli_result) {
        case TL_CLI_EXIT_OK:
            return 0;
        case TL_CLI_ERR_USAGE:
            return 4;
        case TL_CLI_ERR_IO:
            return 3;
        case TL_CLI_OK:
            break;
    }

    int exit_code;
    switch (opts.mode) {
        case TL_MODE_AUDIT:
            exit_code = run_audit(&opts);
            break;
        case TL_MODE_VALIDATE:
            exit_code = run_validate(&opts);
            break;
        case TL_MODE_INSPECT:
            exit_code = run_inspect(&opts);
            break;
        default:
            fprintf(stderr, "tokenlint: internal: unknown mode\n");
            exit_code = 4;
            break;
    }

    tl_cli_opts_free(&opts);
    return exit_code;
}
