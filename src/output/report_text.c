/*
 * src/output/report_text.c
 *
 * Human-readable text report for tokenlint v1.
 *
 * Format follows docs/output-contract.md §Text output format.
 * Color is off by default; enabled only when ctx->color == 1.
 * No ANSI codes in JSON output; this file is text-only.
 */

#include "tokenlint.h"
#include "report.h"
#include "findings.h"
#include "time_util.h"

#include <stdio.h>
#include <string.h>


/* =========================================================================
 * ANSI color codes
 * ========================================================================= */

#define ANSI_RED    "\033[31m"
#define ANSI_GREEN  "\033[32m"
#define ANSI_YELLOW "\033[33m"
#define ANSI_BOLD   "\033[1m"
#define ANSI_RESET  "\033[0m"

static const char *col_red(int color)    { return color ? ANSI_RED    : ""; }
static const char *col_bold(int color)   { return color ? ANSI_BOLD   : ""; }
static const char *col_reset(int color)  { return color ? ANSI_RESET  : ""; }


/* =========================================================================
 * Helpers
 * ========================================================================= */

static void print_rule(FILE *fp, char c, int width)
{
    for (int i = 0; i < width; i++) fputc(c, fp);
    fputc('\n', fp);
}

static const char *severity_label(severity_t sev, int color)
{
    switch (sev) {
        case SEV_CRITICAL: return color ? ANSI_RED    "CRIT" ANSI_RESET : "CRIT";
        case SEV_FAIL:     return color ? ANSI_RED    "FAIL" ANSI_RESET : "FAIL";
        case SEV_WARN:     return color ? ANSI_YELLOW "WARN" ANSI_RESET : "WARN";
        case SEV_INFO:     return color ? ANSI_BOLD   "INFO" ANSI_RESET : "INFO";
        default:           return "????";
    }
}


/* =========================================================================
 * report_text — main entry point
 * ========================================================================= */

void report_text(const tl_report_ctx_t *ctx, FILE *fp)
{
    int color = ctx->color;

    /* ── header ── */
    const char *env_str = ctx->policy ? tl_env_name(ctx->policy->environment)
                                       : "unknown";
    if (ctx->policy && !STR_IS_NULL(ctx->policy->validator_id)) {
        fprintf(fp, "%stokenlint %s%s — %.*s [%s]\n",
                col_bold(color), mode_name(ctx->mode), col_reset(color),
                (int)ctx->policy->validator_id.len,
                ctx->policy->validator_id.data,
                env_str);
    } else {
        fprintf(fp, "%stokenlint %s%s\n",
                col_bold(color), mode_name(ctx->mode), col_reset(color));
    }
    print_rule(fp, (char)0xE2, 40);   /* unicode box char won't render cleanly; use ASCII */
    /* Use plain = signs for portability */
    for (int i = 0; i < 40; i++) fputc('=', fp);
    fputc('\n', fp);

    fputc('\n', fp);

    /* ── findings ── */
    if (ctx->findings && ctx->findings->count > 0) {
        for (size_t i = 0; i < ctx->findings->count; i++) {
            const finding_t *f = &ctx->findings->findings[i];

            /* Status prefix */
            if (f->status == FINDING_SUPPRESSED_POLICY ||
                f->status == FINDING_SUPPRESSED_CLI) {
                fprintf(fp, "  ░░░░  ");
            } else if (f->status == FINDING_ACTIVE) {
                fprintf(fp, "  %s  ", severity_label(f->severity, color));
            } else {
                /* skipped — omit */
                continue;
            }

            /* ID and title */
            fprintf(fp, "%.*s  %.*s",
                    (int)f->id.len,    f->id.data,
                    (int)f->title.len, f->title.data);

            if (f->status == FINDING_SUPPRESSED_POLICY ||
                f->status == FINDING_SUPPRESSED_CLI) {
                fprintf(fp, "  [suppressed]");
            }
            fputc('\n', fp);

            /* detail */
            if (!STR_IS_NULL(f->detail) && f->detail.len > 0) {
                fprintf(fp, "        %.*s\n",
                        (int)f->detail.len, f->detail.data);
            }

            /* suppression info */
            if (f->status == FINDING_SUPPRESSED_POLICY ||
                f->status == FINDING_SUPPRESSED_CLI) {
                if (!STR_IS_NULL(f->suppression.owner)) {
                    fprintf(fp, "        owner:   %.*s\n",
                            (int)f->suppression.owner.len,
                            f->suppression.owner.data);
                }
                if (!STR_IS_NULL(f->suppression.ticket)) {
                    fprintf(fp, "        ticket:  %.*s\n",
                            (int)f->suppression.ticket.len,
                            f->suppression.ticket.data);
                }
                if (!STR_IS_NULL(f->suppression.expires)) {
                    fprintf(fp, "        expires: %.*s (%d days)\n",
                            (int)f->suppression.expires.len,
                            f->suppression.expires.data,
                            f->suppression.expires_in_days);
                }
            }

            fputc('\n', fp);
        }
    } else {
        fprintf(fp, "  (no findings)\n\n");
    }

    /* ── footer rule ── */
    for (int i = 0; i < 40; i++) fputc('-', fp);
    fputc('\n', fp);

    /* ── verdict line ── */
    const char *v_color = "";
    if (color) {
        switch (ctx->verdict) {
            case TL_VERDICT_PASS:  v_color = ANSI_GREEN;  break;
            case TL_VERDICT_WARN:  v_color = ANSI_YELLOW; break;
            case TL_VERDICT_FAIL:
            case TL_VERDICT_ERROR: v_color = ANSI_RED;    break;
        }
    }
    fprintf(fp, "verdict:  %s%s%s\n",
            v_color, verdict_name(ctx->verdict),
            color ? ANSI_RESET : "");

    /* ── summary counts ── */
    size_t total = 0, active = 0, suppressed = 0;
    if (ctx->findings) {
        total = ctx->findings->count;
        for (size_t i = 0; i < ctx->findings->count; i++) {
            const finding_t *f = &ctx->findings->findings[i];
            if (f->status == FINDING_ACTIVE) active++;
            if (f->status == FINDING_SUPPRESSED_POLICY ||
                f->status == FINDING_SUPPRESSED_CLI)    suppressed++;
        }
    }
    fprintf(fp, "findings: %zu total  %zu active  %zu suppressed\n",
            total, active, suppressed);

    fprintf(fp, "exit:     %d\n", ctx->exit_code);

    /* ── error block (if halted) ── */
    if (!tl_ok(ctx->error)) {
        fputc('\n', fp);
        fprintf(fp, "%serror:%s %s\n",
                col_red(color), col_reset(color),
                err_kind_name(ctx->error.kind));
        if (!STR_IS_NULL(ctx->error.message)) {
            fprintf(fp, "  %.*s\n",
                    (int)ctx->error.message.len, ctx->error.message.data);
        }
        if (!STR_IS_NULL(ctx->error.context)) {
            fprintf(fp, "  context: %.*s\n",
                    (int)ctx->error.context.len, ctx->error.context.data);
        }
    }
}
