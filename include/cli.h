/*
 * include/cli.h
 *
 * CLI argument parsing for tokenlint v1.
 *
 * tl_cli_opts_t holds the parsed result of argv.
 * tl_cli_parse() fills it in; main() reads it.
 *
 * Dependencies:
 *   tokenlint.h  — str_t, tl_error_t
 *   report.h     — tl_mode_t
 *   time_util.h  — tl_reference_time_t
 *
 * Include order: tokenlint.h → alg.h → findings.h → policy.h → token.h
 *   → jwks.h → time_util.h → report.h → cli.h
 *
 * C11 required.
 */

#ifndef TOKENLINT_CLI_H
#define TOKENLINT_CLI_H

#include "tokenlint.h"
#include "report.h"
#include "time_util.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * TL_BUILD_VERSION — embedded at compile time via -DTL_BUILD_VERSION="..."
 * Falls back to "dev" if not provided.
 * ========================================================================= */

#ifndef TL_BUILD_VERSION
#  define TL_BUILD_VERSION "dev"
#endif


/* =========================================================================
 * tl_cli_result_t — return value from tl_cli_parse()
 * ========================================================================= */

typedef enum {
    TL_CLI_OK         = 0,  /* parsed successfully                          */
    TL_CLI_EXIT_OK    = 1,  /* --version or --help handled; caller exits 0  */
    TL_CLI_ERR_USAGE  = 2,  /* bad flags / missing required; exit 4         */
    TL_CLI_ERR_IO     = 3   /* token file unreadable; exit 3                */
} tl_cli_result_t;


/* =========================================================================
 * tl_cli_opts_t — parsed CLI options for one invocation
 *
 * token_raw_heap — heap-allocated (malloc) raw JWT string; free with
 *                  tl_cli_opts_free() when done.  NULL in audit mode.
 * token_path_display — "stdin" or the file path; points into argv or
 *                       static literal; do not free.
 * suppress_ids   — malloc'd array of const char* pointing into argv;
 *                  each element may be comma-separated IDs.
 * ========================================================================= */

typedef struct {
    tl_mode_t    mode;              /* TL_MODE_AUDIT / VALIDATE / INSPECT   */

    /* paths (point into argv; do not free) */
    const char  *policy_path;
    const char  *jwks_path;
    const char  *at_str;            /* raw --at value or NULL               */
    const char  *severity_filter;   /* raw --severity value or NULL         */

    /* token */
    char        *token_raw_heap;    /* heap-allocated; free via cli_opts_free */
    const char  *token_path_display; /* "stdin" or file path                */
    int          token_from_stdin;  /* 1 if token came from stdin           */

    /* suppression */
    const char **suppress_ids;      /* malloc'd array; entries point into argv */
    size_t       suppress_count;

    /* flags */
    int  format_json;           /* 1=json (default), 0=text                */
    int  verbose;               /* --verbose                               */
    int  color;                 /* --color                                 */
    int  no_color;              /* --no-color                              */
    int  lenient;               /* --lenient                               */
    int  skip_policy_audit;     /* --skip-policy-audit (validate only)     */
    int  suppress_affects_exit; /* --suppress-affects-exit                 */
} tl_cli_opts_t;


/* =========================================================================
 * tl_cli_opts_init — zero-initialise a tl_cli_opts_t before parsing.
 * ========================================================================= */

void tl_cli_opts_init(tl_cli_opts_t *opts);


/* =========================================================================
 * tl_cli_opts_free — release heap-allocated fields inside tl_cli_opts_t.
 * Does not free opts itself.
 * ========================================================================= */

void tl_cli_opts_free(tl_cli_opts_t *opts);


/* =========================================================================
 * tl_cli_parse — parse argc/argv into opts.
 *
 * Returns TL_CLI_OK on success.
 * Returns TL_CLI_EXIT_OK if caller should exit(0) (--version, --help).
 * Returns TL_CLI_ERR_USAGE on bad arguments (message printed to stderr).
 * Returns TL_CLI_ERR_IO if token file is unreadable.
 * ========================================================================= */

tl_cli_result_t tl_cli_parse(int argc, char **argv, tl_cli_opts_t *opts);


/* =========================================================================
 * tl_cli_resolve_reftime — resolve reference_time from --at or system clock.
 * ========================================================================= */

tl_error_t tl_cli_resolve_reftime(const tl_cli_opts_t *opts,
                                   tl_reference_time_t *out);


/* =========================================================================
 * tl_cli_suppress_active — returns 1 if finding_id is in --suppress list.
 * ========================================================================= */

int tl_cli_suppress_active(const tl_cli_opts_t *opts, const char *finding_id);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKENLINT_CLI_H */
