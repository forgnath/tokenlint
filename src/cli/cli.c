/*
 * src/cli/cli.c
 *
 * Argument parsing, stdin detection, and --at flag parsing for tokenlint v1.
 *
 * Parses argv into a tl_cli_opts_t.  No business logic here — main.c
 * reads tl_cli_opts_t and dispatches to the appropriate mode.
 *
 * Spec: docs/cli-contract.md
 * C11 required.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli.h"
#include "tokenlint.h"
#include "time_util.h"
#include "str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#ifdef _WIN32
#  include <io.h>
#  define isatty _isatty
#  define STDIN_FILENO 0
#else
#  include <unistd.h>
#endif


/* ── internal helpers ───────────────────────────────────────────────────── */

static int streq(const char *a, const char *b) {
    return strcmp(a, b) == 0;
}

/*
 * next_arg — consume the next argv element as the value for flag `flag`.
 * On success, advances *i and returns argv[*i].
 * On failure (end of args), prints to stderr and sets *err.
 */
static const char *next_arg(const char *flag, int argc, char **argv,
                             int *i, int *err) {
    if (*i + 1 >= argc) {
        fprintf(stderr,
                "Flag '%s' requires an argument. "
                "Run 'tokenlint --help' for usage.\n", flag);
        *err = 1;
        return NULL;
    }
    (*i)++;
    return argv[*i];
}

/*
 * stdin_is_piped — returns 1 if stdin is not a tty (i.e. data is piped in).
 */
static int stdin_is_piped(void) {
    return !isatty(STDIN_FILENO);
}

/*
 * read_stdin_token — read all of stdin into a malloc'd buffer.
 * Caller must free. Returns NULL on error.
 * Strips trailing whitespace (newline, CR) from the raw token.
 */
static char *read_stdin_token(void) {
    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;

    int c;
    while ((c = fgetc(stdin)) != EOF) {
        if (len + 1 >= cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        buf[len++] = (char)c;
    }
    buf[len] = '\0';

    /* strip trailing whitespace */
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' ||
                        buf[len-1] == ' '  || buf[len-1] == '\t')) {
        buf[--len] = '\0';
    }
    return buf;
}

/*
 * read_file_token — read a token from a file path.
 * Caller must free. Returns NULL on error.
 */
static char *read_file_token(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }

    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t n = fread(buf, 1, (size_t)sz, f);
    buf[n] = '\0';
    fclose(f);

    /* strip trailing whitespace */
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' ||
                     buf[n-1] == ' '  || buf[n-1] == '\t')) {
        buf[--n] = '\0';
    }
    return buf;
}


/* =========================================================================
 * tl_cli_opts_init — zero-initialise a tl_cli_opts_t.
 * ========================================================================= */

void tl_cli_opts_init(tl_cli_opts_t *opts) {
    memset(opts, 0, sizeof(*opts));
    opts->mode              = TL_MODE_AUDIT;   /* will be overwritten */
    opts->format_json       = 1;               /* default: json */
    /* suppress_ids and suppress_count are 0-initialised by memset */
    /* at_str, policy_path, etc. are NULL-initialised */
}


/* =========================================================================
 * tl_cli_opts_free — free heap-allocated fields inside tl_cli_opts_t.
 * ========================================================================= */

void tl_cli_opts_free(tl_cli_opts_t *opts) {
    if (!opts) return;
    if (opts->token_raw_heap) {
        free(opts->token_raw_heap);
        opts->token_raw_heap = NULL;
    }
    /* suppress_ids elements point into argv (not heap) — no free needed */
}


/* =========================================================================
 * tl_cli_parse — parse argc/argv into tl_cli_opts_t.
 *
 * Returns TL_CLI_OK on success.
 * Returns TL_CLI_EXIT_OK if --version or --help was handled (caller should
 *   exit 0).
 * Returns TL_CLI_ERR on usage errors (message already printed to stderr).
 * ========================================================================= */

static void print_top_help(void) {
    printf(
        "Usage: tokenlint <subcommand> [options]\n"
        "\n"
        "Subcommands:\n"
        "  audit     Validate a policy file for dangerous trust assumptions\n"
        "  validate  Validate a token against a policy and JWKS\n"
        "  inspect   Parse and display token structure\n"
        "\n"
        "Global flags:\n"
        "  --version          Print version and exit\n"
        "  --help             Print this help and exit\n"
        "  --format <fmt>     json (default) or text\n"
        "  --color            Enable ANSI color in text output\n"
        "  --no-color         Disable ANSI color (default)\n"
        "  --verbose          Include info/skipped findings\n"
        "\n"
        "Run 'tokenlint <subcommand> --help' for subcommand usage.\n"
    );
}

static void print_audit_help(void) {
    printf(
        "Usage: tokenlint audit --policy <path> [options]\n"
        "\n"
        "Validate a policy file for dangerous trust assumptions.\n"
        "\n"
        "Required:\n"
        "  --policy <path>          Path to validator policy YAML file\n"
        "\n"
        "Options:\n"
        "  --at <time>              Reference time (unix epoch, ISO8601Z, 'now')\n"
        "  --format <fmt>           json (default) or text\n"
        "  --severity <levels>      Comma-separated: critical,fail,warn,info\n"
        "  --suppress <ids>         Comma-separated finding IDs to suppress\n"
        "  --suppress-affects-exit  CLI suppressions affect exit code\n"
        "  --lenient                Treat unknown fields as WARN not FAIL\n"
        "  --verbose                Include info/skipped findings\n"
        "  --color                  Enable ANSI color\n"
        "  --no-color               Disable ANSI color (default)\n"
    );
}

static void print_validate_help(void) {
    printf(
        "Usage: tokenlint validate [--token <path|->] --policy <path> --jwks <path> [options]\n"
        "\n"
        "Validate a token against a policy and JWKS.\n"
        "\n"
        "Required:\n"
        "  --policy <path>          Path to validator policy YAML file\n"
        "  --jwks <path>            Path to JWKS file\n"
        "  --token <path|->         Token file path, '-' for stdin\n"
        "    (or pipe token on stdin if --token is absent)\n"
        "\n"
        "Options:\n"
        "  --skip-policy-audit      Skip policy audit phase\n"
        "  --at <time>              Reference time\n"
        "  --format <fmt>           json (default) or text\n"
        "  --severity <levels>      Comma-separated: critical,fail,warn,info\n"
        "  --suppress <ids>         Comma-separated finding IDs to suppress\n"
        "  --suppress-affects-exit  CLI suppressions affect exit code\n"
        "  --lenient                Lenient schema parsing\n"
        "  --verbose                Include info/skipped findings\n"
        "  --color                  Enable ANSI color\n"
        "  --no-color               Disable ANSI color (default)\n"
    );
}

static void print_inspect_help(void) {
    printf(
        "Usage: tokenlint inspect [--token <path|->] [options]\n"
        "\n"
        "Parse and display token structure. No policy or JWKS required.\n"
        "\n"
        "Token input:\n"
        "  --token <path|->         Token file path, '-' for stdin\n"
        "    (or pipe token on stdin if --token is absent)\n"
        "\n"
        "Options:\n"
        "  --at <time>              Reference time for exp/nbf display\n"
        "  --format <fmt>           json (default) or text\n"
        "  --verbose                Include raw header/payload bytes\n"
        "  --color                  Enable ANSI color\n"
        "  --no-color               Disable ANSI color (default)\n"
    );
}

tl_cli_result_t tl_cli_parse(int argc, char **argv, tl_cli_opts_t *opts) {
    tl_cli_opts_init(opts);

    if (argc < 2) {
        print_top_help();
        return TL_CLI_EXIT_OK;
    }

    /* --version and --help at top level */
    if (streq(argv[1], "--version")) {
        printf("tokenlint %s\n", TL_BUILD_VERSION);
        return TL_CLI_EXIT_OK;
    }
    if (streq(argv[1], "--help") || streq(argv[1], "-h")) {
        print_top_help();
        return TL_CLI_EXIT_OK;
    }

    /* Subcommand */
    const char *sub = argv[1];
    if (streq(sub, "audit")) {
        opts->mode = TL_MODE_AUDIT;
    } else if (streq(sub, "validate")) {
        opts->mode = TL_MODE_VALIDATE;
    } else if (streq(sub, "inspect")) {
        opts->mode = TL_MODE_INSPECT;
    } else {
        fprintf(stderr,
                "Unknown subcommand '%s'. "
                "Valid subcommands: audit, validate, inspect\n", sub);
        return TL_CLI_ERR_USAGE;
    }

    /* Per-subcommand --help */
    if (argc >= 3 && (streq(argv[2], "--help") || streq(argv[2], "-h"))) {
        switch (opts->mode) {
            case TL_MODE_AUDIT:    print_audit_help();    break;
            case TL_MODE_VALIDATE: print_validate_help(); break;
            case TL_MODE_INSPECT:  print_inspect_help();  break;
        }
        return TL_CLI_EXIT_OK;
    }

    /* Collect raw --suppress values; we'll split them below */
    /* We allow --suppress to be passed multiple times or as comma-separated */
    const char *suppress_raw[64];
    int suppress_raw_count = 0;
    const char *token_path_arg = NULL;    /* raw --token value */

    int err = 0;

    for (int i = 2; i < argc && !err; i++) {
        const char *arg = argv[i];

        /* Global flags */
        if (streq(arg, "--version")) {
            printf("tokenlint %s\n", TL_BUILD_VERSION);
            return TL_CLI_EXIT_OK;
        }
        if (streq(arg, "--help") || streq(arg, "-h")) {
            switch (opts->mode) {
                case TL_MODE_AUDIT:    print_audit_help();    break;
                case TL_MODE_VALIDATE: print_validate_help(); break;
                case TL_MODE_INSPECT:  print_inspect_help();  break;
            }
            return TL_CLI_EXIT_OK;
        }
        if (streq(arg, "--color")) {
            opts->color = 1;
        } else if (streq(arg, "--no-color")) {
            opts->no_color = 1;
        } else if (streq(arg, "--verbose")) {
            opts->verbose = 1;
        } else if (streq(arg, "--format")) {
            const char *v = next_arg("--format", argc, argv, &i, &err);
            if (!v) break;
            if (streq(v, "json")) {
                opts->format_json = 1;
            } else if (streq(v, "text")) {
                opts->format_json = 0;
            } else {
                fprintf(stderr,
                        "Unknown format '%s'. Valid values: json, text\n", v);
                err = 1;
            }
        } else if (streq(arg, "--at")) {
            const char *v = next_arg("--at", argc, argv, &i, &err);
            if (!v) break;
            opts->at_str = v;
        } else if (streq(arg, "--policy")) {
            const char *v = next_arg("--policy", argc, argv, &i, &err);
            if (!v) break;
            if (opts->mode == TL_MODE_INSPECT) {
                fprintf(stderr,
                        "Unknown flag '--policy'. "
                        "Run 'tokenlint inspect --help' for usage.\n");
                err = 1;
                break;
            }
            opts->policy_path = v;
        } else if (streq(arg, "--jwks")) {
            const char *v = next_arg("--jwks", argc, argv, &i, &err);
            if (!v) break;
            if (opts->mode != TL_MODE_VALIDATE) {
                fprintf(stderr,
                        "Unknown flag '--jwks'. "
                        "Run 'tokenlint %s --help' for usage.\n",
                        opts->mode == TL_MODE_AUDIT ? "audit" : "inspect");
                err = 1;
                break;
            }
            opts->jwks_path = v;
        } else if (streq(arg, "--token")) {
            const char *v = next_arg("--token", argc, argv, &i, &err);
            if (!v) break;
            if (opts->mode == TL_MODE_AUDIT) {
                fprintf(stderr,
                        "Unknown flag '--token'. "
                        "Run 'tokenlint audit --help' for usage.\n");
                err = 1;
                break;
            }
            token_path_arg = v;
        } else if (streq(arg, "--suppress")) {
            const char *v = next_arg("--suppress", argc, argv, &i, &err);
            if (!v) break;
            if (opts->mode == TL_MODE_INSPECT) {
                fprintf(stderr,
                        "Unknown flag '--suppress'. "
                        "Run 'tokenlint inspect --help' for usage.\n");
                err = 1;
                break;
            }
            if (suppress_raw_count < 64) {
                suppress_raw[suppress_raw_count++] = v;
            }
        } else if (streq(arg, "--suppress-affects-exit")) {
            if (opts->mode == TL_MODE_INSPECT) {
                fprintf(stderr,
                        "Unknown flag '--suppress-affects-exit'. "
                        "Run 'tokenlint inspect --help' for usage.\n");
                err = 1;
                break;
            }
            opts->suppress_affects_exit = 1;
        } else if (streq(arg, "--lenient")) {
            if (opts->mode == TL_MODE_INSPECT) {
                fprintf(stderr,
                        "Unknown flag '--lenient'. "
                        "Run 'tokenlint inspect --help' for usage.\n");
                err = 1;
                break;
            }
            opts->lenient = 1;
        } else if (streq(arg, "--severity")) {
            const char *v = next_arg("--severity", argc, argv, &i, &err);
            if (!v) break;
            if (opts->mode == TL_MODE_INSPECT) {
                fprintf(stderr,
                        "Unknown flag '--severity'. "
                        "Run 'tokenlint inspect --help' for usage.\n");
                err = 1;
                break;
            }
            opts->severity_filter = v;
        } else if (streq(arg, "--skip-policy-audit")) {
            if (opts->mode == TL_MODE_AUDIT) {
                fprintf(stderr,
                        "'--skip-policy-audit' is invalid for the 'audit' "
                        "subcommand.\n");
                err = 1;
                break;
            }
            if (opts->mode == TL_MODE_INSPECT) {
                fprintf(stderr,
                        "Unknown flag '--skip-policy-audit'. "
                        "Run 'tokenlint inspect --help' for usage.\n");
                err = 1;
                break;
            }
            opts->skip_policy_audit = 1;
        } else {
            /* Unknown flag */
            const char *subcmd = sub;
            fprintf(stderr,
                    "Unknown flag '%s'. "
                    "Run 'tokenlint %s --help' for usage.\n",
                    arg, subcmd);
            return TL_CLI_ERR_USAGE;
        }
    }

    if (err) return TL_CLI_ERR_USAGE;

    /* --no-color wins over --color */
    if (opts->no_color) opts->color = 0;

    /* ── validate required flags ─────────────────────────────────────────── */

    if (opts->mode == TL_MODE_AUDIT || opts->mode == TL_MODE_VALIDATE) {
        if (!opts->policy_path) {
            fprintf(stderr,
                    "Required flag '--policy' is missing. "
                    "Run 'tokenlint %s --help' for usage.\n",
                    opts->mode == TL_MODE_AUDIT ? "audit" : "validate");
            return TL_CLI_ERR_USAGE;
        }
    }
    if (opts->mode == TL_MODE_VALIDATE) {
        if (!opts->jwks_path) {
            fprintf(stderr,
                    "Required flag '--jwks' is missing. "
                    "Run 'tokenlint validate --help' for usage.\n");
            return TL_CLI_ERR_USAGE;
        }
    }

    /* ── token resolution ────────────────────────────────────────────────── */

    if (opts->mode == TL_MODE_VALIDATE || opts->mode == TL_MODE_INSPECT) {
        if (token_path_arg) {
            if (streq(token_path_arg, "-")) {
                /* explicit stdin */
                opts->token_from_stdin = 1;
                opts->token_path_display = "stdin";
                opts->token_raw_heap = read_stdin_token();
                if (!opts->token_raw_heap) {
                    fprintf(stderr, "Failed to read token from stdin.\n");
                    return TL_CLI_ERR_USAGE;
                }
            } else {
                /* file path — --token <path> wins; ignore piped stdin */
                opts->token_from_stdin = 0;
                opts->token_path_display = token_path_arg;
                opts->token_raw_heap = read_file_token(token_path_arg);
                if (!opts->token_raw_heap) {
                    fprintf(stderr, "Cannot read token file: %s\n",
                            token_path_arg);
                    return TL_CLI_ERR_IO;
                }
            }
        } else if (stdin_is_piped()) {
            /* implicit stdin */
            opts->token_from_stdin = 1;
            opts->token_path_display = "stdin";
            opts->token_raw_heap = read_stdin_token();
            if (!opts->token_raw_heap) {
                fprintf(stderr, "Failed to read token from stdin.\n");
                return TL_CLI_ERR_USAGE;
            }
        } else {
            if (opts->mode == TL_MODE_VALIDATE) {
                fprintf(stderr,
                        "No token provided. Use '--token <path>', "
                        "'--token -', or pipe a token on stdin.\n");
                return TL_CLI_ERR_USAGE;
            }
            /* inspect with no token: allowed? spec says same contract as validate.
               So it's also an error for inspect with no token. */
            fprintf(stderr,
                    "No token provided. Use '--token <path>', "
                    "'--token -', or pipe a token on stdin.\n");
            return TL_CLI_ERR_USAGE;
        }
    }

    /* ── parse suppress IDs ──────────────────────────────────────────────── */

    /* Count total IDs across all --suppress args (comma-separated) */
    size_t total = 0;
    for (int i = 0; i < suppress_raw_count; i++) {
        const char *p = suppress_raw[i];
        total++;
        while (*p) { if (*p == ',') total++; p++; }
    }

    if (total > 0) {
        opts->suppress_ids = malloc(sizeof(const char *) * total);
        if (!opts->suppress_ids) {
            fprintf(stderr, "Out of memory parsing --suppress.\n");
            return TL_CLI_ERR_USAGE;
        }
        opts->suppress_count = 0;

        for (int i = 0; i < suppress_raw_count; i++) {
            /* strtok_r over a copy — but we need the IDs to persist.
               Since suppress_raw[i] points into argv (which persists),
               we can split in-place — but argv is not writable in general.
               Instead, store pointers to non-comma-split portions and
               detect commas at match time in main.c.
               For simplicity: just store the entire raw string; main.c
               splits on commas when checking. */
            opts->suppress_ids[opts->suppress_count++] = suppress_raw[i];
        }
    }

    return TL_CLI_OK;
}


/* =========================================================================
 * tl_cli_resolve_reftime — parse --at flag or resolve system clock.
 *
 * Must be called after tl_cli_parse() succeeds.
 * Returns TL_OK on success; TL_ERR_AT_FLAG on bad --at value.
 * ========================================================================= */

tl_error_t tl_cli_resolve_reftime(const tl_cli_opts_t *opts,
                                   tl_reference_time_t *out) {
    if (opts->at_str) {
        str_t at = str_from_cstr(opts->at_str);
        return tl_parse_at_flag(at, out);
    }
    return tl_resolve_reference_time(out);
}


/* =========================================================================
 * tl_cli_suppress_active — returns 1 if finding_id matches any --suppress
 * entry in opts.  Handles comma-separated values within a single entry.
 * ========================================================================= */

int tl_cli_suppress_active(const tl_cli_opts_t *opts, const char *finding_id) {
    if (!opts->suppress_ids || !finding_id) return 0;

    for (size_t i = 0; i < opts->suppress_count; i++) {
        const char *raw = opts->suppress_ids[i];
        /* Walk comma-separated tokens */
        const char *p = raw;
        while (*p) {
            const char *start = p;
            while (*p && *p != ',') p++;
            size_t len = (size_t)(p - start);
            size_t flen = strlen(finding_id);
            if (len == flen && memcmp(start, finding_id, len) == 0) {
                return 1;
            }
            if (*p == ',') p++;
        }
    }
    return 0;
}
