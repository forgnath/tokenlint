/*
 * include/time_util.h
 *
 * Time utilities for tokenlint v1.
 *
 * Parses the --at flag, resolves reference_time from the system clock,
 * and formats timestamps as ISO 8601 with Z suffix.
 *
 * All time values are int64_t Unix epoch seconds.
 *
 * Dependency: tokenlint.h (str_t, tl_error_t, TL_NODISCARD, TL_NONNULL)
 * Include order: #include "tokenlint.h" before this header.
 *
 * C11 required. No vendor headers.
 */

#ifndef TOKENLINT_TIME_UTIL_H
#define TOKENLINT_TIME_UTIL_H

#include "tokenlint.h"

#include <stddef.h>   /* size_t  */
#include <stdint.h>   /* int64_t */

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * tl_time_source_t — how reference_time was determined
 *
 * Drives the "source" field in JSON output:
 *   system_clock | cli_at | cli_at_now
 * ========================================================================= */

typedef enum {
    TL_TIME_SRC_SYSTEM_CLOCK = 0,  /* --at absent; system clock used        */
    TL_TIME_SRC_CLI_AT       = 1,  /* --at <unix> or --at <ISO8601>         */
    TL_TIME_SRC_CLI_AT_NOW   = 2   /* --at now; system clock, labelled now  */
} tl_time_source_t;


/* =========================================================================
 * tl_reference_time_t — resolved reference time for a run
 * ========================================================================= */

typedef struct {
    int64_t          value;   /* Unix epoch seconds (>= 0, post-1970)       */
    tl_time_source_t source;  /* how value was obtained                      */
} tl_reference_time_t;


/* =========================================================================
 * tl_parse_at_flag — parse the --at flag string into a reference time.
 *
 * Accepted formats (time-contract.md):
 *   "now"                          -> system clock, source = cli_at_now
 *   "<unsigned integer>"           -> exact Unix epoch seconds, cli_at
 *   "YYYY-MM-DDTHH:MM:SSZ"         -> ISO 8601 UTC with Z suffix, cli_at
 *   "YYYY-MM-DDTHH:MM:SS+HH:MM"   -> ISO 8601 with numeric offset, cli_at
 *   "YYYY-MM-DDTHH:MM:SS-HH:MM"   -> ISO 8601 with numeric offset, cli_at
 *
 * Rejected (-> TL_ERR_AT_FLAG / TL-I001):
 *   "YYYY-MM-DDTHH:MM:SS"          -> no timezone (ambiguous)
 *   "-1"                           -> negative integer
 *   any value resolving < 0        -> pre-1970
 *   unparseable strings            -> "yesterday"
 *
 * *out is written only on success. TL_OK returned on success.
 * ========================================================================= */

TL_NODISCARD TL_NONNULL(2)
tl_error_t tl_parse_at_flag(str_t at_str, tl_reference_time_t *out);


/* =========================================================================
 * tl_resolve_reference_time — resolve reference time when --at is absent.
 *
 * Reads the system clock; sets source = TL_TIME_SRC_SYSTEM_CLOCK.
 * Returns TL_ERR_INTERNAL if the system clock is unavailable.
 * ========================================================================= */

TL_NODISCARD TL_NONNULL(1)
tl_error_t tl_resolve_reference_time(tl_reference_time_t *out);


/* =========================================================================
 * tl_format_iso8601z — format Unix epoch seconds as ISO 8601 with Z suffix.
 *
 * buf must be at least TL_ISO8601Z_BUF_LEN bytes.
 * Output: "2026-04-30T12:00:00Z\0"
 * Returns 0 on success, -1 on failure (gmtime_r / strftime error).
 * ========================================================================= */

#define TL_ISO8601Z_BUF_LEN  21   /* 20 printable chars + NUL */

int tl_format_iso8601z(int64_t epoch_secs, char *buf, size_t buf_len);


/* =========================================================================
 * tl_time_source_str — JSON-output string for a tl_time_source_t value.
 *
 * Returns a string literal; caller must not free.
 *   TL_TIME_SRC_SYSTEM_CLOCK -> "system_clock"
 *   TL_TIME_SRC_CLI_AT       -> "cli_at"
 *   TL_TIME_SRC_CLI_AT_NOW   -> "cli_at_now"
 * ========================================================================= */

const char *tl_time_source_str(tl_time_source_t source);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKENLINT_TIME_UTIL_H */
