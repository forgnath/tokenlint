/*
 * include/findings.h
 *
 * Finding types for tokenlint v1.
 *
 * A finding_t is data — collected during evaluation, reported in output.
 * It is distinct from tl_error_t (a halt condition defined in tokenlint.h).
 *
 * finding_set_t is a fixed-capacity array of findings (capacity: 256).
 * Overflow is explicit and never silent — the overflowed flag is set and
 * TL_ERR_INTERNAL is emitted in the error envelope.  The first 256 findings
 * are always included.
 *
 * suppression_t holds the normalised representation of one suppression entry
 * from the policy file.  It is embedded in policy_t (policy.h) and consulted
 * by findings_add() when determining finding_status_t.
 *
 * Dependencies: tokenlint.h (str_t, TL_NODISCARD, TL_NONNULL)
 * Include order: #include "tokenlint.h" before this header.
 *
 * No vendor headers included here.  Safe to include from src/eval/.
 *
 * C11 required.
 */

#ifndef TOKENLINT_FINDINGS_H
#define TOKENLINT_FINDINGS_H

#include "tokenlint.h"

#include <stddef.h>   /* size_t */

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * severity_t — finding severity level
 *
 * Ordered from least to most severe.  Affects exit code and JSON output.
 * Severity is immutable — suppression never changes severity, only status.
 * ========================================================================= */

typedef enum {
    SEV_INFO     = 0,
    SEV_WARN     = 1,
    SEV_FAIL     = 2,
    SEV_CRITICAL = 3
} severity_t;


/* =========================================================================
 * finding_status_t — lifecycle state of a finding
 *
 * FINDING_ACTIVE            — visible, contributes to exit code
 * FINDING_SUPPRESSED_POLICY — muted by a suppression entry in the policy file
 * FINDING_SUPPRESSED_CLI    — muted by --suppress flag on the command line
 * FINDING_SKIPPED           — not applicable in this evaluation context
 *                             (e.g. validate-only finding during audit mode)
 * ========================================================================= */

typedef enum {
    FINDING_ACTIVE,
    FINDING_SUPPRESSED_POLICY,
    FINDING_SUPPRESSED_CLI,
    FINDING_SKIPPED
} finding_status_t;


/* =========================================================================
 * finding_t — a single evaluation result
 *
 * All str_t fields point into the run arena.  The finding_t itself lives in
 * the finding_set_t array (statically embedded, not separately allocated).
 *
 * Suppression sub-struct is populated only when status is
 * FINDING_SUPPRESSED_POLICY or FINDING_SUPPRESSED_CLI.
 *   source        — "policy" or "cli"
 *   reason        — human-readable reason from suppression entry
 *   owner         — owner field from suppression entry
 *   ticket        — optional ticket reference (STR_NULL if absent)
 *   expires       — ISO 8601 date string (STR_NULL if absent)
 *   expires_in_days — days until expiry, negative if already expired
 *   affects_exit  — 1 if suppression does NOT affect the exit code
 *                   (non-suppressible findings always affect_exit = 1)
 * ========================================================================= */

typedef struct {
    str_t            id;           /* e.g. "TL-V022"                        */
    str_t            title;        /* symbolic name, e.g. "TOKEN_EXPIRED"   */
    str_t            detail;       /* human-readable detail message          */
    str_t            policy_path;  /* path of the policy file evaluated      */
    severity_t       severity;     /* immutable; suppression never changes   */
    finding_status_t status;

    struct {
        str_t  source;          /* "policy" | "cli"                         */
        str_t  reason;          /* from suppression entry                   */
        str_t  owner;           /* from suppression entry                   */
        str_t  ticket;          /* optional; STR_NULL if absent             */
        str_t  expires;         /* ISO 8601 date string; STR_NULL if absent */
        int    expires_in_days; /* days until expiry; negative = past       */
        int    affects_exit;    /* 1 = still affects exit code              */
    } suppression;
} finding_t;


/* =========================================================================
 * finding_set_t — bounded collection of findings for one run
 *
 * Fixed-capacity array; no dynamic allocation.  All findings for a single
 * tokenlint run are stored here.
 *
 * Overflow behaviour:
 *   If findings_add() is called when count == TL_MAX_FINDINGS:
 *     - overflowed is set to 1
 *     - the finding is dropped (not silently — overflowed is checked at exit)
 *     - TL_ERR_INTERNAL is signalled in the output envelope
 *
 * The _Static_assert in src/eval/findings.c enforces cap <= 256.
 * ========================================================================= */

#define TL_MAX_FINDINGS 256

typedef struct {
    finding_t findings[TL_MAX_FINDINGS];
    size_t    count;
    int       overflowed;   /* 1 if any finding was dropped due to overflow */
} finding_set_t;


/* =========================================================================
 * suppression_t — normalised suppression entry from the policy file
 *
 * Populated by the policy parser from each entry in the suppressions array.
 * Consulted by findings_add() to determine whether a new finding should be
 * suppressed.
 *
 * Fields:
 *   finding_id    — the finding code this suppression targets, e.g. "TL-A007"
 *   reason        — required; non-empty string
 *   owner         — required; non-empty string
 *   ticket        — optional; STR_NULL if absent
 *   expires       — ISO 8601 date string; STR_NULL if absent
 *                   (required in prod; FAIL TL-S024 if missing)
 *   expires_epoch — Unix epoch of the expires date, or 0 if absent
 *                   Populated by the parser after date parsing.
 * ========================================================================= */

typedef struct {
    str_t   finding_id;    /* e.g. STR_LIT("TL-A007")                 */
    str_t   reason;        /* required; non-empty                      */
    str_t   owner;         /* required; non-empty                      */
    str_t   ticket;        /* optional; STR_NULL if absent             */
    str_t   expires;       /* ISO 8601 date string; STR_NULL if absent */
    int64_t expires_epoch; /* Unix epoch of expires; 0 if absent       */
} suppression_t;


/* =========================================================================
 * findings_add — add a finding to the set (declared here; implemented in
 * src/eval/findings.c).
 *
 * Checks suppression entries from the provided suppression array.
 * Sets finding status to FINDING_SUPPRESSED_POLICY if a matching,
 * non-expired suppression entry exists.
 *
 * Returns 1 if the finding was added (active or suppressed).
 * Returns 0 if the finding was dropped due to overflow.
 *
 * arena is used to intern the detail string if it was constructed at runtime.
 * suppression_list / suppression_count may be NULL/0 (no suppressions).
 *
 * TL_NONNULL(1, 2, 3): fs, f, and arena must not be NULL.
 * suppression_list may be NULL when suppression_count is 0.
 */
TL_NODISCARD TL_NONNULL(1, 2, 3)
int findings_add(finding_set_t       *fs,
                 const finding_t     *f,
                 arena_t             *arena,
                 const suppression_t *suppression_list,
                 size_t               suppression_count);

/*
 * findings_init — zero-initialise a finding_set_t.
 * Call once before any findings_add() calls.
 * TL_NONNULL(1): fs must not be NULL.
 */
TL_NONNULL(1)
void findings_init(finding_set_t *fs);

/*
 * findings_has_active_fail — returns 1 if any active (non-suppressed) finding
 * has severity >= SEV_FAIL.  Used to determine exit code.
 * TL_NONNULL(1): fs must not be NULL.
 */
TL_PURE TL_NONNULL(1)
int findings_has_active_fail(const finding_set_t *fs);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKENLINT_FINDINGS_H */
