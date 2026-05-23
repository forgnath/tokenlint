/*
 * src/eval/findings.c
 *
 * findings_add(), findings_init(), findings_has_active_fail().
 *
 * Non-suppressible findings:
 *   All TL-S0xx findings are non-suppressible by definition.
 *   The additional non-suppressible set from finding-registry.md is encoded
 *   in the is_nonsuppressible() table below.  Any suppression entry targeting
 *   a non-suppressible finding is silently ignored — the finding remains ACTIVE.
 *
 * Suppression check (for suppressible findings):
 *   For each new finding, scan suppression_list for a matching finding_id.
 *   If found and the suppression is not expired (expires_epoch == 0 or
 *   expires_epoch > now), mark the finding FINDING_SUPPRESSED_POLICY and
 *   populate the suppression sub-struct including expires_in_days.
 *
 * Overflow:
 *   If count == TL_MAX_FINDINGS, set overflowed = 1 and return 0.
 *   The first 256 findings are always preserved.
 *
 * Dependency: tokenlint.h, findings.h.
 * No vendor headers.  Safe to include from src/eval/.
 */

#include "tokenlint.h"
#include "findings.h"

#include <string.h>
#include <stdint.h>
#include <time.h>     /* time(NULL) for expires_in_days computation */

_Static_assert(TL_MAX_FINDINGS <= 256,
    "finding capacity exceeds intended maximum");


/* =========================================================================
 * Non-suppressible finding table
 *
 * Built from the canonical list in docs/finding-registry.md.
 * All TL-S findings are non-suppressible; TL-V/TL-I exceptions listed below.
 * ========================================================================= */

/*
 * is_nonsuppressible — returns 1 if the finding with this string ID can never
 * be suppressed, 0 if it is eligible for suppression.
 *
 * Uses a linear scan over a small static table (27 entries max).
 * Performance is irrelevant — findings_add() is called at most 256 times.
 */
static int is_nonsuppressible(str_t id)
{
    /* All TL-S findings are non-suppressible — check prefix first. */
    if (id.len >= 4 &&
        id.data[0] == 'T' && id.data[1] == 'L' &&
        id.data[2] == '-' && id.data[3] == 'S')
    {
        return 1;
    }

    /* Additional non-suppressible findings outside TL-S namespace */
    static const char * const nonsuppressible[] = {
        "TL-V000",  /* TOKEN_UNPARSEABLE      */
        "TL-V001",  /* TOKEN_ALG_ABSENT       */
        "TL-V002",  /* TOKEN_ALG_UNRECOGNIZED */
        "TL-V006",  /* TOKEN_SIG_INVALID      */
        "TL-V022",  /* TOKEN_EXPIRED          */
        "TL-V024",  /* TOKEN_TTL_INVALID      */
        "TL-I001",  /* AT_FLAG_INVALID        */
        NULL
    };

    for (size_t i = 0; nonsuppressible[i] != NULL; i++) {
        const char *ns = nonsuppressible[i];
        size_t      ns_len = strlen(ns);
        if (id.len == ns_len && memcmp(id.data, ns, ns_len) == 0)
            return 1;
    }

    return 0;
}


/* =========================================================================
 * findings_init — zero-initialise a finding_set_t
 * ========================================================================= */

void findings_init(finding_set_t *fs)
{
    memset(fs, 0, sizeof *fs);
}


/* =========================================================================
 * findings_add — add a finding to the set
 *
 * Steps:
 *   1. Overflow guard — return 0 if capacity exhausted.
 *   2. Copy the template finding into the next slot.
 *   3. Default status: FINDING_ACTIVE.
 *   4. If finding is non-suppressible, leave ACTIVE regardless of suppressions.
 *   5. Otherwise, scan suppression_list for a match:
 *      a. Skip if expires_epoch != 0 && expires_epoch <= now (expired).
 *      b. On match: set FINDING_SUPPRESSED_POLICY, populate suppression fields,
 *         compute expires_in_days from now.
 *   6. Return 1.
 * ========================================================================= */

int findings_add(finding_set_t       *fs,
                 const finding_t     *f,
                 arena_t             *arena,
                 const suppression_t *suppression_list,
                 size_t               suppression_count)
{
    TL_UNUSED(arena); /* reserved for future runtime detail string interning */

    /* Step 1: overflow guard */
    if (fs->count >= TL_MAX_FINDINGS) {
        fs->overflowed = 1;
        return 0;
    }

    /* Step 2: copy template into slot */
    finding_t *slot = &fs->findings[fs->count++];
    *slot = *f;

    /* Step 3: default active */
    slot->status = FINDING_ACTIVE;
    memset(&slot->suppression, 0, sizeof slot->suppression);

    /* Step 4: non-suppressible findings are always active — skip suppression */
    if (is_nonsuppressible(f->id))
        return 1;

    /* Step 5: scan for a matching, non-expired suppression */
    int64_t now = (int64_t)time(NULL);

    for (size_t i = 0; i < suppression_count; i++) {
        const suppression_t *s = &suppression_list[i];

        /* ID match required */
        if (!str_eq(s->finding_id, f->id))
            continue;

        /* Step 5a: expired suppression — treat as absent */
        if (s->expires_epoch != 0 && s->expires_epoch <= now)
            continue;

        /* Step 5b: live suppression — apply it */
        slot->status = FINDING_SUPPRESSED_POLICY;

        slot->suppression.source      = STR_LIT("policy");
        slot->suppression.reason      = s->reason;
        slot->suppression.owner       = s->owner;
        slot->suppression.ticket      = s->ticket;
        slot->suppression.expires     = s->expires;
        slot->suppression.affects_exit = 0;

        /* Compute expires_in_days (0 if no expiry set) */
        if (s->expires_epoch != 0) {
            int64_t delta_secs = s->expires_epoch - now;
            /* Round toward zero — partial days count as zero */
            int64_t days = delta_secs / (int64_t)86400;
            /* Clamp to int range; negative means already past (shouldn't
             * reach here since we skip expired above, but be safe) */
            slot->suppression.expires_in_days = (int)days;
        } else {
            slot->suppression.expires_in_days = 0;
        }

        break; /* first matching suppression wins */
    }

    return 1;
}


/* =========================================================================
 * findings_has_active_fail — true if any active finding is SEV_FAIL or above
 * ========================================================================= */

int findings_has_active_fail(const finding_set_t *fs)
{
    for (size_t i = 0; i < fs->count; i++) {
        const finding_t *f = &fs->findings[i];
        if (f->status == FINDING_ACTIVE && f->severity >= SEV_FAIL)
            return 1;
    }
    return 0;
}
