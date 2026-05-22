/*
 * src/eval/findings.c
 *
 * findings_add(), findings_init(), findings_has_active_fail().
 * See finding-registry.md for the full finding list.
 *
 * Suppression check:
 *   For each new finding, scan the suppression_list for a matching
 *   finding_id.  If found and the suppression is not expired, mark the
 *   finding FINDING_SUPPRESSED_POLICY.
 *
 * Overflow:
 *   If count == TL_MAX_FINDINGS, set overflowed = 1 and return 0.
 *   The first 256 findings are always preserved.
 */

#include "tokenlint.h"
#include "findings.h"

#include <string.h>
#include <stdint.h>

_Static_assert(TL_MAX_FINDINGS <= 256,
    "finding capacity exceeds intended maximum");

/* ── findings_init ──────────────────────────────────────────────────────── */

void findings_init(finding_set_t *fs)
{
    memset(fs, 0, sizeof *fs);
}

/* ── findings_add ───────────────────────────────────────────────────────── */

int findings_add(finding_set_t       *fs,
                 const finding_t     *f,
                 arena_t             *arena,
                 const suppression_t *suppression_list,
                 size_t               suppression_count)
{
    TL_UNUSED(arena); /* reserved for future detail string interning */

    if (fs->count >= TL_MAX_FINDINGS) {
        fs->overflowed = 1;
        return 0;
    }

    finding_t *slot = &fs->findings[fs->count++];
    *slot = *f;

    /* Default: active */
    slot->status = FINDING_ACTIVE;

    /* Check suppressions */
    for (size_t i = 0; i < suppression_count; i++) {
        const suppression_t *s = &suppression_list[i];
        if (!str_eq(s->finding_id, f->id)) continue;

        /* Matched — mark suppressed */
        slot->status = FINDING_SUPPRESSED_POLICY;
        slot->suppression.source  = STR_LIT("policy");
        slot->suppression.reason  = s->reason;
        slot->suppression.owner   = s->owner;
        slot->suppression.ticket  = s->ticket;
        slot->suppression.expires = s->expires;
        slot->suppression.affects_exit = 0;
        break;
    }

    return 1;
}

/* ── findings_has_active_fail ───────────────────────────────────────────── */

int findings_has_active_fail(const finding_set_t *fs)
{
    for (size_t i = 0; i < fs->count; i++) {
        const finding_t *f = &fs->findings[i];
        if (f->status == FINDING_ACTIVE && f->severity >= SEV_FAIL)
            return 1;
    }
    return 0;
}
