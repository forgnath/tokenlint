/*
 * tests/unit/test_findings.c
 *
 * Unit tests for src/eval/findings.c
 *
 * Covers:
 *   - findings_init zeroes the set
 *   - findings_add returns 1 on success
 *   - findings_add returns 0 and sets overflowed on overflow
 *   - findings_has_active_fail with no findings
 *   - findings_has_active_fail with only warns
 *   - findings_has_active_fail with a FAIL
 *   - findings_has_active_fail with suppressed FAIL
 *   - Suppression of a suppressible finding
 *   - Non-suppressible TL-S prefix findings cannot be suppressed
 *   - Non-suppressible specific findings (TL-V006, TL-V022, etc.)
 *   - Expired suppression is ignored (finding stays ACTIVE)
 *   - expires_in_days is populated for live suppression with expiry
 *   - Suppression with no expiry sets expires_in_days = 0
 *   - First matching suppression wins (multiple entries)
 *   - Suppression fields (source, reason, owner, ticket) are copied
 *   - NULL suppression list is safe (count == 0)
 *   - count increments correctly across multiple adds
 *
 * Build (from repo root):
 *   gcc -std=c11 -Wall -Wextra -Wpedantic -Werror \
 *       -I include -I tests \
 *       src/util/arena.c src/eval/findings.c \
 *       tests/unit/test_findings.c \
 *       -o build/test/test_findings
 *   ./build/test/test_findings
 */

#include "helpers/test_runner.h"
#include "tokenlint.h"
#include "findings.h"

#include <stdint.h>
#include <time.h>
#include <string.h>


/* ── helpers ────────────────────────────────────────────────────────────── */

/* Build a minimal finding_t with given id and severity. */
static finding_t make_finding(const char *id_lit, severity_t sev)
{
    finding_t f;
    memset(&f, 0, sizeof f);
    f.id       = str_from_cstr(id_lit);
    f.title    = STR_LIT("test-title");
    f.detail   = STR_LIT("test-detail");
    f.severity = sev;
    f.status   = FINDING_ACTIVE;
    return f;
}

/* Build a suppression_t for a given finding id (no expiry). */
static suppression_t make_suppression(const char *id_lit)
{
    suppression_t s;
    memset(&s, 0, sizeof s);
    s.finding_id   = str_from_cstr(id_lit);
    s.reason       = STR_LIT("test reason");
    s.owner        = STR_LIT("test-team");
    s.ticket       = STR_NULL;
    s.expires      = STR_NULL;
    s.expires_epoch = 0;
    return s;
}

/* Build a suppression_t with a specific expires_epoch. */
static suppression_t make_suppression_expires(const char *id_lit,
                                               int64_t expires_epoch)
{
    suppression_t s = make_suppression(id_lit);
    s.expires_epoch = expires_epoch;
    s.expires       = STR_LIT("2099-01-01"); /* placeholder date string */
    return s;
}

/* Shared arena for all tests (small — findings.c doesn't use it yet). */
static arena_t *g_arena = NULL;

static void setup_arena(void)
{
    if (!g_arena)
        g_arena = arena_new(TL_KB(64));
}


/* ── tests ──────────────────────────────────────────────────────────────── */

TEST(init_zeroes_set)
{
    finding_set_t fs;
    /* Dirty the memory first */
    memset(&fs, 0xFF, sizeof fs);
    findings_init(&fs);
    ASSERT_EQ(fs.count, 0);
    ASSERT_EQ(fs.overflowed, 0);
}

TEST(add_returns_one_on_success)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t f = make_finding("TL-A007", SEV_FAIL);
    int r = findings_add(&fs, &f, g_arena, NULL, 0);
    ASSERT_EQ(r, 1);
    ASSERT_EQ((int)fs.count, 1);
}

TEST(add_increments_count)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t f1 = make_finding("TL-A007", SEV_FAIL);
    finding_t f2 = make_finding("TL-A002", SEV_CRITICAL);
    finding_t f3 = make_finding("TL-V023", SEV_FAIL);
    { int _r = findings_add(&fs, &f1, g_arena, NULL, 0); TL_UNUSED(_r); }
    { int _r = findings_add(&fs, &f2, g_arena, NULL, 0); TL_UNUSED(_r); }
    { int _r = findings_add(&fs, &f3, g_arena, NULL, 0); TL_UNUSED(_r); }
    ASSERT_EQ((int)fs.count, 3);
}

TEST(add_overflow_sets_flag_returns_zero)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);

    finding_t f = make_finding("TL-A007", SEV_FAIL);

    /* Fill to capacity */
    for (int i = 0; i < TL_MAX_FINDINGS; i++) {
        int r = findings_add(&fs, &f, g_arena, NULL, 0);
        ASSERT_EQ(r, 1);
    }
    ASSERT_EQ((int)fs.count, TL_MAX_FINDINGS);
    ASSERT_EQ(fs.overflowed, 0);

    /* One more — should overflow */
    int r = findings_add(&fs, &f, g_arena, NULL, 0);
    ASSERT_EQ(r, 0);
    ASSERT_EQ(fs.overflowed, 1);
    ASSERT_EQ((int)fs.count, TL_MAX_FINDINGS); /* count not incremented */
}

TEST(has_active_fail_empty_set)
{
    finding_set_t fs;
    findings_init(&fs);
    ASSERT_EQ(findings_has_active_fail(&fs), 0);
}

TEST(has_active_fail_only_warns)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t f = make_finding("TL-A007", SEV_WARN);
    { int _r = findings_add(&fs, &f, g_arena, NULL, 0); TL_UNUSED(_r); }
    ASSERT_EQ(findings_has_active_fail(&fs), 0);
}

TEST(has_active_fail_with_fail_severity)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t f = make_finding("TL-A007", SEV_FAIL);
    { int _r = findings_add(&fs, &f, g_arena, NULL, 0); TL_UNUSED(_r); }
    ASSERT_EQ(findings_has_active_fail(&fs), 1);
}

TEST(has_active_fail_with_critical_severity)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t f = make_finding("TL-A002", SEV_CRITICAL);
    { int _r = findings_add(&fs, &f, g_arena, NULL, 0); TL_UNUSED(_r); }
    ASSERT_EQ(findings_has_active_fail(&fs), 1);
}

TEST(has_active_fail_suppressed_fail_not_counted)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t    f = make_finding("TL-A007", SEV_FAIL);
    suppression_t s = make_suppression("TL-A007");
    { int _r = findings_add(&fs, &f, g_arena, &s, 1); TL_UNUSED(_r); }
    /* suppressed → should NOT count as active fail */
    ASSERT_EQ(findings_has_active_fail(&fs), 0);
    ASSERT_EQ(fs.findings[0].status, FINDING_SUPPRESSED_POLICY);
}

TEST(suppression_status_set_on_match)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t    f = make_finding("TL-A007", SEV_FAIL);
    suppression_t s = make_suppression("TL-A007");
    { int _r = findings_add(&fs, &f, g_arena, &s, 1); TL_UNUSED(_r); }
    ASSERT_EQ(fs.findings[0].status, FINDING_SUPPRESSED_POLICY);
}

TEST(suppression_no_match_stays_active)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t    f = make_finding("TL-A007", SEV_FAIL);
    suppression_t s = make_suppression("TL-A002"); /* different id */
    { int _r = findings_add(&fs, &f, g_arena, &s, 1); TL_UNUSED(_r); }
    ASSERT_EQ(fs.findings[0].status, FINDING_ACTIVE);
}

TEST(suppression_fields_copied)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t    f = make_finding("TL-A007", SEV_FAIL);
    suppression_t s = make_suppression("TL-A007");
    s.ticket = STR_LIT("SEC-9999");
    { int _r = findings_add(&fs, &f, g_arena, &s, 1); TL_UNUSED(_r); }

    const finding_t *slot = &fs.findings[0];
    ASSERT_TRUE(str_eq(slot->suppression.source, STR_LIT("policy")));
    ASSERT_TRUE(str_eq(slot->suppression.reason, STR_LIT("test reason")));
    ASSERT_TRUE(str_eq(slot->suppression.owner,  STR_LIT("test-team")));
    ASSERT_TRUE(str_eq(slot->suppression.ticket, STR_LIT("SEC-9999")));
    ASSERT_EQ(slot->suppression.affects_exit, 0);
}

TEST(suppression_null_list_safe)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t f = make_finding("TL-A007", SEV_FAIL);
    int r = findings_add(&fs, &f, g_arena, NULL, 0);
    ASSERT_EQ(r, 1);
    ASSERT_EQ(fs.findings[0].status, FINDING_ACTIVE);
}

TEST(suppression_expired_ignored)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t f = make_finding("TL-A007", SEV_FAIL);

    /* expires_epoch in the past */
    suppression_t s = make_suppression_expires("TL-A007", (int64_t)1000);
    { int _r = findings_add(&fs, &f, g_arena, &s, 1); TL_UNUSED(_r); }

    /* Expired → finding should still be ACTIVE */
    ASSERT_EQ(fs.findings[0].status, FINDING_ACTIVE);
}

TEST(suppression_future_expiry_applied)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t f = make_finding("TL-A007", SEV_FAIL);

    /* expires_epoch far in the future */
    int64_t future = (int64_t)time(NULL) + (int64_t)86400 * 365;
    suppression_t s = make_suppression_expires("TL-A007", future);
    { int _r = findings_add(&fs, &f, g_arena, &s, 1); TL_UNUSED(_r); }

    ASSERT_EQ(fs.findings[0].status, FINDING_SUPPRESSED_POLICY);
    ASSERT_GT(fs.findings[0].suppression.expires_in_days, 0);
}

TEST(suppression_no_expiry_expires_in_days_zero)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t    f = make_finding("TL-A007", SEV_FAIL);
    suppression_t s = make_suppression("TL-A007"); /* no expiry */
    { int _r = findings_add(&fs, &f, g_arena, &s, 1); TL_UNUSED(_r); }
    ASSERT_EQ(fs.findings[0].suppression.expires_in_days, 0);
}

TEST(suppression_first_match_wins)
{
    setup_arena();
    finding_set_t fs;
    findings_init(&fs);
    finding_t f = make_finding("TL-A007", SEV_FAIL);

    suppression_t list[2];
    list[0] = make_suppression("TL-A007");
    list[0].reason = STR_LIT("first reason");
    list[1] = make_suppression("TL-A007");
    list[1].reason = STR_LIT("second reason");

    { int _r = findings_add(&fs, &f, g_arena, list, 2); TL_UNUSED(_r); }

    ASSERT_EQ(fs.findings[0].status, FINDING_SUPPRESSED_POLICY);
    ASSERT_TRUE(str_eq(fs.findings[0].suppression.reason,
                       STR_LIT("first reason")));
}

/* ── Security properties: non-suppressible findings ────────────────────── */

SECURITY_PROP(tl_s_prefix_nonsuppressible)
{
    /* Every TL-S finding must ignore suppression entries */
    setup_arena();

    static const char * const s_ids[] = {
        "TL-S001", "TL-S002", "TL-S003", "TL-S004", "TL-S005",
        "TL-S006", "TL-S007", "TL-S008", "TL-S009", "TL-S010",
        "TL-S011", "TL-S012", "TL-S013", "TL-S014", "TL-S015",
        "TL-S020", "TL-S021", "TL-S022", "TL-S023", "TL-S024",
        NULL
    };

    for (size_t i = 0; s_ids[i] != NULL; i++) {
        finding_set_t fs;
        findings_init(&fs);

        finding_t    f = make_finding(s_ids[i], SEV_FAIL);
        suppression_t s = make_suppression(s_ids[i]);
        int64_t future = (int64_t)time(NULL) + (int64_t)86400 * 365;
        s.expires_epoch = future;

        { int _r = findings_add(&fs, &f, g_arena, &s, 1); TL_UNUSED(_r); }

        if (fs.findings[0].status != FINDING_ACTIVE) {
            /* Print which one failed */
            fprintf(stderr, "  non-suppressible %s was suppressed!\n",
                    s_ids[i]);
            ASSERT_EQ(fs.findings[0].status, FINDING_ACTIVE);
        }
    }
}

SECURITY_PROP(tl_v_nonsuppressible_set)
{
    /* TL-V000, TL-V001, TL-V002, TL-V006, TL-V022, TL-V024 must not suppress */
    setup_arena();

    static const char * const ns[] = {
        "TL-V000", "TL-V001", "TL-V002",
        "TL-V006", "TL-V022", "TL-V024",
        "TL-I001",
        NULL
    };

    for (size_t i = 0; ns[i] != NULL; i++) {
        finding_set_t fs;
        findings_init(&fs);

        finding_t    f = make_finding(ns[i], SEV_FAIL);
        suppression_t s = make_suppression(ns[i]);
        int64_t future = (int64_t)time(NULL) + (int64_t)86400 * 365;
        s.expires_epoch = future;

        { int _r = findings_add(&fs, &f, g_arena, &s, 1); TL_UNUSED(_r); }

        if (fs.findings[0].status != FINDING_ACTIVE) {
            fprintf(stderr, "  non-suppressible %s was suppressed!\n", ns[i]);
            ASSERT_EQ(fs.findings[0].status, FINDING_ACTIVE);
        }
    }
}

SECURITY_PROP(suppressible_tl_v_findings_can_be_suppressed)
{
    /*
     * Verify the inverse: suppressible TL-V findings DO get suppressed
     * when a valid suppression entry is present.
     */
    setup_arena();

    static const char * const suppressible[] = {
        "TL-V003", "TL-V004", "TL-V005",
        "TL-V009", "TL-V010", "TL-V011", "TL-V012",
        "TL-V020", "TL-V021", "TL-V023", "TL-V025",
        NULL
    };

    for (size_t i = 0; suppressible[i] != NULL; i++) {
        finding_set_t fs;
        findings_init(&fs);

        finding_t    f = make_finding(suppressible[i], SEV_FAIL);
        suppression_t s = make_suppression(suppressible[i]);

        { int _r = findings_add(&fs, &f, g_arena, &s, 1); TL_UNUSED(_r); }

        if (fs.findings[0].status != FINDING_SUPPRESSED_POLICY) {
            fprintf(stderr, "  suppressible %s was NOT suppressed!\n",
                    suppressible[i]);
            ASSERT_EQ(fs.findings[0].status, FINDING_SUPPRESSED_POLICY);
        }
    }
}

/* ── TEST_MAIN ──────────────────────────────────────────────────────────── */

TEST_MAIN(
    tl_run_init_zeroes_set,
    tl_run_add_returns_one_on_success,
    tl_run_add_increments_count,
    tl_run_add_overflow_sets_flag_returns_zero,
    tl_run_has_active_fail_empty_set,
    tl_run_has_active_fail_only_warns,
    tl_run_has_active_fail_with_fail_severity,
    tl_run_has_active_fail_with_critical_severity,
    tl_run_has_active_fail_suppressed_fail_not_counted,
    tl_run_suppression_status_set_on_match,
    tl_run_suppression_no_match_stays_active,
    tl_run_suppression_fields_copied,
    tl_run_suppression_null_list_safe,
    tl_run_suppression_expired_ignored,
    tl_run_suppression_future_expiry_applied,
    tl_run_suppression_no_expiry_expires_in_days_zero,
    tl_run_suppression_first_match_wins,
    tl_run_tl_s_prefix_nonsuppressible,
    tl_run_tl_v_nonsuppressible_set,
    tl_run_suppressible_tl_v_findings_can_be_suppressed,
)
