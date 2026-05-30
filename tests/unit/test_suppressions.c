/*
 * tests/unit/test_suppressions.c
 *
 * Unit tests for suppression logic (findings_add() suppression path).
 *
 * Covers:
 *   - Policy suppression: active matching suppression silences a finding
 *   - Policy suppression: expired suppression does NOT silence
 *   - Policy suppression: non-suppressible findings ignore suppression
 *   - CLI suppression: tl_cli_suppress_active() matching
 *   - CLI suppression: comma-separated IDs
 *   - TL-S020/TL-S021/TL-S022/TL-S023/TL-S024 (structural suppression findings)
 *     are verified via the policy_parser; here we test findings_add() directly.
 *
 * Uses ALLOWSET_ADD from alg.h; no parsers involved.
 */

#define _POSIX_C_SOURCE 200809L

#include "helpers/test_runner.h"
#include "helpers/policy_builder.h"

#include "tokenlint.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"
#include "cli.h"

#include <string.h>
#include <stdint.h>
#include <time.h>


/* =========================================================================
 * Helpers
 * ========================================================================= */

static int has_active(const finding_set_t *fs, const char *id_cstr)
{
    str_t id = str_from_cstr(id_cstr);
    for (size_t i = 0; i < fs->count; i++) {
        if (str_eq(fs->findings[i].id, id) &&
            fs->findings[i].status == FINDING_ACTIVE)
            return 1;
    }
    return 0;
}

static int has_suppressed_policy(const finding_set_t *fs, const char *id_cstr)
{
    str_t id = str_from_cstr(id_cstr);
    for (size_t i = 0; i < fs->count; i++) {
        if (str_eq(fs->findings[i].id, id) &&
            fs->findings[i].status == FINDING_SUPPRESSED_POLICY)
            return 1;
    }
    return 0;
}

static finding_t make_finding(const char *id, severity_t sev)
{
    finding_t f;
    memset(&f, 0, sizeof(f));
    f.id       = str_from_cstr(id);
    f.title    = STR_LIT("TEST_FINDING");
    f.detail   = STR_LIT("test detail");
    f.severity = sev;
    f.status   = FINDING_ACTIVE;
    return f;
}


/* =========================================================================
 * TEST: policy suppression — matching suppression marks finding suppressed
 * ========================================================================= */

TEST(suppression_policy_match)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    /* Build a suppressible finding */
    finding_t f = make_finding("TL-A007", SEV_WARN);

    /* Suppression entry that matches */
    suppression_t supp;
    memset(&supp, 0, sizeof(supp));
    supp.finding_id    = STR_LIT("TL-A007");
    supp.reason        = STR_LIT("approved for 6-month migration window");
    supp.owner         = STR_LIT("platform-security");
    supp.expires       = STR_NULL;
    supp.expires_epoch = 0;  /* no expiry */

    int r = findings_add(&fs, &f, arena, &supp, 1);
    ASSERT_TRUE(r);
    ASSERT_EQ(fs.count, (size_t)1);
    ASSERT_TRUE(has_suppressed_policy(&fs, "TL-A007"));
    ASSERT_FALSE(has_active(&fs, "TL-A007"));

    /* suppression sub-struct populated */
    ASSERT_TRUE(str_eq(fs.findings[0].suppression.source, STR_LIT("policy")));

    arena_free(arena);
}


/* =========================================================================
 * TEST: policy suppression — non-matching suppression leaves finding active
 * ========================================================================= */

TEST(suppression_policy_no_match)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    finding_t f = make_finding("TL-A007", SEV_WARN);

    suppression_t supp;
    memset(&supp, 0, sizeof(supp));
    supp.finding_id    = STR_LIT("TL-A002");  /* different ID */
    supp.reason        = STR_LIT("wrong finding");
    supp.owner         = STR_LIT("owner");
    supp.expires_epoch = 0;

    int r = findings_add(&fs, &f, arena, &supp, 1);
    ASSERT_TRUE(r);
    ASSERT_TRUE(has_active(&fs, "TL-A007"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: policy suppression — expired suppression does NOT silence finding
 * ========================================================================= */

TEST(suppression_policy_expired)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    finding_t f = make_finding("TL-A007", SEV_WARN);

    /* Expiry in the past */
    suppression_t supp;
    memset(&supp, 0, sizeof(supp));
    supp.finding_id    = STR_LIT("TL-A007");
    supp.reason        = STR_LIT("expired suppression");
    supp.owner         = STR_LIT("owner");
    supp.expires       = STR_LIT("2020-01-01");
    supp.expires_epoch = 1577836800;  /* 2020-01-01 UTC — well in the past */

    int r = findings_add(&fs, &f, arena, &supp, 1);
    ASSERT_TRUE(r);
    /* Finding must remain ACTIVE because suppression is expired */
    ASSERT_TRUE(has_active(&fs, "TL-A007"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: non-suppressible TL-S findings ignore policy suppressions
 * ========================================================================= */

TEST(suppression_nonsuppressible_schema_finding)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    /* TL-S001 is always non-suppressible */
    finding_t f = make_finding("TL-S001", SEV_CRITICAL);

    suppression_t supp;
    memset(&supp, 0, sizeof(supp));
    supp.finding_id    = STR_LIT("TL-S001");
    supp.reason        = STR_LIT("attempted suppression");
    supp.owner         = STR_LIT("attacker");
    supp.expires_epoch = 0;

    int r = findings_add(&fs, &f, arena, &supp, 1);
    ASSERT_TRUE(r);
    /* Must still be ACTIVE despite suppression entry */
    ASSERT_TRUE(has_active(&fs, "TL-S001"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: non-suppressible TL-V findings (TL-V006, TL-V022)
 * ========================================================================= */

TEST(suppression_nonsuppressible_v006)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    finding_t f = make_finding("TL-V006", SEV_CRITICAL);

    suppression_t supp;
    memset(&supp, 0, sizeof(supp));
    supp.finding_id    = STR_LIT("TL-V006");
    supp.reason        = STR_LIT("bad actor attempt");
    supp.owner         = STR_LIT("nobody");
    supp.expires_epoch = 0;

    int r = findings_add(&fs, &f, arena, &supp, 1);
    ASSERT_TRUE(r);
    ASSERT_TRUE(has_active(&fs, "TL-V006"));

    arena_free(arena);
}

TEST(suppression_nonsuppressible_v022)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    finding_t f = make_finding("TL-V022", SEV_CRITICAL);

    suppression_t supp;
    memset(&supp, 0, sizeof(supp));
    supp.finding_id    = STR_LIT("TL-V022");
    supp.reason        = STR_LIT("attempt");
    supp.owner         = STR_LIT("owner");
    supp.expires_epoch = 0;

    int r = findings_add(&fs, &f, arena, &supp, 1);
    ASSERT_TRUE(r);
    ASSERT_TRUE(has_active(&fs, "TL-V022"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: multiple suppressions — first matching one applies
 * ========================================================================= */

TEST(suppression_multiple_entries_first_match)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    finding_t f = make_finding("TL-A007", SEV_WARN);

    suppression_t supps[3];
    memset(supps, 0, sizeof(supps));
    supps[0].finding_id    = STR_LIT("TL-A002");
    supps[0].reason        = STR_LIT("no match");
    supps[0].owner         = STR_LIT("owner");

    supps[1].finding_id    = STR_LIT("TL-A007");
    supps[1].reason        = STR_LIT("correct match");
    supps[1].owner         = STR_LIT("platform");
    supps[1].expires_epoch = 0;

    supps[2].finding_id    = STR_LIT("TL-A007");
    supps[2].reason        = STR_LIT("second match — should not override first");
    supps[2].owner         = STR_LIT("other");

    int r = findings_add(&fs, &f, arena, supps, 3);
    ASSERT_TRUE(r);
    ASSERT_TRUE(has_suppressed_policy(&fs, "TL-A007"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: findings overflow — 257th finding is dropped, overflowed is set
 * ========================================================================= */

TEST(suppression_overflow_flag)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    finding_t f = make_finding("TL-A007", SEV_WARN);

    /* Fill to capacity */
    for (int i = 0; i < TL_MAX_FINDINGS; i++) {
        int _r = findings_add(&fs, &f, arena, NULL, 0);
        TL_UNUSED(_r);
    }
    ASSERT_EQ(fs.count, (size_t)TL_MAX_FINDINGS);
    ASSERT_FALSE(fs.overflowed);

    /* One more — should trigger overflow */
    int r = findings_add(&fs, &f, arena, NULL, 0);
    ASSERT_FALSE(r);  /* returns 0 on overflow */
    ASSERT_EQ(fs.count, (size_t)TL_MAX_FINDINGS);
    ASSERT_TRUE(fs.overflowed);

    arena_free(arena);
}


/* =========================================================================
 * TEST: CLI suppress — tl_cli_suppress_active() single ID
 * ========================================================================= */

TEST(suppression_cli_single_id)
{
    tl_cli_opts_t opts;
    tl_cli_opts_init(&opts);

    static const char *ids[1] = { "TL-A007" };
    opts.suppress_ids   = ids;
    opts.suppress_count = 1;

    ASSERT_TRUE(tl_cli_suppress_active(&opts, "TL-A007"));
    ASSERT_FALSE(tl_cli_suppress_active(&opts, "TL-A002"));
    ASSERT_FALSE(tl_cli_suppress_active(&opts, "TL-V006"));
}


/* =========================================================================
 * TEST: CLI suppress — comma-separated IDs in a single --suppress value
 * ========================================================================= */

TEST(suppression_cli_comma_separated)
{
    tl_cli_opts_t opts;
    tl_cli_opts_init(&opts);

    /* A single argv entry containing multiple comma-separated IDs */
    static const char *ids[1] = { "TL-A007,TL-A002,TL-V003" };
    opts.suppress_ids   = ids;
    opts.suppress_count = 1;

    ASSERT_TRUE(tl_cli_suppress_active(&opts, "TL-A007"));
    ASSERT_TRUE(tl_cli_suppress_active(&opts, "TL-A002"));
    ASSERT_TRUE(tl_cli_suppress_active(&opts, "TL-V003"));
    ASSERT_FALSE(tl_cli_suppress_active(&opts, "TL-V006"));
}


/* =========================================================================
 * TEST: CLI suppress — multiple argv entries
 * ========================================================================= */

TEST(suppression_cli_multiple_argv_entries)
{
    tl_cli_opts_t opts;
    tl_cli_opts_init(&opts);

    static const char *ids[2] = { "TL-A007", "TL-V003" };
    opts.suppress_ids   = ids;
    opts.suppress_count = 2;

    ASSERT_TRUE(tl_cli_suppress_active(&opts, "TL-A007"));
    ASSERT_TRUE(tl_cli_suppress_active(&opts, "TL-V003"));
    ASSERT_FALSE(tl_cli_suppress_active(&opts, "TL-V022"));
}


/* =========================================================================
 * TEST: CLI suppress — empty suppress list matches nothing
 * ========================================================================= */

TEST(suppression_cli_empty_list)
{
    tl_cli_opts_t opts;
    tl_cli_opts_init(&opts);

    opts.suppress_ids   = NULL;
    opts.suppress_count = 0;

    ASSERT_FALSE(tl_cli_suppress_active(&opts, "TL-A007"));
    ASSERT_FALSE(tl_cli_suppress_active(&opts, "TL-S001"));
}


/* =========================================================================
 * TEST: future-dated suppression (non-expired) silences finding
 * ========================================================================= */

TEST(suppression_policy_future_expiry)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    finding_t f = make_finding("TL-A007", SEV_WARN);

    /* Expiry far in the future */
    suppression_t supp;
    memset(&supp, 0, sizeof(supp));
    supp.finding_id    = STR_LIT("TL-A007");
    supp.reason        = STR_LIT("future suppression");
    supp.owner         = STR_LIT("owner");
    supp.expires       = STR_LIT("2099-12-31");
    supp.expires_epoch = 4102444800LL;  /* 2100-01-01 approximate */

    int r = findings_add(&fs, &f, arena, &supp, 1);
    ASSERT_TRUE(r);
    ASSERT_TRUE(has_suppressed_policy(&fs, "TL-A007"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: TL-I001 (AT_FLAG_INVALID) is non-suppressible
 * ========================================================================= */

TEST(suppression_nonsuppressible_i001)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    finding_t f = make_finding("TL-I001", SEV_CRITICAL);

    suppression_t supp;
    memset(&supp, 0, sizeof(supp));
    supp.finding_id    = STR_LIT("TL-I001");
    supp.reason        = STR_LIT("attempt");
    supp.owner         = STR_LIT("owner");
    supp.expires_epoch = 0;

    int r = findings_add(&fs, &f, arena, &supp, 1);
    ASSERT_TRUE(r);
    ASSERT_TRUE(has_active(&fs, "TL-I001"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: findings_has_active_fail — correct detection
 * ========================================================================= */

TEST(suppression_has_active_fail)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    ASSERT_FALSE(findings_has_active_fail(&fs));

    /* Add a WARN — not a fail */
    finding_t fw = make_finding("TL-A007", SEV_WARN);
    int _r = findings_add(&fs, &fw, arena, NULL, 0);
    TL_UNUSED(_r);
    ASSERT_FALSE(findings_has_active_fail(&fs));

    /* Add a FAIL */
    finding_t ff = make_finding("TL-V003", SEV_FAIL);
    _r = findings_add(&fs, &ff, arena, NULL, 0);
    TL_UNUSED(_r);
    ASSERT_TRUE(findings_has_active_fail(&fs));

    arena_free(arena);
}


/* =========================================================================
 * TEST: suppressed finding does not count as active fail
 * ========================================================================= */

TEST(suppression_suppressed_not_active_fail)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    finding_t f = make_finding("TL-V003", SEV_FAIL);

    suppression_t supp;
    memset(&supp, 0, sizeof(supp));
    supp.finding_id    = STR_LIT("TL-V003");
    supp.reason        = STR_LIT("known issue");
    supp.owner         = STR_LIT("security");
    supp.expires_epoch = 0;

    int _r = findings_add(&fs, &f, arena, &supp, 1);
    TL_UNUSED(_r);

    /* TL-V003 is suppressible; it should be suppressed */
    ASSERT_TRUE(has_suppressed_policy(&fs, "TL-V003"));
    /* And therefore not counted as an active fail */
    ASSERT_FALSE(findings_has_active_fail(&fs));

    arena_free(arena);
}


/* =========================================================================
 * TEST_MAIN
 * ========================================================================= */

TEST_MAIN(
    tl_run_suppression_policy_match,
    tl_run_suppression_policy_no_match,
    tl_run_suppression_policy_expired,
    tl_run_suppression_nonsuppressible_schema_finding,
    tl_run_suppression_nonsuppressible_v006,
    tl_run_suppression_nonsuppressible_v022,
    tl_run_suppression_multiple_entries_first_match,
    tl_run_suppression_overflow_flag,
    tl_run_suppression_cli_single_id,
    tl_run_suppression_cli_comma_separated,
    tl_run_suppression_cli_multiple_argv_entries,
    tl_run_suppression_cli_empty_list,
    tl_run_suppression_policy_future_expiry,
    tl_run_suppression_nonsuppressible_i001,
    tl_run_suppression_has_active_fail,
    tl_run_suppression_suppressed_not_active_fail,
)
