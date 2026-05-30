/*
 * tests/integration/test_audit_pass.c
 *
 * Integration tests: audit mode, passing scenarios.
 *
 * Exercises the full audit pipeline:
 *   policy_parse() → eval_audit() → findings
 *
 * All fixture paths are relative to the repo root; the test binary must be
 * invoked from the repo root (or the Makefile sets the working directory).
 */

#define _POSIX_C_SOURCE 200809L

#include "helpers/test_runner.h"
#include "helpers/policy_builder.h"

#include "tokenlint.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"
#include "eval_ctx.h"

#include <string.h>
#include <stddef.h>


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

static int any_active_fail(const finding_set_t *fs)
{
    return findings_has_active_fail(fs);
}

/* Run policy_parse + eval_audit; return 0 on TL_OK, 1 on error */
static int run_audit_fixture(const char    *policy_path,
                              finding_set_t *fs,
                              arena_t       *arena)
{
    policy_t *policy = NULL;
    tl_error_t err = policy_parse(arena, policy_path, fs, &policy);
    if (!tl_ok(err)) return 1;

    eval_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.policy         = policy;
    ctx.findings       = fs;
    ctx.arena          = arena;
    ctx.reference_time = 1700000000;

    eval_audit(&ctx);
    return 0;
}


/* =========================================================================
 * TEST: minimal valid policy — no TL-A findings
 *
 * tests/fixtures/policies/valid/minimal.yaml uses RS256, https issuer,
 * bounded TTL, requires iss/sub/aud/exp/iat.
 * ========================================================================= */

TEST(audit_pass_minimal_policy)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    int rc = run_audit_fixture("tests/fixtures/policies/valid/minimal.yaml",
                               &fs, arena);
    ASSERT_EQ(rc, 0);

    /* No active fail/critical findings */
    ASSERT_FALSE(any_active_fail(&fs));

    /* Specific TL-A findings must not be present */
    ASSERT_FALSE(has_active(&fs, "TL-A002"));
    ASSERT_FALSE(has_active(&fs, "TL-A003"));
    ASSERT_FALSE(has_active(&fs, "TL-A004"));
    ASSERT_FALSE(has_active(&fs, "TL-A005"));
    ASSERT_FALSE(has_active(&fs, "TL-A007"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: builder-constructed good policy — no TL-A findings
 * ========================================================================= */

TEST(audit_pass_builder_prod_policy)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "payments-api");
    policy_builder_algorithm(&pb, ALG_RS256);
    policy_builder_require_claims(&pb, CLAIM_EXP | CLAIM_ISS | CLAIM_AUD);
    policy_builder_max_ttl(&pb, 3600);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    eval_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.policy         = policy;
    ctx.findings       = &fs;
    ctx.arena          = arena;
    ctx.reference_time = 1700000000;

    eval_audit(&ctx);

    ASSERT_FALSE(any_active_fail(&fs));
    ASSERT_FALSE(has_active(&fs, "TL-A002"));
    ASSERT_FALSE(has_active(&fs, "TL-A003"));
    ASSERT_FALSE(has_active(&fs, "TL-A004"));
    ASSERT_FALSE(has_active(&fs, "TL-A005"));
    ASSERT_FALSE(has_active(&fs, "TL-A007"));
    ASSERT_FALSE(has_active(&fs, "TL-A014"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: full fixture (stage env, multiple issuers) — no TL-A fails in stage
 * ========================================================================= */

TEST(audit_pass_full_stage_policy)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    int rc = run_audit_fixture("tests/fixtures/policies/valid/full.yaml",
                               &fs, arena);
    ASSERT_EQ(rc, 0);

    /* full.yaml is stage + RS256/PS256/ES256 — HS256 is absent, so no TL-A005 */
    ASSERT_FALSE(has_active(&fs, "TL-S002"));
    ASSERT_FALSE(has_active(&fs, "TL-A005"));
    ASSERT_FALSE(any_active_fail(&fs));

    arena_free(arena);
}


/* =========================================================================
 * TEST: dev env policy with HS256 — TL-A005 fires as WARN not FAIL
 *
 * In dev/test environments, symmetric algorithms emit WARN, not FAIL.
 * This means it is still an active finding but at severity WARN,
 * so it should not count as an active fail.
 * ========================================================================= */

TEST(audit_pass_dev_hs256_no_fail)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    int rc = run_audit_fixture("tests/fixtures/policies/valid/dev.yaml",
                               &fs, arena);
    ASSERT_EQ(rc, 0);

    /* In dev env, TL-A005 may fire but as WARN — not a fail */
    ASSERT_FALSE(any_active_fail(&fs));

    arena_free(arena);
}


/* =========================================================================
 * TEST: policy_parse returns TL_OK for all valid fixtures
 * ========================================================================= */

TEST(audit_pass_all_valid_fixtures_parse_ok)
{
    static const char *valid_fixtures[] = {
        "tests/fixtures/policies/valid/minimal.yaml",
        "tests/fixtures/policies/valid/full.yaml",
        "tests/fixtures/policies/valid/dev.yaml",
    };
    size_t n = sizeof(valid_fixtures) / sizeof(valid_fixtures[0]);

    for (size_t i = 0; i < n; i++) {
        arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
        ASSERT_NOT_NULL(arena);

        finding_set_t fs;
        findings_init(&fs);

        policy_t *policy = NULL;
        tl_error_t err = policy_parse(arena, valid_fixtures[i], &fs, &policy);
        ASSERT_TRUE(tl_ok(err));
        ASSERT_NOT_NULL(policy);

        arena_free(arena);
    }
}


/* =========================================================================
 * TEST_MAIN
 * ========================================================================= */

TEST_MAIN(
    tl_run_audit_pass_minimal_policy,
    tl_run_audit_pass_builder_prod_policy,
    tl_run_audit_pass_full_stage_policy,
    tl_run_audit_pass_dev_hs256_no_fail,
    tl_run_audit_pass_all_valid_fixtures_parse_ok,
)
