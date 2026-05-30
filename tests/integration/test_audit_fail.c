/*
 * tests/integration/test_audit_fail.c
 *
 * Integration tests: audit mode, failing scenarios.
 *
 * Exercises the full audit pipeline:
 *   policy_parse() → eval_audit() → findings
 *
 * Each test proves exactly which TL-S / TL-A finding fires for a
 * known-bad policy input.
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

static int run_policy_parse(const char    *path,
                             finding_set_t *fs,
                             arena_t       *arena,
                             policy_t     **policy_out)
{
    tl_error_t err = policy_parse(arena, path, fs, policy_out);
    return tl_ok(err) ? 0 : (int)err.kind;
}

static void run_audit_on(policy_t *policy, finding_set_t *fs, arena_t *arena)
{
    eval_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.policy         = policy;
    ctx.findings       = fs;
    ctx.arena          = arena;
    ctx.reference_time = 1700000000;
    eval_audit(&ctx);
}


/* =========================================================================
 * TEST: alg_none.yaml → TL-S002 (schema halt, non-suppressible)
 * ========================================================================= */

TEST(audit_fail_TL_S002_fires)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t *policy = NULL;
    int rc = run_policy_parse("tests/fixtures/policies/invalid/alg_none.yaml",
                               &fs, arena, &policy);

    /* policy_parse must fail (schema halt) */
    ASSERT_NE(rc, 0);
    ASSERT_TRUE(has_active(&fs, "TL-S002"));

    arena_free(arena);
}

TEST(audit_fail_TL_S002_no_fire_on_good_policy)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t *policy = NULL;
    int rc = run_policy_parse("tests/fixtures/policies/valid/minimal.yaml",
                               &fs, arena, &policy);
    ASSERT_EQ(rc, 0);
    ASSERT_FALSE(has_active(&fs, "TL-S002"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: jwks_url.yaml → TL-S011 (JWKS_URL_SOURCE)
 * ========================================================================= */

TEST(audit_fail_TL_S011_fires)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t *policy = NULL;
    /* jwks.source is a URL — schema error in v1 */
    run_policy_parse("tests/fixtures/policies/invalid/jwks_url.yaml",
                     &fs, arena, &policy);

    ASSERT_TRUE(has_active(&fs, "TL-S011"));

    arena_free(arena);
}

TEST(audit_fail_TL_S011_no_fire_on_local_source)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t *policy = NULL;
    run_policy_parse("tests/fixtures/policies/valid/minimal.yaml",
                     &fs, arena, &policy);
    ASSERT_FALSE(has_active(&fs, "TL-S011"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: builder with http issuer in prod → TL-A002
 * ========================================================================= */

TEST(audit_fail_TL_A002_fires)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "http://auth.example.com");  /* http, not https */
    policy_builder_audience_exact(&pb, "api");
    policy_builder_algorithm(&pb, ALG_RS256);
    policy_builder_require_claims(&pb, CLAIM_ISS | CLAIM_AUD | CLAIM_EXP);
    policy_builder_max_ttl(&pb, 3600);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    run_audit_on(policy, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-A002"));

    arena_free(arena);
}

TEST(audit_fail_TL_A002_no_fire)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "api");
    policy_builder_algorithm(&pb, ALG_RS256);
    policy_builder_require_claims(&pb, CLAIM_ISS | CLAIM_AUD | CLAIM_EXP);
    policy_builder_max_ttl(&pb, 3600);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    run_audit_on(policy, &fs, arena);
    ASSERT_FALSE(has_active(&fs, "TL-A002"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: builder with wildcard audience → TL-A004
 * ========================================================================= */

TEST(audit_fail_TL_A004_fires)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "*");   /* wildcard */
    policy_builder_algorithm(&pb, ALG_RS256);
    policy_builder_max_ttl(&pb, 3600);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    run_audit_on(policy, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-A004"));

    arena_free(arena);
}

TEST(audit_fail_TL_A004_no_fire)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "specific-service");
    policy_builder_algorithm(&pb, ALG_RS256);
    policy_builder_max_ttl(&pb, 3600);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    run_audit_on(policy, &fs, arena);
    ASSERT_FALSE(has_active(&fs, "TL-A004"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: HS256 in prod → TL-A005
 * ========================================================================= */

TEST(audit_fail_TL_A005_fires)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "api");
    policy_builder_algorithm(&pb, ALG_HS256);   /* symmetric in prod */
    policy_builder_max_ttl(&pb, 3600);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    run_audit_on(policy, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-A005"));

    arena_free(arena);
}

TEST(audit_fail_TL_A005_no_fire)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "api");
    policy_builder_algorithm(&pb, ALG_RS256);   /* asymmetric — safe */
    policy_builder_max_ttl(&pb, 3600);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    run_audit_on(policy, &fs, arena);
    ASSERT_FALSE(has_active(&fs, "TL-A005"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: no max_ttl → TL-A007
 * ========================================================================= */

TEST(audit_fail_TL_A007_fires)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "api");
    policy_builder_algorithm(&pb, ALG_RS256);
    /* max_ttl intentionally NOT set — remains 0 */
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    run_audit_on(policy, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-A007"));

    arena_free(arena);
}

TEST(audit_fail_TL_A007_no_fire)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "api");
    policy_builder_algorithm(&pb, ALG_RS256);
    policy_builder_max_ttl(&pb, 3600);   /* set — no TL-A007 */
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    run_audit_on(policy, &fs, arena);
    ASSERT_FALSE(has_active(&fs, "TL-A007"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: requires.claims missing exp → TL-A014
 * ========================================================================= */

TEST(audit_fail_TL_A014_fires)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "api");
    policy_builder_algorithm(&pb, ALG_RS256);
    policy_builder_max_ttl(&pb, 3600);
    /* No require_claims call — exp/iss/aud absent from required mask */
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    run_audit_on(policy, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-A014"));

    arena_free(arena);
}

TEST(audit_fail_TL_A014_no_fire)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "api");
    policy_builder_algorithm(&pb, ALG_RS256);
    policy_builder_max_ttl(&pb, 3600);
    policy_builder_require_claims(&pb, CLAIM_EXP | CLAIM_ISS | CLAIM_AUD);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    run_audit_on(policy, &fs, arena);
    ASSERT_FALSE(has_active(&fs, "TL-A014"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: localhost issuer in prod → TL-A003
 * ========================================================================= */

TEST(audit_fail_TL_A003_fires)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://localhost/auth");
    policy_builder_audience_exact(&pb, "api");
    policy_builder_algorithm(&pb, ALG_RS256);
    policy_builder_max_ttl(&pb, 3600);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    run_audit_on(policy, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-A003"));

    arena_free(arena);
}

TEST(audit_fail_TL_A003_no_fire)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "api");
    policy_builder_algorithm(&pb, ALG_RS256);
    policy_builder_max_ttl(&pb, 3600);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    run_audit_on(policy, &fs, arena);
    ASSERT_FALSE(has_active(&fs, "TL-A003"));

    arena_free(arena);
}


/* =========================================================================
 * TEST_MAIN
 * ========================================================================= */

TEST_MAIN(
    tl_run_audit_fail_TL_S002_fires,
    tl_run_audit_fail_TL_S002_no_fire_on_good_policy,
    tl_run_audit_fail_TL_S011_fires,
    tl_run_audit_fail_TL_S011_no_fire_on_local_source,
    tl_run_audit_fail_TL_A002_fires,
    tl_run_audit_fail_TL_A002_no_fire,
    tl_run_audit_fail_TL_A004_fires,
    tl_run_audit_fail_TL_A004_no_fire,
    tl_run_audit_fail_TL_A005_fires,
    tl_run_audit_fail_TL_A005_no_fire,
    tl_run_audit_fail_TL_A007_fires,
    tl_run_audit_fail_TL_A007_no_fire,
    tl_run_audit_fail_TL_A014_fires,
    tl_run_audit_fail_TL_A014_no_fire,
    tl_run_audit_fail_TL_A003_fires,
    tl_run_audit_fail_TL_A003_no_fire,
)
