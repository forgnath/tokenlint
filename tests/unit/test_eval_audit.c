/*
 * tests/unit/test_eval_audit.c
 *
 * Unit tests for src/eval/eval_audit.c
 *
 * Covers all TL-A findings:
 *   TL-A002  ISSUER_HTTP_PROD
 *   TL-A003  ISSUER_LOCALHOST_PROD
 *   TL-A004  AUDIENCE_WILDCARD
 *   TL-A005  POLICY_ALG_SYMMETRIC_PROD
 *   TL-A007  TTL_UNBOUNDED
 *   TL-A014  REQUIRED_CLAIM_MISSING
 */

#include "helpers/test_runner.h"
#include "tokenlint.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"
#include "eval_ctx.h"

#include <string.h>
#include <stddef.h>

void eval_audit(eval_ctx_t *ctx);


/* =========================================================================
 * Fixture helpers
 * ========================================================================= */

/* Build a fully-valid policy (no findings should fire for it) */
static policy_t make_good_policy(void)
{
    policy_t p;
    memset(&p, 0, sizeof(p));
    p.environment = ENV_PROD;

    /* RS256 only — asymmetric, safe */
    ALLOWSET_ADD(p.algorithms, ALG_RS256);

    /* Non-wildcard audience */
    static str_t aud_vals[1];
    aud_vals[0] = STR_LIT("payments-api");
    p.audiences.mode   = AUDIENCE_MODE_EXACT;
    p.audiences.values = aud_vals;
    p.audiences.count  = 1;

    /* Non-http, non-localhost issuer */
    static str_t iss_vals[1];
    iss_vals[0] = STR_LIT("https://auth.example.com");
    p.issuers.mode   = ISSUER_MODE_EXACT;
    p.issuers.values = iss_vals;
    p.issuers.count  = 1;

    /* TTL bounded */
    p.time_limits.max_ttl_seconds        = 3600;
    p.time_limits.max_clock_skew_seconds = 60;

    /* Required claims include iss, aud, exp */
    p.required_registered_claims = CLAIM_ISS | CLAIM_AUD | CLAIM_EXP;

    return p;
}

static eval_ctx_t make_ctx(arena_t *arena, finding_set_t *fs, policy_t *pol)
{
    eval_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.arena          = arena;
    ctx.findings       = fs;
    ctx.policy         = pol;
    ctx.reference_time = 1700000000;
    return ctx;
}

static int has_finding(const finding_set_t *fs, const char *id_cstr)
{
    str_t id = str_from_cstr(id_cstr);
    for (size_t i = 0; i < fs->count; i++) {
        if (str_eq(fs->findings[i].id, id) &&
            fs->findings[i].status == FINDING_ACTIVE) return 1;
    }
    return 0;
}

static size_t count_finding(const finding_set_t *fs, const char *id_cstr)
{
    str_t id = str_from_cstr(id_cstr);
    size_t n = 0;
    for (size_t i = 0; i < fs->count; i++) {
        if (str_eq(fs->findings[i].id, id) &&
            fs->findings[i].status == FINDING_ACTIVE) n++;
    }
    return n;
}


/* =========================================================================
 * Baseline: good policy emits no TL-A findings
 * ========================================================================= */

TEST(good_policy_no_audit_findings) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-A002"));
    ASSERT_FALSE(has_finding(&fs, "TL-A003"));
    ASSERT_FALSE(has_finding(&fs, "TL-A004"));
    ASSERT_FALSE(has_finding(&fs, "TL-A005"));
    ASSERT_FALSE(has_finding(&fs, "TL-A007"));
    ASSERT_FALSE(has_finding(&fs, "TL-A014"));
    arena_free(arena);
}


/* =========================================================================
 * TL-A002: ISSUER_HTTP_PROD
 * ========================================================================= */

TEST(a002_fires_http_issuer_prod) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    static str_t iss_vals[1];
    iss_vals[0] = STR_LIT("http://auth.example.com");
    pol.issuers.values = iss_vals;
    pol.issuers.count  = 1;

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A002"));
    arena_free(arena);
}

TEST(a002_no_fire_https_issuer_prod) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-A002"));
    arena_free(arena);
}

TEST(a002_no_fire_http_issuer_dev) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    pol.environment = ENV_DEV;

    static str_t iss_vals[1];
    iss_vals[0] = STR_LIT("http://auth.example.com");
    pol.issuers.values = iss_vals;

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-A002"));
    arena_free(arena);
}


/* =========================================================================
 * TL-A003: ISSUER_LOCALHOST_PROD
 * ========================================================================= */

TEST(a003_fires_localhost_issuer_prod) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    static str_t iss_vals[1];
    iss_vals[0] = STR_LIT("https://localhost/auth");
    pol.issuers.values = iss_vals;

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A003"));
    arena_free(arena);
}

TEST(a003_fires_127001_prod) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    static str_t iss_vals[1];
    iss_vals[0] = STR_LIT("https://127.0.0.1:8080/auth");
    pol.issuers.values = iss_vals;

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A003"));
    arena_free(arena);
}

TEST(a003_no_fire_real_host_prod) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-A003"));
    arena_free(arena);
}

TEST(a003_no_fire_localhost_dev) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    pol.environment = ENV_DEV;

    static str_t iss_vals[1];
    iss_vals[0] = STR_LIT("https://localhost/auth");
    pol.issuers.values = iss_vals;

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-A003"));
    arena_free(arena);
}


/* =========================================================================
 * TL-A004: AUDIENCE_WILDCARD
 * ========================================================================= */

TEST(a004_fires_wildcard_audience) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    static str_t aud_vals[1];
    aud_vals[0] = STR_LIT("*");
    pol.audiences.values = aud_vals;
    pol.audiences.count  = 1;

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A004"));
    arena_free(arena);
}

TEST(a004_fires_empty_audience) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    static str_t aud_vals[1];
    aud_vals[0] = STR_LIT("");
    pol.audiences.values = aud_vals;
    pol.audiences.count  = 1;

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A004"));
    arena_free(arena);
}

TEST(a004_no_fire_specific_audience) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-A004"));
    arena_free(arena);
}

TEST(a004_fires_in_any_environment) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    pol.environment = ENV_DEV;  /* even dev gets TL-A004 */

    static str_t aud_vals[1];
    aud_vals[0] = STR_LIT("*");
    pol.audiences.values = aud_vals;
    pol.audiences.count  = 1;

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A004"));
    arena_free(arena);
}


/* =========================================================================
 * TL-A005: POLICY_ALG_SYMMETRIC_PROD
 * ========================================================================= */

TEST(a005_fires_hs256_prod) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    ALLOWSET_ADD(pol.algorithms, ALG_HS256);

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A005"));
    arena_free(arena);
}

TEST(a005_fires_hs512_prod) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    pol.algorithms = ALLOWSET_EMPTY;
    ALLOWSET_ADD(pol.algorithms, ALG_HS512);

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A005"));
    arena_free(arena);
}

TEST(a005_no_fire_hs256_dev) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    pol.environment = ENV_DEV;
    ALLOWSET_ADD(pol.algorithms, ALG_HS256);

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-A005"));
    arena_free(arena);
}

TEST(a005_fires_env_unknown_treated_as_prod) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    pol.environment = ENV_UNKNOWN;
    ALLOWSET_ADD(pol.algorithms, ALG_HS256);

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A005"));
    arena_free(arena);
}

TEST(a005_no_fire_asymmetric_only) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-A005"));
    arena_free(arena);
}


/* =========================================================================
 * TL-A007: TTL_UNBOUNDED
 * ========================================================================= */

TEST(a007_fires_no_max_ttl) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    pol.time_limits.max_ttl_seconds = 0; /* unset */

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A007"));
    arena_free(arena);
}

TEST(a007_no_fire_max_ttl_set) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy(); /* max_ttl_seconds = 3600 */
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-A007"));
    arena_free(arena);
}


/* =========================================================================
 * TL-A014: REQUIRED_CLAIM_MISSING
 * ========================================================================= */

TEST(a014_fires_exp_missing) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    pol.required_registered_claims = CLAIM_ISS | CLAIM_AUD; /* no exp */

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A014"));
    arena_free(arena);
}

TEST(a014_fires_iss_missing) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    pol.required_registered_claims = CLAIM_AUD | CLAIM_EXP; /* no iss */

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A014"));
    arena_free(arena);
}

TEST(a014_fires_aud_missing) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    pol.required_registered_claims = CLAIM_ISS | CLAIM_EXP; /* no aud */

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A014"));
    arena_free(arena);
}

TEST(a014_fires_three_separate_findings) {
    /* When all three are missing, three separate A014 findings fire */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    pol.required_registered_claims = 0; /* none required */

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_EQ(count_finding(&fs, "TL-A014"), 3);
    arena_free(arena);
}

TEST(a014_no_fire_all_present) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy(); /* ISS|AUD|EXP all set */
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-A014"));
    arena_free(arena);
}


/* =========================================================================
 * SECURITY_PROP: critical findings are correct severity
 * ========================================================================= */

SECURITY_PROP(a002_is_critical_severity) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    static str_t iss_vals[1];
    iss_vals[0] = STR_LIT("http://auth.example.com");
    pol.issuers.values = iss_vals;

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    int found = 0;
    for (size_t i = 0; i < fs.count; i++) {
        str_t id = str_from_cstr("TL-A002");
        if (str_eq(fs.findings[i].id, id)) {
            ASSERT_EQ(fs.findings[i].severity, SEV_CRITICAL);
            found = 1;
        }
    }
    ASSERT_TRUE(found);
    arena_free(arena);
}

SECURITY_PROP(a004_wildcard_aud_is_critical) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    static str_t aud_vals[1];
    aud_vals[0] = STR_LIT("*");
    pol.audiences.values = aud_vals;

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    int found = 0;
    for (size_t i = 0; i < fs.count; i++) {
        str_t id = str_from_cstr("TL-A004");
        if (str_eq(fs.findings[i].id, id)) {
            ASSERT_EQ(fs.findings[i].severity, SEV_CRITICAL);
            found = 1;
        }
    }
    ASSERT_TRUE(found);
    arena_free(arena);
}

SECURITY_PROP(a005_symmetric_prod_is_critical) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t pol = make_good_policy();
    ALLOWSET_ADD(pol.algorithms, ALG_HS256);

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol);
    eval_audit(&ctx);

    int found = 0;
    for (size_t i = 0; i < fs.count; i++) {
        str_t id = str_from_cstr("TL-A005");
        if (str_eq(fs.findings[i].id, id)) {
            ASSERT_EQ(fs.findings[i].severity, SEV_CRITICAL);
            found = 1;
        }
    }
    ASSERT_TRUE(found);
    arena_free(arena);
}

/* unused helper suppress */
static size_t _ucf(const finding_set_t *fs, const char *id) __attribute__((unused));
static size_t _ucf(const finding_set_t *fs, const char *id) { return count_finding(fs, id); }

TEST_MAIN(
    tl_run_good_policy_no_audit_findings,
    tl_run_a002_fires_http_issuer_prod,
    tl_run_a002_no_fire_https_issuer_prod,
    tl_run_a002_no_fire_http_issuer_dev,
    tl_run_a003_fires_localhost_issuer_prod,
    tl_run_a003_fires_127001_prod,
    tl_run_a003_no_fire_real_host_prod,
    tl_run_a003_no_fire_localhost_dev,
    tl_run_a004_fires_wildcard_audience,
    tl_run_a004_fires_empty_audience,
    tl_run_a004_no_fire_specific_audience,
    tl_run_a004_fires_in_any_environment,
    tl_run_a005_fires_hs256_prod,
    tl_run_a005_fires_hs512_prod,
    tl_run_a005_no_fire_hs256_dev,
    tl_run_a005_fires_env_unknown_treated_as_prod,
    tl_run_a005_no_fire_asymmetric_only,
    tl_run_a007_fires_no_max_ttl,
    tl_run_a007_no_fire_max_ttl_set,
    tl_run_a014_fires_exp_missing,
    tl_run_a014_fires_iss_missing,
    tl_run_a014_fires_aud_missing,
    tl_run_a014_fires_three_separate_findings,
    tl_run_a014_no_fire_all_present,
    tl_run_a002_is_critical_severity,
    tl_run_a004_wildcard_aud_is_critical,
    tl_run_a005_symmetric_prod_is_critical,
)
