/*
 * tests/unit/test_eval_time.c
 *
 * Unit tests for src/eval/eval_time.c
 *
 * Covers all TL-V time findings:
 *   TL-V020  IAT_ABSENT_TTL_UNVERIFIABLE
 *   TL-V021  EXP_ABSENT_TTL_UNVERIFIABLE
 *   TL-V022  TOKEN_EXPIRED                (non-suppressible)
 *   TL-V023  TOKEN_NOT_YET_VALID
 *   TL-V024  TOKEN_TTL_INVALID            (non-suppressible)
 *   TL-V025  TOKEN_TTL_EXCEEDED
 *
 * All epoch constants verified with python3:
 *   python3 -c "import datetime; print(datetime.datetime(2024,1,1,tzinfo=datetime.timezone.utc).timestamp())"
 *   → 1704067200
 */

#include "helpers/test_runner.h"
#include "tokenlint.h"
#include "findings.h"
#include "policy.h"
#include "token.h"
#include "eval_ctx.h"

#include <string.h>
#include <stddef.h>

void eval_time(eval_ctx_t *ctx);

/* 2024-01-01T00:00:00Z = 1704067200 */
#define T_BASE   ((int64_t)1704067200)
#define T_HOUR   ((int64_t)3600)
#define T_MIN    ((int64_t)60)

static policy_t make_policy_with_ttl(int64_t max_ttl, int64_t clock_skew)
{
    policy_t p;
    memset(&p, 0, sizeof(p));
    p.environment = ENV_PROD;
    p.required_registered_claims = CLAIM_ISS | CLAIM_AUD | CLAIM_EXP;
    p.time_limits.max_ttl_seconds        = max_ttl;
    p.time_limits.max_clock_skew_seconds = clock_skew;
    return p;
}

static token_t make_token_times(int64_t exp, int64_t nbf, int64_t iat,
                                 uint32_t present)
{
    token_t t;
    memset(&t, 0, sizeof(t));
    t.exp = exp;
    t.nbf = nbf;
    t.iat = iat;
    t.present_claims = present;
    return t;
}

static eval_ctx_t make_ctx(arena_t *arena, finding_set_t *fs,
                            policy_t *pol, token_t *tok, int64_t reftime)
{
    eval_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.arena          = arena;
    ctx.findings       = fs;
    ctx.policy         = pol;
    ctx.token          = tok;
    ctx.reference_time = reftime;
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


/* =========================================================================
 * TL-V022: TOKEN_EXPIRED
 * ========================================================================= */

TEST(v022_fires_token_expired) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    /* exp = T_BASE, reference_time = T_BASE → expired (>= exp) */
    token_t tok = make_token_times(T_BASE, 0, 0, CLAIM_EXP);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V022"));
    arena_free(arena);
}

TEST(v022_fires_reference_after_exp) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    token_t tok = make_token_times(T_BASE, 0, 0, CLAIM_EXP);
    /* reference_time one second after exp */
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE + 1);
    eval_time(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V022"));
    arena_free(arena);
}

TEST(v022_no_fire_token_not_yet_expired) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    /* exp = T_BASE + 1, reference_time = T_BASE → not expired */
    token_t tok = make_token_times(T_BASE + 1, 0, 0, CLAIM_EXP);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V022"));
    arena_free(arena);
}

TEST(v022_no_fire_exp_absent) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(0, T_MIN);

    /* No CLAIM_EXP in present_claims — exp check skipped */
    token_t tok = make_token_times(0, 0, 0, 0);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V022"));
    arena_free(arena);
}


/* =========================================================================
 * TL-V023: TOKEN_NOT_YET_VALID
 * ========================================================================= */

TEST(v023_fires_reference_before_nbf_minus_skew) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    /* clock_skew = 60 */
    policy_t pol = make_policy_with_ttl(0, T_MIN);

    /* nbf = T_BASE, skew = 60, reference_time = T_BASE - 61 → not yet valid */
    token_t tok = make_token_times(0, T_BASE, 0, CLAIM_NBF);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE - 61);
    eval_time(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V023"));
    arena_free(arena);
}

TEST(v023_no_fire_within_skew_window) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(0, T_MIN);

    /* reference_time = T_BASE - 60 = exactly at nbf - skew → PASS */
    token_t tok = make_token_times(0, T_BASE, 0, CLAIM_NBF);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE - T_MIN);
    eval_time(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V023"));
    arena_free(arena);
}

TEST(v023_no_fire_nbf_absent) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(0, T_MIN);

    token_t tok = make_token_times(0, 0, 0, 0); /* no CLAIM_NBF */
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V023"));
    arena_free(arena);
}


/* =========================================================================
 * TL-V020: IAT_ABSENT_TTL_UNVERIFIABLE
 * ========================================================================= */

TEST(v020_fires_iat_absent_ttl_set) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    /* No CLAIM_IAT, max_ttl_seconds = 3600 → V020 */
    token_t tok = make_token_times(T_BASE + T_HOUR, 0, 0, CLAIM_EXP);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V020"));
    arena_free(arena);
}

TEST(v020_no_fire_iat_present) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    token_t tok = make_token_times(T_BASE + T_HOUR, 0, T_BASE,
                                   CLAIM_EXP | CLAIM_IAT);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V020"));
    arena_free(arena);
}

TEST(v020_no_fire_ttl_not_set) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    /* max_ttl_seconds = 0 → TTL not set → V020 doesn't fire */
    policy_t pol = make_policy_with_ttl(0, T_MIN);

    token_t tok = make_token_times(T_BASE + T_HOUR, 0, 0, CLAIM_EXP);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V020"));
    arena_free(arena);
}


/* =========================================================================
 * TL-V021: EXP_ABSENT_TTL_UNVERIFIABLE
 * ========================================================================= */

TEST(v021_fires_exp_absent_ttl_set) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    /* No CLAIM_EXP, max_ttl_seconds = 3600 → V021 */
    token_t tok = make_token_times(0, 0, T_BASE, CLAIM_IAT);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V021"));
    arena_free(arena);
}

TEST(v021_no_fire_exp_present) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    token_t tok = make_token_times(T_BASE + T_HOUR, 0, T_BASE,
                                   CLAIM_EXP | CLAIM_IAT);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V021"));
    arena_free(arena);
}


/* =========================================================================
 * TL-V024: TOKEN_TTL_INVALID  (exp - iat <= 0)
 * ========================================================================= */

TEST(v024_fires_exp_equals_iat) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    /* exp == iat → ttl = 0 → V024 */
    token_t tok = make_token_times(T_BASE, 0, T_BASE, CLAIM_EXP | CLAIM_IAT);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE - T_HOUR);
    eval_time(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V024"));
    arena_free(arena);
}

TEST(v024_fires_exp_before_iat) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    /* exp < iat → ttl negative → V024 */
    token_t tok = make_token_times(T_BASE - 1, 0, T_BASE, CLAIM_EXP | CLAIM_IAT);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE - T_HOUR);
    eval_time(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V024"));
    arena_free(arena);
}

TEST(v024_no_fire_valid_ttl) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    token_t tok = make_token_times(T_BASE + T_HOUR, 0, T_BASE,
                                   CLAIM_EXP | CLAIM_IAT);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V024"));
    arena_free(arena);
}


/* =========================================================================
 * TL-V025: TOKEN_TTL_EXCEEDED
 * ========================================================================= */

TEST(v025_fires_ttl_exceeds_max) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    /* max_ttl = 1 hour, token ttl = 2 hours */
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    token_t tok = make_token_times(T_BASE + 2 * T_HOUR, 0, T_BASE,
                                   CLAIM_EXP | CLAIM_IAT);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V025"));
    arena_free(arena);
}

TEST(v025_no_fire_ttl_at_max) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    /* ttl = exactly max → PASS */
    token_t tok = make_token_times(T_BASE + T_HOUR, 0, T_BASE,
                                   CLAIM_EXP | CLAIM_IAT);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V025"));
    arena_free(arena);
}

TEST(v025_no_fire_no_max_ttl) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    /* max_ttl_seconds = 0 → unbounded → V025 doesn't fire */
    policy_t pol = make_policy_with_ttl(0, T_MIN);

    token_t tok = make_token_times(T_BASE + 100 * T_HOUR, 0, T_BASE,
                                   CLAIM_EXP | CLAIM_IAT);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V025"));
    arena_free(arena);
}


/* =========================================================================
 * Clock skew: applies ONLY to nbf, never to exp
 * ========================================================================= */

TEST(exp_check_never_applies_skew) {
    /* Even with a large clock_skew, exp check has no grace period */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    /* clock_skew = 1 hour */
    policy_t pol = make_policy_with_ttl(0, T_HOUR);

    /* reference_time == exp → expired, even with skew */
    token_t tok = make_token_times(T_BASE, 0, 0, CLAIM_EXP);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V022"));
    arena_free(arena);
}

/* =========================================================================
 * SECURITY_PROP tests
 * ========================================================================= */

SECURITY_PROP(expired_token_always_fails) {
    /* V022 must fire regardless of suppression count */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    token_t tok = make_token_times(T_BASE - 1, 0, 0, CLAIM_EXP);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE);
    eval_time(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V022"));

    /* Verify it's marked non-suppressible: check the raw finding */
    int found_active = 0;
    for (size_t i = 0; i < fs.count; i++) {
        str_t id = str_from_cstr("TL-V022");
        if (str_eq(fs.findings[i].id, id)) {
            ASSERT_EQ(fs.findings[i].status, FINDING_ACTIVE);
            found_active = 1;
        }
    }
    ASSERT_TRUE(found_active);
    arena_free(arena);
}

SECURITY_PROP(invalid_ttl_always_fails) {
    /* V024 (exp <= iat) is non-suppressible */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    token_t tok = make_token_times(T_BASE, 0, T_BASE + 1,
                                   CLAIM_EXP | CLAIM_IAT);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE - T_HOUR);
    eval_time(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V024"));

    int found_active = 0;
    for (size_t i = 0; i < fs.count; i++) {
        str_t id = str_from_cstr("TL-V024");
        if (str_eq(fs.findings[i].id, id)) {
            ASSERT_EQ(fs.findings[i].status, FINDING_ACTIVE);
            found_active = 1;
        }
    }
    ASSERT_TRUE(found_active);
    arena_free(arena);
}

SECURITY_PROP(all_time_checks_independent) {
    /* Multiple time findings can fire in the same evaluation */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_policy_with_ttl(T_HOUR, T_MIN);

    /* exp in the past (V022) + iat == exp (V024) + ttl exceeded (V025 won't
     * fire because V024 fires first for ttl<=0, but both exp and iat absent
     * related findings check independently) */

    /* Construct: exp=T_BASE (expired), iat=T_BASE (same, so ttl=0 = V024),
     * reference_time = T_BASE+1 */
    token_t tok = make_token_times(T_BASE, 0, T_BASE, CLAIM_EXP | CLAIM_IAT);
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &tok, T_BASE + 1);
    eval_time(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V022")); /* expired */
    ASSERT_TRUE(has_finding(&fs, "TL-V024")); /* ttl invalid */

    arena_free(arena);
}

TEST_MAIN(
    tl_run_v022_fires_token_expired,
    tl_run_v022_fires_reference_after_exp,
    tl_run_v022_no_fire_token_not_yet_expired,
    tl_run_v022_no_fire_exp_absent,
    tl_run_v023_fires_reference_before_nbf_minus_skew,
    tl_run_v023_no_fire_within_skew_window,
    tl_run_v023_no_fire_nbf_absent,
    tl_run_v020_fires_iat_absent_ttl_set,
    tl_run_v020_no_fire_iat_present,
    tl_run_v020_no_fire_ttl_not_set,
    tl_run_v021_fires_exp_absent_ttl_set,
    tl_run_v021_no_fire_exp_present,
    tl_run_v024_fires_exp_equals_iat,
    tl_run_v024_fires_exp_before_iat,
    tl_run_v024_no_fire_valid_ttl,
    tl_run_v025_fires_ttl_exceeds_max,
    tl_run_v025_no_fire_ttl_at_max,
    tl_run_v025_no_fire_no_max_ttl,
    tl_run_exp_check_never_applies_skew,
    tl_run_expired_token_always_fails,
    tl_run_invalid_ttl_always_fails,
    tl_run_all_time_checks_independent,
)
