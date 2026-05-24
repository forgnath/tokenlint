/*
 * tests/unit/test_eval_validate.c
 *
 * Unit tests for src/eval/eval_validate.c
 *
 * eval_validate() orchestrates: eval_audit + required-claim checks +
 * eval_alg + eval_time + claim rule checks.
 *
 * Tests verify the integration: correct findings fire, correct findings
 * don't fire, and ordering doesn't cause double-counting.
 */

#include "helpers/test_runner.h"
#include "tokenlint.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"
#include "token.h"
#include "jwks.h"
#include "eval_ctx.h"

#include <string.h>
#include <stddef.h>

void eval_validate(eval_ctx_t *ctx);

#define T_BASE   ((int64_t)1704067200)  /* 2024-01-01T00:00:00Z */
#define T_HOUR   ((int64_t)3600)

/* =========================================================================
 * Fixture helpers
 * ========================================================================= */

static policy_t make_good_policy(void)
{
    policy_t p;
    memset(&p, 0, sizeof(p));
    p.environment = ENV_PROD;
    ALLOWSET_ADD(p.algorithms, ALG_RS256);

    static str_t aud_vals[1]; aud_vals[0] = STR_LIT("api");
    p.audiences.mode = AUDIENCE_MODE_EXACT;
    p.audiences.values = aud_vals;
    p.audiences.count  = 1;

    static str_t iss_vals[1]; iss_vals[0] = STR_LIT("https://auth.example.com");
    p.issuers.mode   = ISSUER_MODE_EXACT;
    p.issuers.values = iss_vals;
    p.issuers.count  = 1;

    p.time_limits.max_ttl_seconds        = T_HOUR;
    p.time_limits.max_clock_skew_seconds = 60;
    p.required_registered_claims = CLAIM_ISS | CLAIM_AUD | CLAIM_EXP;
    return p;
}

/* A token that satisfies the good policy (except signature, which is Layer 7) */
static token_t make_good_token(void)
{
    token_t t;
    memset(&t, 0, sizeof(t));
    t.alg = ALG_RS256;
    t.kid = STR_LIT("k1");
    t.iss = STR_LIT("https://auth.example.com");

    static str_t aud_arr[1]; aud_arr[0] = STR_LIT("api");
    t.aud       = aud_arr;
    t.aud_count = 1;

    t.exp = T_BASE + T_HOUR;
    t.iat = T_BASE;
    t.present_claims = CLAIM_ISS | CLAIM_AUD | CLAIM_EXP | CLAIM_IAT;
    return t;
}

static jwks_key_t make_rsa_key(const char *kid_cstr)
{
    jwks_key_t k;
    memset(&k, 0, sizeof(k));
    if (kid_cstr) k.kid = str_from_cstr(kid_cstr);
    k.kty            = KTY_RSA;
    k.crv            = CRV_UNSET;
    k.declared_alg   = ALG_NONE_ALG;
    k.key_ops_verify = 1;
    k.use            = KEY_USE_SIG;
    return k;
}

static int has_active(const finding_set_t *fs, const char *id_cstr)
{
    str_t id = str_from_cstr(id_cstr);
    for (size_t i = 0; i < fs->count; i++) {
        if (str_eq(fs->findings[i].id, id) &&
            fs->findings[i].status == FINDING_ACTIVE) return 1;
    }
    return 0;
}

static eval_ctx_t make_ctx(arena_t *arena, finding_set_t *fs,
                            policy_t *pol, jwks_t *jwks,
                            token_t *tok, int64_t reftime)
{
    eval_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.arena          = arena;
    ctx.findings       = fs;
    ctx.policy         = pol;
    ctx.jwks           = jwks;
    ctx.token          = tok;
    ctx.reference_time = reftime;
    return ctx;
}


/* =========================================================================
 * Basic integration: good token + good policy → only audit findings
 * (some TL-A findings may fire, but no TL-V from alg/time)
 * ========================================================================= */

TEST(good_token_good_policy_no_v_findings) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_good_policy();
    token_t  tok = make_good_token();
    jwks_key_t keys[1]; keys[0] = make_rsa_key("k1");
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok, T_BASE);
    eval_validate(&ctx);

    /* No algorithm findings */
    ASSERT_FALSE(has_active(&fs, "TL-V003"));
    ASSERT_FALSE(has_active(&fs, "TL-V004"));
    ASSERT_FALSE(has_active(&fs, "TL-V005"));
    ASSERT_FALSE(has_active(&fs, "TL-V009"));
    ASSERT_FALSE(has_active(&fs, "TL-V010"));
    ASSERT_FALSE(has_active(&fs, "TL-V011"));

    /* No time findings */
    ASSERT_FALSE(has_active(&fs, "TL-V022"));
    ASSERT_FALSE(has_active(&fs, "TL-V024"));
    ASSERT_FALSE(has_active(&fs, "TL-V025"));

    arena_free(arena);
}


/* =========================================================================
 * eval_validate calls eval_audit internally
 * ========================================================================= */

TEST(validate_runs_audit_pass) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_good_policy();
    /* Inject a bad audience — A004 should fire */
    static str_t aud_vals[1]; aud_vals[0] = STR_LIT("*");
    pol.audiences.values = aud_vals;

    token_t  tok = make_good_token();
    jwks_key_t keys[1]; keys[0] = make_rsa_key("k1");
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok, T_BASE);
    eval_validate(&ctx);

    ASSERT_TRUE(has_active(&fs, "TL-A004"));
    arena_free(arena);
}


/* =========================================================================
 * Required claim checks fire TL-C001
 * ========================================================================= */

TEST(required_claim_absent_fires_c001) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_good_policy();
    /* Policy requires exp; token doesn't have it */
    token_t tok = make_good_token();
    tok.present_claims &= ~CLAIM_EXP; /* remove exp from present */
    tok.exp = 0;

    jwks_key_t keys[1]; keys[0] = make_rsa_key("k1");
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok, T_BASE);
    eval_validate(&ctx);

    ASSERT_TRUE(has_active(&fs, "TL-C001"));
    arena_free(arena);
}

TEST(no_c001_when_all_required_claims_present) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_good_policy();
    token_t  tok = make_good_token(); /* all required present */

    jwks_key_t keys[1]; keys[0] = make_rsa_key("k1");
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok, T_BASE);
    eval_validate(&ctx);

    ASSERT_FALSE(has_active(&fs, "TL-C001"));
    arena_free(arena);
}


/* =========================================================================
 * Algorithm findings integrate correctly through validate
 * ========================================================================= */

TEST(validate_fires_v003_wrong_alg) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_good_policy(); /* allows RS256 */
    token_t  tok = make_good_token();
    tok.alg = ALG_ES256; /* wrong alg */

    jwks_key_t keys[1]; keys[0] = make_rsa_key("k1");
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok, T_BASE);
    eval_validate(&ctx);

    ASSERT_TRUE(has_active(&fs, "TL-V003"));
    arena_free(arena);
}


/* =========================================================================
 * Time findings integrate correctly through validate
 * ========================================================================= */

TEST(validate_fires_v022_expired_token) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_good_policy();
    token_t  tok = make_good_token();
    /* reference_time at or after exp */
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, NULL, &tok,
                              tok.exp); /* reference_time == exp → expired */
    /* Need jwks for alg path */
    jwks_key_t keys[1]; keys[0] = make_rsa_key("k1");
    jwks_t jwks = { keys, 1 };
    ctx.jwks = &jwks;

    eval_validate(&ctx);

    ASSERT_TRUE(has_active(&fs, "TL-V022"));
    arena_free(arena);
}

TEST(validate_fires_v025_ttl_exceeded) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_good_policy(); /* max_ttl = 1 hour */
    token_t  tok = make_good_token();
    /* Set TTL = 2 hours */
    tok.exp = T_BASE + 2 * T_HOUR;

    jwks_key_t keys[1]; keys[0] = make_rsa_key("k1");
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok, T_BASE);
    eval_validate(&ctx);

    ASSERT_TRUE(has_active(&fs, "TL-V025"));
    arena_free(arena);
}


/* =========================================================================
 * SECURITY_PROP: validate always includes audit pass
 * ========================================================================= */

SECURITY_PROP(validate_includes_audit_no_bypass) {
    /* A dangerous policy (wildcard audience) should always produce A004,
     * even through the validate path */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_good_policy();
    static str_t aud_vals[1]; aud_vals[0] = STR_LIT("*");
    pol.audiences.values = aud_vals;

    token_t tok = make_good_token();
    jwks_key_t keys[1]; keys[0] = make_rsa_key("k1");
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok, T_BASE);
    eval_validate(&ctx);

    /* Even though we're validating a token, audit findings must fire */
    ASSERT_TRUE(has_active(&fs, "TL-A004"));
    arena_free(arena);
}

SECURITY_PROP(expired_token_always_fails_in_validate) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs; findings_init(&fs);
    policy_t pol = make_good_policy();
    token_t  tok = make_good_token();

    jwks_key_t keys[1]; keys[0] = make_rsa_key("k1");
    jwks_t jwks = { keys, 1 };

    /* reference_time past exp → expired */
    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok,
                              T_BASE + T_HOUR + 1);
    eval_validate(&ctx);

    ASSERT_TRUE(has_active(&fs, "TL-V022"));
    arena_free(arena);
}

TEST_MAIN(
    tl_run_good_token_good_policy_no_v_findings,
    tl_run_validate_runs_audit_pass,
    tl_run_required_claim_absent_fires_c001,
    tl_run_no_c001_when_all_required_claims_present,
    tl_run_validate_fires_v003_wrong_alg,
    tl_run_validate_fires_v022_expired_token,
    tl_run_validate_fires_v025_ttl_exceeded,
    tl_run_validate_includes_audit_no_bypass,
    tl_run_expired_token_always_fails_in_validate,
)
