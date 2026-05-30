/*
 * tests/integration/test_validate_pass.c
 *
 * Integration tests: validate mode, passing scenarios.
 *
 * Uses token_builder and policy_builder to construct inputs directly,
 * bypassing the parsers.  Invokes eval_validate() directly.
 *
 * Token fixture files under tests/fixtures/tokens/valid/ are empty stubs
 * (only the fixture gen script knows how to create real JWTs).  All passing
 * validate tests therefore use the builders.
 *
 * The reference_time used throughout is 1700000000 (2023-11-14T22:13:20Z).
 * Valid tokens have exp > reference_time and iat <= reference_time.
 */

#define _POSIX_C_SOURCE 200809L

#include "helpers/test_runner.h"
#include "helpers/token_builder.h"
#include "helpers/policy_builder.h"

#include "tokenlint.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"
#include "token.h"
#include "jwks.h"
#include "eval_ctx.h"

#include <string.h>
#include <stddef.h>


/* =========================================================================
 * Constants
 * ========================================================================= */

#define REFTIME   ((int64_t)1700000000)
#define VALID_EXP (REFTIME + 3600)
#define VALID_IAT  REFTIME


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

/* Build a minimal valid JWKS (single RS256 key with kid matching "key-1") */
static jwks_t *make_jwks_rs256(arena_t *arena, const char *kid_cstr)
{
    jwks_key_t *k = (jwks_key_t *)arena_alloc(arena, sizeof(jwks_key_t),
                                                _Alignof(jwks_key_t));
    if (!k) return NULL;
    memset(k, 0, sizeof(*k));
    k->kid           = arena_strdup(arena, str_from_cstr(kid_cstr));
    k->kty           = KTY_RSA;
    k->crv           = CRV_UNSET;
    k->use           = KEY_USE_SIG;
    k->key_ops_verify = 1;
    k->declared_alg  = ALG_RS256;
    /* key_material: null — sig verification not reached in these tests
     * because token.sig == NULL and eval_alg won't find a key and emits
     * TL-V011.  We test "structural pass" only here — full sig verify
     * is exercised once crypto backend is wired. */
    k->key_material     = NULL;
    k->key_material_len = 0;

    jwks_t *j = (jwks_t *)arena_alloc(arena, sizeof(jwks_t), _Alignof(jwks_t));
    if (!j) return NULL;
    j->keys  = k;
    j->count = 1;
    return j;
}

static void run_validate_on(const policy_t *policy,
                             const jwks_t   *jwks,
                             const token_t  *token,
                             finding_set_t  *fs,
                             arena_t        *arena)
{
    eval_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.policy         = policy;
    ctx.jwks           = jwks;
    ctx.token          = token;
    ctx.findings       = fs;
    ctx.arena          = arena;
    ctx.reference_time = REFTIME;
    eval_validate(&ctx);
}


/* =========================================================================
 * TEST: well-formed RS256 token against matching policy — no V findings
 *
 * Token has kid matching a key in the JWKS.  eval_alg passes structurally.
 * eval_time passes (exp in the future, iat <= now, TTL within limit).
 * No TL-V findings (except TL-V011 which fires because we have no real
 * key_material — that's expected in this test harness).
 * ========================================================================= */

TEST(validate_pass_rs256_structure_ok)
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
    policy_builder_require_claims(&pb, CLAIM_EXP | CLAIM_ISS | CLAIM_AUD | CLAIM_IAT);
    policy_builder_max_ttl(&pb, 7200);
    policy_builder_require_kid(&pb, 1);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_RS256);
    token_builder_kid(&tb, "key-1");
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_single(&tb, "payments-api");
    token_builder_exp(&tb, VALID_EXP);
    token_builder_iat(&tb, VALID_IAT);
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);

    /* Structural checks pass: no alg, time, or claim findings */
    ASSERT_FALSE(has_active(&fs, "TL-V001"));
    ASSERT_FALSE(has_active(&fs, "TL-V002"));
    ASSERT_FALSE(has_active(&fs, "TL-V003"));
    ASSERT_FALSE(has_active(&fs, "TL-V009"));
    ASSERT_FALSE(has_active(&fs, "TL-V010"));
    ASSERT_FALSE(has_active(&fs, "TL-V022"));
    ASSERT_FALSE(has_active(&fs, "TL-V023"));
    ASSERT_FALSE(has_active(&fs, "TL-V024"));
    ASSERT_FALSE(has_active(&fs, "TL-V025"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: ES256 token against ES256 policy — structural pass
 * ========================================================================= */

TEST(validate_pass_es256_structure_ok)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_STAGE);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "api");
    policy_builder_algorithm(&pb, ALG_ES256);
    policy_builder_require_claims(&pb, CLAIM_EXP | CLAIM_ISS | CLAIM_AUD | CLAIM_IAT);
    policy_builder_max_ttl(&pb, 3600);
    policy_builder_require_kid(&pb, 1);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    /* EC key */
    jwks_key_t *k = (jwks_key_t *)arena_alloc(arena, sizeof(jwks_key_t),
                                                _Alignof(jwks_key_t));
    ASSERT_NOT_NULL(k);
    memset(k, 0, sizeof(*k));
    k->kid            = STR_LIT("ec-key-1");
    k->kty            = KTY_EC;
    k->crv            = CRV_P256;
    k->use            = KEY_USE_SIG;
    k->key_ops_verify = 1;
    k->declared_alg   = ALG_ES256;

    jwks_t *jwks = (jwks_t *)arena_alloc(arena, sizeof(jwks_t), _Alignof(jwks_t));
    ASSERT_NOT_NULL(jwks);
    jwks->keys  = k;
    jwks->count = 1;

    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_ES256);
    token_builder_kid(&tb, "ec-key-1");
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_single(&tb, "api");
    token_builder_exp(&tb, VALID_EXP);
    token_builder_iat(&tb, VALID_IAT);
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);

    ASSERT_FALSE(has_active(&fs, "TL-V001"));
    ASSERT_FALSE(has_active(&fs, "TL-V003"));
    ASSERT_FALSE(has_active(&fs, "TL-V004"));
    ASSERT_FALSE(has_active(&fs, "TL-V009"));
    ASSERT_FALSE(has_active(&fs, "TL-V010"));
    ASSERT_FALSE(has_active(&fs, "TL-V022"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: token with multiple audiences — matching policy aud — no TL-V findings
 * ========================================================================= */

TEST(validate_pass_multi_aud_match)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "primary-api");
    policy_builder_audience_exact(&pb, "secondary-api");
    policy_builder_algorithm(&pb, ALG_RS256);
    policy_builder_require_claims(&pb, CLAIM_EXP | CLAIM_ISS | CLAIM_AUD | CLAIM_IAT);
    policy_builder_max_ttl(&pb, 3600);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    const char *auds[] = { "primary-api", "secondary-api" };
    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_RS256);
    token_builder_kid(&tb, "key-1");
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_multi(&tb, auds, 2);
    token_builder_exp(&tb, VALID_EXP);
    token_builder_iat(&tb, VALID_IAT);
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);

    ASSERT_FALSE(has_active(&fs, "TL-V003"));
    ASSERT_FALSE(has_active(&fs, "TL-V022"));
    ASSERT_FALSE(any_active_fail(&fs));

    arena_free(arena);
}


/* =========================================================================
 * TEST: token with nbf set (not yet valid check) — nbf in the past → passes
 * ========================================================================= */

TEST(validate_pass_nbf_in_past)
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
    policy_builder_require_claims(&pb, CLAIM_EXP | CLAIM_ISS | CLAIM_AUD | CLAIM_IAT);
    policy_builder_max_ttl(&pb, 3600);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_RS256);
    token_builder_kid(&tb, "key-1");
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_single(&tb, "api");
    token_builder_exp(&tb, VALID_EXP);
    token_builder_iat(&tb, VALID_IAT);
    token_builder_nbf(&tb, REFTIME - 60);  /* nbf one minute ago — valid */
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);

    ASSERT_FALSE(has_active(&fs, "TL-V022"));
    ASSERT_FALSE(has_active(&fs, "TL-V023"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: TTL within limit — no TL-V025
 * ========================================================================= */

TEST(validate_pass_ttl_within_limit)
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
    policy_builder_require_claims(&pb,
        CLAIM_EXP | CLAIM_ISS | CLAIM_AUD | CLAIM_IAT);
    policy_builder_max_ttl(&pb, 3600);  /* 1 hour limit */
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_RS256);
    token_builder_kid(&tb, "key-1");
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_single(&tb, "api");
    token_builder_iat(&tb, VALID_IAT);
    token_builder_exp(&tb, VALID_IAT + 1800);  /* 30 min TTL — within 1hr */
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);

    ASSERT_FALSE(has_active(&fs, "TL-V025"));
    ASSERT_FALSE(has_active(&fs, "TL-V024"));

    arena_free(arena);
}


/* =========================================================================
 * TEST_MAIN
 * ========================================================================= */

TEST_MAIN(
    tl_run_validate_pass_rs256_structure_ok,
    tl_run_validate_pass_es256_structure_ok,
    tl_run_validate_pass_multi_aud_match,
    tl_run_validate_pass_nbf_in_past,
    tl_run_validate_pass_ttl_within_limit,
)
