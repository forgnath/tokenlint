/*
 * tests/integration/test_validate_fail.c
 *
 * Integration tests: validate mode, failing scenarios.
 *
 * Each test proves that a specific TL-V finding fires for a known-bad
 * token or policy combination.  Uses token_builder + policy_builder;
 * eval_validate() is called directly (not via CLI subprocess).
 *
 * Reference time: REFTIME = 1700000000 (2023-11-14T22:13:20Z).
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

#define REFTIME       ((int64_t)1700000000)
#define VALID_EXP     (REFTIME + 3600)
#define VALID_IAT      REFTIME
#define PAST_EXP      (REFTIME - 1)        /* one second ago → expired */
#define FUTURE_NBF    (REFTIME + 300)       /* not valid for 5 more minutes */


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

static jwks_t *make_jwks_rs256(arena_t *arena, const char *kid_cstr)
{
    jwks_key_t *k = (jwks_key_t *)arena_alloc(arena, sizeof(jwks_key_t),
                                                _Alignof(jwks_key_t));
    if (!k) return NULL;
    memset(k, 0, sizeof(*k));
    k->kid            = arena_strdup(arena, str_from_cstr(kid_cstr));
    k->kty            = KTY_RSA;
    k->crv            = CRV_UNSET;
    k->use            = KEY_USE_SIG;
    k->key_ops_verify = 1;
    k->declared_alg   = ALG_RS256;
    k->key_material     = NULL;
    k->key_material_len = 0;

    jwks_t *j = (jwks_t *)arena_alloc(arena, sizeof(jwks_t), _Alignof(jwks_t));
    if (!j) return NULL;
    j->keys  = k;
    j->count = 1;
    return j;
}

static policy_t *make_base_policy(policy_builder_t *pb)
{
    policy_builder_environment(pb, ENV_PROD);
    policy_builder_issuer_exact(pb, "https://auth.example.com");
    policy_builder_audience_exact(pb, "payments-api");
    policy_builder_algorithm(pb, ALG_RS256);
    policy_builder_require_claims(pb,
        CLAIM_EXP | CLAIM_ISS | CLAIM_AUD | CLAIM_IAT);
    policy_builder_max_ttl(pb, 3600);
    policy_builder_require_kid(pb, 1);
    return policy_builder_build(pb);
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
 * TEST: TL-V022 TOKEN_EXPIRED — exp in the past
 * ========================================================================= */

TEST(validate_fail_TL_V022_fires)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_t *policy = make_base_policy(&pb);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_RS256);
    token_builder_kid(&tb, "key-1");
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_single(&tb, "payments-api");
    token_builder_exp(&tb, PAST_EXP);   /* expired */
    token_builder_iat(&tb, REFTIME - 3600);
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-V022"));

    arena_free(arena);
}

TEST(validate_fail_TL_V022_no_fire)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_t *policy = make_base_policy(&pb);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_RS256);
    token_builder_kid(&tb, "key-1");
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_single(&tb, "payments-api");
    token_builder_exp(&tb, VALID_EXP);   /* not expired */
    token_builder_iat(&tb, VALID_IAT);
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_FALSE(has_active(&fs, "TL-V022"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: TL-V023 TOKEN_NOT_YET_VALID — nbf in the future
 * ========================================================================= */

TEST(validate_fail_TL_V023_fires)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_t *policy = make_base_policy(&pb);
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
    token_builder_nbf(&tb, FUTURE_NBF);   /* not valid yet — well past clock_skew */
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-V023"));

    arena_free(arena);
}

TEST(validate_fail_TL_V023_no_fire)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_builder_t pb = policy_builder_new(arena);
    policy_t *policy = make_base_policy(&pb);
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
    token_builder_nbf(&tb, REFTIME - 60);  /* already valid — no TL-V023 */
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_FALSE(has_active(&fs, "TL-V023"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: TL-V003 TOKEN_ALG_NOT_ALLOWED — alg not in policy
 * ========================================================================= */

TEST(validate_fail_TL_V003_fires)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    /* Policy only allows RS256 */
    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "payments-api");
    policy_builder_algorithm(&pb, ALG_RS256);
    policy_builder_require_claims(&pb, CLAIM_EXP | CLAIM_ISS | CLAIM_AUD);
    policy_builder_max_ttl(&pb, 3600);
    policy_builder_require_kid(&pb, 1);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    /* Token claims ES256 — not in policy */
    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_ES256);
    token_builder_kid(&tb, "key-1");
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_single(&tb, "payments-api");
    token_builder_exp(&tb, VALID_EXP);
    token_builder_iat(&tb, VALID_IAT);
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-V003"));

    arena_free(arena);
}

TEST(validate_fail_TL_V003_no_fire)
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
    policy_builder_require_kid(&pb, 1);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    /* Token claims RS256 — matching policy */
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
    ASSERT_FALSE(has_active(&fs, "TL-V003"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: TL-V009 TOKEN_KID_ABSENT_STRICT — require_kid: true, no kid in token
 * ========================================================================= */

TEST(validate_fail_TL_V009_fires)
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
    policy_builder_require_kid(&pb, 1);  /* strict */
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    /* Token has no kid */
    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_RS256);
    /* No kid set — STR_NULL */
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_single(&tb, "payments-api");
    token_builder_exp(&tb, VALID_EXP);
    token_builder_iat(&tb, VALID_IAT);
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-V009"));

    arena_free(arena);
}

TEST(validate_fail_TL_V009_no_fire)
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
    policy_builder_require_kid(&pb, 1);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    /* Token has kid — no TL-V009 */
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
    ASSERT_FALSE(has_active(&fs, "TL-V009"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: TL-V010 TOKEN_KID_NO_MATCH — kid in token but not in JWKS
 * ========================================================================= */

TEST(validate_fail_TL_V010_fires)
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
    policy_builder_require_kid(&pb, 1);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");  /* key-1 in JWKS */
    ASSERT_NOT_NULL(jwks);

    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_RS256);
    token_builder_kid(&tb, "key-99");   /* different kid — no match */
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_single(&tb, "payments-api");
    token_builder_exp(&tb, VALID_EXP);
    token_builder_iat(&tb, VALID_IAT);
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-V010"));

    arena_free(arena);
}

TEST(validate_fail_TL_V010_no_fire)
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
    policy_builder_require_kid(&pb, 1);
    policy_t *policy = policy_builder_build(&pb);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_RS256);
    token_builder_kid(&tb, "key-1");   /* matching kid */
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_single(&tb, "payments-api");
    token_builder_exp(&tb, VALID_EXP);
    token_builder_iat(&tb, VALID_IAT);
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_FALSE(has_active(&fs, "TL-V010"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: TL-V025 TOKEN_TTL_EXCEEDED — exp - iat exceeds max_ttl
 * ========================================================================= */

TEST(validate_fail_TL_V025_fires)
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
    policy_builder_require_claims(&pb,
        CLAIM_EXP | CLAIM_ISS | CLAIM_AUD | CLAIM_IAT);
    policy_builder_max_ttl(&pb, 3600);   /* 1 hour limit */
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
    token_builder_iat(&tb, VALID_IAT);
    token_builder_exp(&tb, VALID_IAT + 7200);  /* 2hr TTL > 1hr limit */
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-V025"));

    arena_free(arena);
}

TEST(validate_fail_TL_V025_no_fire)
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
    policy_builder_require_claims(&pb,
        CLAIM_EXP | CLAIM_ISS | CLAIM_AUD | CLAIM_IAT);
    policy_builder_max_ttl(&pb, 3600);
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
    token_builder_iat(&tb, VALID_IAT);
    token_builder_exp(&tb, VALID_IAT + 1800);  /* 30 min — within 1hr */
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_FALSE(has_active(&fs, "TL-V025"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: TL-V020 IAT_ABSENT_TTL_UNVERIFIABLE — iat absent, max_ttl set
 * ========================================================================= */

TEST(validate_fail_TL_V020_fires)
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
    policy_builder_max_ttl(&pb, 3600);   /* TTL set */
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
    /* NO iat — TL-V020 should fire */
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-V020"));

    arena_free(arena);
}

TEST(validate_fail_TL_V020_no_fire)
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
    policy_builder_max_ttl(&pb, 3600);
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
    token_builder_iat(&tb, VALID_IAT);  /* iat present */
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_FALSE(has_active(&fs, "TL-V020"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: TL-V024 TOKEN_TTL_INVALID — exp - iat <= 0
 * ========================================================================= */

TEST(validate_fail_TL_V024_fires)
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
    policy_builder_require_claims(&pb,
        CLAIM_EXP | CLAIM_ISS | CLAIM_AUD | CLAIM_IAT);
    policy_builder_max_ttl(&pb, 3600);
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
    token_builder_iat(&tb, VALID_IAT + 1000);
    token_builder_exp(&tb, VALID_IAT);   /* exp <= iat → invalid TTL */
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_TRUE(has_active(&fs, "TL-V024"));

    arena_free(arena);
}

TEST(validate_fail_TL_V024_no_fire)
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
    policy_builder_require_claims(&pb,
        CLAIM_EXP | CLAIM_ISS | CLAIM_AUD | CLAIM_IAT);
    policy_builder_max_ttl(&pb, 3600);
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
    token_builder_iat(&tb, VALID_IAT);
    token_builder_exp(&tb, VALID_IAT + 1800);  /* valid TTL */
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    run_validate_on(policy, jwks, token, &fs, arena);
    ASSERT_FALSE(has_active(&fs, "TL-V024"));

    arena_free(arena);
}


/* =========================================================================
 * TEST_MAIN
 * ========================================================================= */

TEST_MAIN(
    tl_run_validate_fail_TL_V022_fires,
    tl_run_validate_fail_TL_V022_no_fire,
    tl_run_validate_fail_TL_V023_fires,
    tl_run_validate_fail_TL_V023_no_fire,
    tl_run_validate_fail_TL_V003_fires,
    tl_run_validate_fail_TL_V003_no_fire,
    tl_run_validate_fail_TL_V009_fires,
    tl_run_validate_fail_TL_V009_no_fire,
    tl_run_validate_fail_TL_V010_fires,
    tl_run_validate_fail_TL_V010_no_fire,
    tl_run_validate_fail_TL_V025_fires,
    tl_run_validate_fail_TL_V025_no_fire,
    tl_run_validate_fail_TL_V020_fires,
    tl_run_validate_fail_TL_V020_no_fire,
    tl_run_validate_fail_TL_V024_fires,
    tl_run_validate_fail_TL_V024_no_fire,
)
