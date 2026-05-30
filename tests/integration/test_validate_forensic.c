/*
 * tests/integration/test_validate_forensic.c
 *
 * Integration tests: --at flag / reference_time forensic scenarios.
 *
 * Verifies:
 *   - --at past time → expired token passes (was valid at that past time)
 *   - --at future time → non-yet-valid token passes
 *   - Two runs at the same --at produce the same finding set (determinism)
 *   - reference_time_source reflects how the time was resolved
 *
 * Uses token_builder + policy_builder; no parsers involved.
 * tl_cli_resolve_reftime() is exercised for the --at path.
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
#include "time_util.h"
#include "cli.h"

#include <string.h>
#include <stddef.h>
#include <stdint.h>


/* =========================================================================
 * Constants
 * ========================================================================= */

/* A fixed point in the past: 2020-01-01T00:00:00Z */
#define AT_PAST   ((int64_t)1577836800)
/* A fixed point in the future (relative to most test environments) */
#define AT_FUTURE ((int64_t)9999999999LL)
/* Our standard reference time */
#define REFTIME   ((int64_t)1700000000)


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

static void run_validate_at(const policy_t *policy,
                             const jwks_t   *jwks,
                             const token_t  *token,
                             int64_t         reference_time,
                             reftime_source_t source,
                             finding_set_t   *fs,
                             arena_t         *arena)
{
    eval_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.policy                = policy;
    ctx.jwks                  = jwks;
    ctx.token                 = token;
    ctx.findings              = fs;
    ctx.arena                 = arena;
    ctx.reference_time        = reference_time;
    ctx.reference_time_source = source;
    eval_validate(&ctx);
}

static policy_t *make_base_policy(arena_t *arena)
{
    policy_builder_t pb = policy_builder_new(arena);
    policy_builder_environment(&pb, ENV_PROD);
    policy_builder_issuer_exact(&pb, "https://auth.example.com");
    policy_builder_audience_exact(&pb, "payments-api");
    policy_builder_algorithm(&pb, ALG_RS256);
    policy_builder_require_claims(&pb,
        CLAIM_EXP | CLAIM_ISS | CLAIM_AUD | CLAIM_IAT);
    policy_builder_max_ttl(&pb, 3600);
    policy_builder_require_kid(&pb, 1);
    return policy_builder_build(&pb);
}


/* =========================================================================
 * TEST: --at past time → token that has since expired passes exp check
 *
 * Token: iat=AT_PAST, exp=AT_PAST+3600 (was valid at AT_PAST)
 * Run with reference_time = AT_PAST + 1800 (half-way through its life)
 * → TL-V022 must NOT fire
 * ========================================================================= */

TEST(forensic_at_past_token_not_expired)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t *policy = make_base_policy(arena);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    /* Token was valid at AT_PAST but has since expired in real time */
    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_RS256);
    token_builder_kid(&tb, "key-1");
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_single(&tb, "payments-api");
    token_builder_iat(&tb, AT_PAST);
    token_builder_exp(&tb, AT_PAST + 3600);
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    /* Run at half-way through its valid lifetime */
    run_validate_at(policy, jwks, token,
                    AT_PAST + 1800, REFTIME_CLI_AT, &fs, arena);

    ASSERT_FALSE(has_active(&fs, "TL-V022"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: --at past time → token expired at that past time fires TL-V022
 * ========================================================================= */

TEST(forensic_at_past_token_expired_at_past)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t *policy = make_base_policy(arena);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    /* Token expired at AT_PAST - 1 */
    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_RS256);
    token_builder_kid(&tb, "key-1");
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_single(&tb, "payments-api");
    token_builder_iat(&tb, AT_PAST - 3600);
    token_builder_exp(&tb, AT_PAST - 1);  /* expired before our --at point */
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    /* Run at AT_PAST: token was already expired */
    run_validate_at(policy, jwks, token,
                    AT_PAST, REFTIME_CLI_AT, &fs, arena);

    ASSERT_TRUE(has_active(&fs, "TL-V022"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: --at future time → nbf in the future does NOT fire TL-V023
 * ========================================================================= */

TEST(forensic_at_future_nbf_valid)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    policy_t *policy = make_base_policy(arena);
    ASSERT_NOT_NULL(policy);

    jwks_t *jwks = make_jwks_rs256(arena, "key-1");
    ASSERT_NOT_NULL(jwks);

    /* Token has nbf=AT_FUTURE+100; exp=AT_FUTURE+3600 */
    token_builder_t tb = token_builder_new(arena);
    token_builder_alg(&tb, ALG_RS256);
    token_builder_kid(&tb, "key-1");
    token_builder_iss(&tb, "https://auth.example.com");
    token_builder_aud_single(&tb, "payments-api");
    token_builder_iat(&tb, AT_FUTURE);
    token_builder_nbf(&tb, AT_FUTURE + 100);
    token_builder_exp(&tb, AT_FUTURE + 3600);
    token_t *token = token_builder_build(&tb);
    ASSERT_NOT_NULL(token);

    /* Run at AT_FUTURE + 200 → nbf has passed, exp still in the future */
    run_validate_at(policy, jwks, token,
                    AT_FUTURE + 200, REFTIME_CLI_AT, &fs, arena);

    ASSERT_FALSE(has_active(&fs, "TL-V023"));
    ASSERT_FALSE(has_active(&fs, "TL-V022"));

    arena_free(arena);
}


/* =========================================================================
 * TEST: determinism — same inputs at same --at produce identical finding set
 * ========================================================================= */

TEST(forensic_deterministic_output)
{
    /* Run the same token+policy twice at the same reference_time.
     * The finding sets must be identical (same count, same IDs, same statuses). */

    const int64_t fixed_at = 1700000500LL;

    /* Run 1 */
    arena_t *a1 = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(a1);
    finding_set_t fs1;
    findings_init(&fs1);

    policy_t *p1 = make_base_policy(a1);
    jwks_t   *j1 = make_jwks_rs256(a1, "key-1");

    token_builder_t tb1 = token_builder_new(a1);
    token_builder_alg(&tb1, ALG_RS256);
    token_builder_kid(&tb1, "key-1");
    token_builder_iss(&tb1, "https://auth.example.com");
    token_builder_aud_single(&tb1, "payments-api");
    token_builder_iat(&tb1, fixed_at - 300);
    token_builder_exp(&tb1, fixed_at + 3300);
    token_t *t1 = token_builder_build(&tb1);

    run_validate_at(p1, j1, t1, fixed_at, REFTIME_CLI_AT, &fs1, a1);

    /* Run 2 — fresh arena, identical inputs */
    arena_t *a2 = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(a2);
    finding_set_t fs2;
    findings_init(&fs2);

    policy_t *p2 = make_base_policy(a2);
    jwks_t   *j2 = make_jwks_rs256(a2, "key-1");

    token_builder_t tb2 = token_builder_new(a2);
    token_builder_alg(&tb2, ALG_RS256);
    token_builder_kid(&tb2, "key-1");
    token_builder_iss(&tb2, "https://auth.example.com");
    token_builder_aud_single(&tb2, "payments-api");
    token_builder_iat(&tb2, fixed_at - 300);
    token_builder_exp(&tb2, fixed_at + 3300);
    token_t *t2 = token_builder_build(&tb2);

    run_validate_at(p2, j2, t2, fixed_at, REFTIME_CLI_AT, &fs2, a2);

    /* Compare counts */
    ASSERT_EQ(fs1.count, fs2.count);

    /* Compare each finding's id and status */
    for (size_t i = 0; i < fs1.count; i++) {
        ASSERT_TRUE(str_eq(fs1.findings[i].id, fs2.findings[i].id));
        ASSERT_EQ((int)fs1.findings[i].status, (int)fs2.findings[i].status);
        ASSERT_EQ((int)fs1.findings[i].severity, (int)fs2.findings[i].severity);
    }

    arena_free(a1);
    arena_free(a2);
}


/* =========================================================================
 * TEST: tl_cli_resolve_reftime with --at unix string
 * ========================================================================= */

TEST(forensic_resolve_reftime_unix)
{
    tl_cli_opts_t opts;
    tl_cli_opts_init(&opts);
    opts.at_str = "1700000000";

    tl_reference_time_t rt;
    tl_error_t err = tl_cli_resolve_reftime(&opts, &rt);

    ASSERT_TRUE(tl_ok(err));
    ASSERT_EQ(rt.value, (int64_t)1700000000);
    ASSERT_EQ((int)rt.source, (int)TL_TIME_SRC_CLI_AT);
}


/* =========================================================================
 * TEST: tl_cli_resolve_reftime with "now" → system clock source
 * ========================================================================= */

TEST(forensic_resolve_reftime_now)
{
    tl_cli_opts_t opts;
    tl_cli_opts_init(&opts);
    opts.at_str = "now";

    tl_reference_time_t rt;
    tl_error_t err = tl_cli_resolve_reftime(&opts, &rt);

    ASSERT_TRUE(tl_ok(err));
    ASSERT_GT(rt.value, (int64_t)0);
    ASSERT_EQ((int)rt.source, (int)TL_TIME_SRC_CLI_AT_NOW);
}


/* =========================================================================
 * TEST: tl_cli_resolve_reftime absent --at → system clock
 * ========================================================================= */

TEST(forensic_resolve_reftime_system_clock)
{
    tl_cli_opts_t opts;
    tl_cli_opts_init(&opts);
    opts.at_str = NULL;

    tl_reference_time_t rt;
    tl_error_t err = tl_cli_resolve_reftime(&opts, &rt);

    ASSERT_TRUE(tl_ok(err));
    ASSERT_GT(rt.value, (int64_t)0);
    ASSERT_EQ((int)rt.source, (int)TL_TIME_SRC_SYSTEM_CLOCK);
}


/* =========================================================================
 * TEST: tl_cli_resolve_reftime with invalid --at → TL_ERR_AT_FLAG
 * ========================================================================= */

TEST(forensic_resolve_reftime_invalid)
{
    tl_cli_opts_t opts;
    tl_cli_opts_init(&opts);
    opts.at_str = "not-a-timestamp";

    tl_reference_time_t rt;
    tl_error_t err = tl_cli_resolve_reftime(&opts, &rt);

    ASSERT_FALSE(tl_ok(err));
    ASSERT_EQ((int)err.kind, (int)TL_ERR_AT_FLAG);
}


/* =========================================================================
 * TEST_MAIN
 * ========================================================================= */

TEST_MAIN(
    tl_run_forensic_at_past_token_not_expired,
    tl_run_forensic_at_past_token_expired_at_past,
    tl_run_forensic_at_future_nbf_valid,
    tl_run_forensic_deterministic_output,
    tl_run_forensic_resolve_reftime_unix,
    tl_run_forensic_resolve_reftime_now,
    tl_run_forensic_resolve_reftime_system_clock,
    tl_run_forensic_resolve_reftime_invalid,
)
