/*
 * tests/unit/test_policy_parser.c
 *
 * Unit tests for src/parse/policy_parser.c.
 */

#include "helpers/test_runner.h"
#include "tokenlint.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"

#include <string.h>
#include <unistd.h>

/* ── fixture paths ───────────────────────────────────────────────────────── */

#define FIX_VALID(name)   "tests/fixtures/policies/valid/"   name
#define FIX_INVALID(name) "tests/fixtures/policies/invalid/" name

/* ── helpers ─────────────────────────────────────────────────────────────── */

static finding_t *find_by_id(finding_set_t *fs, const char *id) {
    for (size_t i = 0; i < fs->count; i++)
        if (str_eq(fs->findings[i].id, str_from_cstr(id)))
            return &fs->findings[i];
    return NULL;
}

static int count_by_id(finding_set_t *fs, const char *id) {
    int n = 0;
    for (size_t i = 0; i < fs->count; i++)
        if (str_eq(fs->findings[i].id, str_from_cstr(id))) n++;
    return n;
}

/* ── happy path tests ────────────────────────────────────────────────────── */

TEST(parse_minimal_valid) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena, FIX_VALID("minimal.yaml"), &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(pol);

    /* schema_version */
    ASSERT_TRUE(str_eq(pol->schema_version, STR_LIT("tokenlint.validator.v1")));

    /* validator */
    ASSERT_TRUE(str_eq(pol->validator_id, STR_LIT("test-api")));
    ASSERT_EQ(pol->environment, ENV_PROD);

    /* issuers */
    ASSERT_EQ(pol->issuers.mode, ISSUER_MODE_EXACT);
    ASSERT_EQ((int)pol->issuers.count, 1);
    ASSERT_TRUE(str_eq(pol->issuers.values[0], STR_LIT("https://auth.example.com")));

    /* audiences */
    ASSERT_EQ(pol->audiences.mode, AUDIENCE_MODE_EXACT);
    ASSERT_EQ((int)pol->audiences.count, 1);
    ASSERT_TRUE(str_eq(pol->audiences.values[0], STR_LIT("test-api")));

    /* algorithms */
    ASSERT_TRUE(ALLOWSET_CONTAINS(pol->algorithms, ALG_RS256));
    ASSERT_FALSE(ALLOWSET_CONTAINS(pol->algorithms, ALG_ES256));

    /* jwks */
    ASSERT_TRUE(str_eq(pol->jwks_policy.source, STR_LIT("./keys.json")));
    ASSERT_EQ(pol->jwks_policy.require_kid, 1);

    /* requires.claims */
    ASSERT_TRUE(!!(pol->required_registered_claims & CLAIM_ISS));
    ASSERT_TRUE(!!(pol->required_registered_claims & CLAIM_AUD));
    ASSERT_TRUE(!!(pol->required_registered_claims & CLAIM_EXP));
    ASSERT_TRUE(!!(pol->required_registered_claims & CLAIM_IAT));
    ASSERT_TRUE(!!(pol->required_registered_claims & CLAIM_SUB));

    /* limits */
    ASSERT_EQ(pol->time_limits.max_ttl_seconds, 3600LL);
    ASSERT_EQ(pol->time_limits.max_clock_skew_seconds, 60LL);

    arena_free(arena);
}

TEST(parse_full_valid) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena, FIX_VALID("full.yaml"), &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(pol);

    ASSERT_EQ(pol->environment, ENV_STAGE);
    ASSERT_EQ((int)pol->issuers.count, 2);
    ASSERT_TRUE(ALLOWSET_CONTAINS(pol->algorithms, ALG_RS256));
    ASSERT_TRUE(ALLOWSET_CONTAINS(pol->algorithms, ALG_PS256));
    ASSERT_TRUE(ALLOWSET_CONTAINS(pol->algorithms, ALG_ES256));
    ASSERT_EQ(pol->jwks_policy.require_kid, 0);
    ASSERT_EQ(pol->time_limits.max_ttl_seconds, 1800LL);
    ASSERT_EQ(pol->time_limits.max_clock_skew_seconds, 30LL);

    /* claim_rules */
    ASSERT_EQ((int)pol->claim_rule_count, 1);
    ASSERT_TRUE(str_eq(pol->claim_rules[0].claim, STR_LIT("scope")));
    ASSERT_EQ(pol->claim_rules[0].op, CLAIM_OP_DENY_ANY);
    ASSERT_EQ(pol->claim_rules[0].required, 1);
    ASSERT_EQ((int)pol->claim_rules[0].value_count, 2);

    arena_free(arena);
}

TEST(parse_dev_env_hs256_allowed) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena, FIX_VALID("dev.yaml"), &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(pol);
    ASSERT_EQ(pol->environment, ENV_DEV);
    ASSERT_TRUE(ALLOWSET_CONTAINS(pol->algorithms, ALG_HS256));

    /* TL-A005 should NOT fire in dev */
    ASSERT_NULL(find_by_id(&fs, "TL-A005"));

    arena_free(arena);
}

TEST(parse_issuer_trailing_slash_normalized) {
    /* The minimal.yaml issuer has no trailing slash; full.yaml also doesn't.
     * We verify the normalization path doesn't corrupt clean values. */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena, FIX_VALID("minimal.yaml"), &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    /* No trailing slash on the result */
    str_t issuer = pol->issuers.values[0];
    ASSERT_TRUE(issuer.len > 0);
    ASSERT_NE((int)issuer.data[issuer.len - 1], (int)'/');

    arena_free(arena);
}

TEST(parse_ttl_absent_emits_a007) {
    /* dev.yaml has max_ttl_seconds set, so it won't fire.
     * Create inline policy without limits by using full.yaml which does have it.
     * Instead we write a temp file without limits. */

    /* Write a temp file */
    FILE *tmp = tmpfile();
    ASSERT_NOT_NULL(tmp);
    const char *yaml =
        "schema_version: tokenlint.validator.v1\n"
        "validator:\n  id: x\n  environment: stage\n"
        "accepts:\n  token_types:\n    - jwt\n"
        "  issuers:\n    mode: exact\n    values:\n      - https://x.com\n"
        "  audiences:\n    mode: exact\n    values:\n      - x\n"
        "  algorithms:\n    - RS256\n"
        "jwks:\n  source: ./k.json\n"
        "requires:\n  claims:\n    - iss\n    - aud\n    - exp\n";
    fputs(yaml, tmp);
    rewind(tmp);

    /* Can't use tmpfile() path directly — write to a named temp */
    char tmppath[] = "/tmp/tl_test_XXXXXX.yaml";
    int fd = mkstemps(tmppath, 5);
    ASSERT_NE(fd, -1);
    FILE *tf = fdopen(fd, "w");
    fputs(yaml, tf);
    fclose(tf);

    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena, tmppath, &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(pol);

    /* TL-A007 must fire */
    ASSERT_NOT_NULL(find_by_id(&fs, "TL-A007"));

    unlink(tmppath);
    arena_free(arena);
}

/* ── error path tests ────────────────────────────────────────────────────── */

TEST(parse_missing_schema_version_fails) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena,
        FIX_INVALID("no_schema_version.yaml"), &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_SCHEMA);
    ASSERT_NULL(pol);

    arena_free(arena);
}

TEST(parse_alg_none_in_policy_fails) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena,
        FIX_INVALID("alg_none.yaml"), &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_SCHEMA);
    ASSERT_NULL(pol);

    finding_t *f = find_by_id(&fs, "TL-S002");
    ASSERT_NOT_NULL(f);
    ASSERT_EQ(f->severity, SEV_CRITICAL);

    arena_free(arena);
}

TEST(parse_jwks_url_fails_s011) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena,
        FIX_INVALID("jwks_url.yaml"), &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_SCHEMA);
    ASSERT_NULL(pol);

    finding_t *f = find_by_id(&fs, "TL-S011");
    ASSERT_NOT_NULL(f);

    arena_free(arena);
}

TEST(parse_invalid_environment_fails_s004) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena,
        FIX_INVALID("bad_env.yaml"), &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_SCHEMA);
    ASSERT_NULL(pol);

    finding_t *f = find_by_id(&fs, "TL-S004");
    ASSERT_NOT_NULL(f);

    arena_free(arena);
}

TEST(parse_bad_issuer_mode_fails_s008) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena,
        FIX_INVALID("bad_issuer_mode.yaml"), &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_SCHEMA);
    ASSERT_NULL(pol);

    finding_t *f = find_by_id(&fs, "TL-S008");
    ASSERT_NOT_NULL(f);

    arena_free(arena);
}

TEST(parse_negative_ttl_fails_s003) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena,
        FIX_INVALID("negative_ttl.yaml"), &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_SCHEMA);
    ASSERT_NULL(pol);

    finding_t *f = find_by_id(&fs, "TL-S003");
    ASSERT_NOT_NULL(f);

    arena_free(arena);
}

TEST(parse_nonexistent_file_returns_io_error) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena, "/nonexistent/path.yaml", &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_IO);
    ASSERT_NULL(pol);

    arena_free(arena);
}

TEST(parse_required_claims_a014) {
    /* Write policy missing exp from requires.claims */
    char tmppath[] = "/tmp/tl_test_XXXXXX.yaml";
    int fd = mkstemps(tmppath, 5);
    ASSERT_NE(fd, -1);
    FILE *tf = fdopen(fd, "w");
    fputs(
        "schema_version: tokenlint.validator.v1\n"
        "validator:\n  id: x\n  environment: stage\n"
        "accepts:\n  token_types:\n    - jwt\n"
        "  issuers:\n    mode: exact\n    values:\n      - https://x.com\n"
        "  audiences:\n    mode: exact\n    values:\n      - x\n"
        "  algorithms:\n    - RS256\n"
        "jwks:\n  source: ./k.json\n"
        "requires:\n  claims:\n    - iss\n    - aud\n"  /* no exp! */
        "limits:\n  max_ttl_seconds: 3600\n",
        tf
    );
    fclose(tf);

    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena, tmppath, &fs, &pol);
    /* TL-A014 is non-halt — parse still succeeds */
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(pol);

    /* Must have TL-A014 for exp */
    ASSERT_GE(count_by_id(&fs, "TL-A014"), 1);

    unlink(tmppath);
    arena_free(arena);
}

TEST(parse_hs256_in_prod_emits_a005) {
    char tmppath[] = "/tmp/tl_test_XXXXXX.yaml";
    int fd = mkstemps(tmppath, 5);
    ASSERT_NE(fd, -1);
    FILE *tf = fdopen(fd, "w");
    fputs(
        "schema_version: tokenlint.validator.v1\n"
        "validator:\n  id: x\n  environment: prod\n"
        "accepts:\n  token_types:\n    - jwt\n"
        "  issuers:\n    mode: exact\n    values:\n      - https://x.com\n"
        "  audiences:\n    mode: exact\n    values:\n      - x\n"
        "  algorithms:\n    - HS256\n"
        "jwks:\n  source: ./k.json\n"
        "requires:\n  claims:\n    - iss\n    - aud\n    - exp\n"
        "limits:\n  max_ttl_seconds: 3600\n",
        tf
    );
    fclose(tf);

    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    /* Parser completes (TL-A005 is non-halt) */
    tl_error_t err = policy_parse(arena, tmppath, &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(pol);

    finding_t *f = find_by_id(&fs, "TL-A005");
    ASSERT_NOT_NULL(f);
    ASSERT_EQ(f->severity, SEV_CRITICAL);

    unlink(tmppath);
    arena_free(arena);
}

/* ── security properties ─────────────────────────────────────────────────── */

SECURITY_PROP(alg_none_in_policy_always_fails) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena,
        FIX_INVALID("alg_none.yaml"), &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_SCHEMA);
    ASSERT_NULL(pol);

    /* TL-S002 is non-suppressible */
    finding_t *f = find_by_id(&fs, "TL-S002");
    ASSERT_NOT_NULL(f);
    ASSERT_EQ(f->severity, SEV_CRITICAL);
    ASSERT_EQ(f->status, FINDING_ACTIVE);

    arena_free(arena);
}

SECURITY_PROP(jwks_url_source_always_fails) {
    /* Remote JWKS must never be accepted in v1 */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    policy_t *pol = NULL;

    tl_error_t err = policy_parse(arena,
        FIX_INVALID("jwks_url.yaml"), &fs, &pol);
    ASSERT_EQ(err.kind, TL_ERR_SCHEMA);
    ASSERT_NULL(pol);

    finding_t *f = find_by_id(&fs, "TL-S011");
    ASSERT_NOT_NULL(f);

    arena_free(arena);
}

/* ── main ────────────────────────────────────────────────────────────────── */

TEST_MAIN(
    tl_run_parse_minimal_valid,
    tl_run_parse_full_valid,
    tl_run_parse_dev_env_hs256_allowed,
    tl_run_parse_issuer_trailing_slash_normalized,
    tl_run_parse_ttl_absent_emits_a007,
    tl_run_parse_missing_schema_version_fails,
    tl_run_parse_alg_none_in_policy_fails,
    tl_run_parse_jwks_url_fails_s011,
    tl_run_parse_invalid_environment_fails_s004,
    tl_run_parse_bad_issuer_mode_fails_s008,
    tl_run_parse_negative_ttl_fails_s003,
    tl_run_parse_nonexistent_file_returns_io_error,
    tl_run_parse_required_claims_a014,
    tl_run_parse_hs256_in_prod_emits_a005,
    tl_run_alg_none_in_policy_always_fails,
    tl_run_jwks_url_source_always_fails,
)
