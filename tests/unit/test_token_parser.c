/*
 * tests/unit/test_token_parser.c
 *
 * Unit tests for src/parse/token_parser.c.
 */

#include "helpers/test_runner.h"
#include "tokenlint.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"
#include "token.h"

#include <string.h>

/* ── fixtures ────────────────────────────────────────────────────────────── */

/* RS256 with all registered claims and kid */
#define JWT_FULL \
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEifQ" \
    ".eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyMSIsImF1ZCI6ImFwaSIsImV4cCI6OTk5OTk5OTk5OSwibmJmIjoxMDAwMDAwMDAwLCJpYXQiOjE3MDAwMDAwMDAsImp0aSI6InRvazEifQ" \
    ".ZmFrZXNpZw"

/* ES256 with aud as array, no kid */
#define JWT_AUD_ARR \
    "eyJhbGciOiJFUzI1NiJ9" \
    ".eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1MiIsImF1ZCI6WyJhcGkxIiwiYXBpMiJdLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTcwMDAwMDAwMH0" \
    ".ZmFrZXNpZw"

/* alg=none — compact (empty sig) */
#define JWT_NONE "eyJhbGciOiJub25lIn0.eyJzdWIiOiJldmlsIn0."

/* header without alg field */
#define JWT_NO_ALG "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ1In0.ZmFrZXNpZw"

/* unknown alg string XYZ256 */
#define JWT_UNK_ALG "eyJhbGciOiJYWVoyNTYifQ.eyJzdWIiOiJ1In0.ZmFrZXNpZw"

/* EdDSA with kid */
#define JWT_EDDSA \
    "eyJhbGciOiJFZERTQSIsImtpZCI6ImVkMSJ9" \
    ".eyJpc3MiOiJodHRwczovL3guY29tIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDB9" \
    ".ZmFrZXNpZw"

/* ── helper ──────────────────────────────────────────────────────────────── */

static finding_t *find_by_id(finding_set_t *fs, const char *id) {
    for (size_t i = 0; i < fs->count; i++) {
        if (str_eq(fs->findings[i].id, str_from_cstr(id)))
            return &fs->findings[i];
    }
    return NULL;
}

/* ── tests ───────────────────────────────────────────────────────────────── */

TEST(parse_full_token) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    token_t *tok = NULL;

    tl_error_t err = token_parse(arena, STR_LIT(JWT_FULL), &fs, &tok);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(tok);
    ASSERT_EQ((int)fs.count, 0);

    ASSERT_EQ(tok->alg, ALG_RS256);
    ASSERT_TRUE(str_eq(tok->kid, STR_LIT("key1")));
    ASSERT_TRUE(str_eq(tok->iss, STR_LIT("https://auth.example.com")));
    ASSERT_TRUE(str_eq(tok->sub, STR_LIT("user1")));
    ASSERT_EQ((int)tok->aud_count, 1);
    ASSERT_TRUE(str_eq(tok->aud[0], STR_LIT("api")));
    ASSERT_EQ(tok->exp, 9999999999LL);
    ASSERT_EQ(tok->nbf, 1000000000LL);
    ASSERT_EQ(tok->iat, 1700000000LL);
    ASSERT_TRUE(str_eq(tok->jti, STR_LIT("tok1")));

    uint32_t want = CLAIM_ISS|CLAIM_SUB|CLAIM_AUD|CLAIM_EXP|CLAIM_NBF|CLAIM_IAT|CLAIM_JTI;
    ASSERT_EQ((int)tok->present_claims, (int)want);

    /* signing_input contains exactly one dot */
    ASSERT_NOT_NULL(tok->signing_input);
    ASSERT_GT((int)tok->signing_input_len, 0);
    int dots = 0;
    for (size_t i = 0; i < tok->signing_input_len; i++)
        if (tok->signing_input[i] == '.') dots++;
    ASSERT_EQ(dots, 1);

    ASSERT_NOT_NULL(tok->sig);
    ASSERT_GT((int)tok->sig_len, 0);

    arena_free(arena);
}

TEST(parse_aud_array) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    token_t *tok = NULL;

    tl_error_t err = token_parse(arena, STR_LIT(JWT_AUD_ARR), &fs, &tok);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(tok);

    ASSERT_EQ(tok->alg, ALG_ES256);
    ASSERT_EQ((int)tok->aud_count, 2);
    ASSERT_TRUE(str_eq(tok->aud[0], STR_LIT("api1")));
    ASSERT_TRUE(str_eq(tok->aud[1], STR_LIT("api2")));
    ASSERT_TRUE(!!(tok->present_claims & CLAIM_AUD));
    ASSERT_TRUE(STR_IS_NULL(tok->kid));

    arena_free(arena);
}

TEST(parse_eddsa) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    token_t *tok = NULL;

    tl_error_t err = token_parse(arena, STR_LIT(JWT_EDDSA), &fs, &tok);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(tok);
    ASSERT_EQ(tok->alg, ALG_ECDSA_EDDSA);
    ASSERT_TRUE(str_eq(tok->kid, STR_LIT("ed1")));

    arena_free(arena);
}

TEST(alg_none_halts_with_s001) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    token_t *tok = NULL;

    tl_error_t err = token_parse(arena, STR_LIT(JWT_NONE), &fs, &tok);
    ASSERT_EQ(err.kind, TL_ERR_TOKEN);
    ASSERT_NULL(tok);

    finding_t *f = find_by_id(&fs, "TL-S001");
    ASSERT_NOT_NULL(f);
    ASSERT_EQ(f->severity, SEV_CRITICAL);

    arena_free(arena);
}

TEST(alg_absent_halts_with_v001) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    token_t *tok = NULL;

    tl_error_t err = token_parse(arena, STR_LIT(JWT_NO_ALG), &fs, &tok);
    ASSERT_EQ(err.kind, TL_ERR_TOKEN);
    ASSERT_NULL(tok);

    finding_t *f = find_by_id(&fs, "TL-V001");
    ASSERT_NOT_NULL(f);
    ASSERT_EQ(f->severity, SEV_FAIL);

    arena_free(arena);
}

TEST(alg_unrecognized_halts_with_v002) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    token_t *tok = NULL;

    tl_error_t err = token_parse(arena, STR_LIT(JWT_UNK_ALG), &fs, &tok);
    ASSERT_EQ(err.kind, TL_ERR_TOKEN);
    ASSERT_NULL(tok);

    finding_t *f = find_by_id(&fs, "TL-V002");
    ASSERT_NOT_NULL(f);

    arena_free(arena);
}

TEST(empty_jwt_fails_v000) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    token_t *tok = NULL;

    tl_error_t err = token_parse(arena, STR_NULL, &fs, &tok);
    ASSERT_EQ(err.kind, TL_ERR_TOKEN);
    ASSERT_NULL(tok);
    ASSERT_NOT_NULL(find_by_id(&fs, "TL-V000"));

    arena_free(arena);
}

TEST(two_part_jwt_fails_v000) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    token_t *tok = NULL;

    tl_error_t err = token_parse(arena, STR_LIT("header.payload"), &fs, &tok);
    ASSERT_EQ(err.kind, TL_ERR_TOKEN);
    ASSERT_NULL(tok);
    ASSERT_NOT_NULL(find_by_id(&fs, "TL-V000"));

    arena_free(arena);
}

TEST(garbage_fails) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    token_t *tok = NULL;

    tl_error_t err = token_parse(arena, STR_LIT("!!!.???.$$$"), &fs, &tok);
    ASSERT_EQ(err.kind, TL_ERR_TOKEN);
    ASSERT_NULL(tok);

    arena_free(arena);
}

TEST(signing_input_correct) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    token_t *tok = NULL;

    tl_error_t err = token_parse(arena, STR_LIT(JWT_FULL), &fs, &tok);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(tok);

    const char *want_prefix = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEifQ";
    size_t plen = strlen(want_prefix);
    ASSERT_GE((int)tok->signing_input_len, (int)plen);
    ASSERT_TRUE(memcmp(tok->signing_input, want_prefix, plen) == 0);
    ASSERT_EQ((char)tok->signing_input[plen], '.');

    arena_free(arena);
}

TEST(no_kid_gives_str_null) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    token_t *tok = NULL;

    tl_error_t err = token_parse(arena, STR_LIT(JWT_AUD_ARR), &fs, &tok);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(tok);
    ASSERT_TRUE(STR_IS_NULL(tok->kid));

    arena_free(arena);
}

/* ── security properties ─────────────────────────────────────────────────── */

SECURITY_PROP(alg_none_never_produces_token) {
    /* TL-S001 is non-suppressible; alg=none must NEVER produce a token_t */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    token_t *tok = NULL;

    tl_error_t err = token_parse(arena, STR_LIT(JWT_NONE), &fs, &tok);
    ASSERT_EQ(err.kind, TL_ERR_TOKEN);
    ASSERT_NULL(tok);

    /* TL-S001 must be CRITICAL */
    int found = 0;
    for (size_t i = 0; i < fs.count; i++) {
        if (str_eq(fs.findings[i].id, STR_LIT("TL-S001"))) {
            ASSERT_EQ(fs.findings[i].severity, SEV_CRITICAL);
            found = 1;
        }
    }
    ASSERT_TRUE(found);

    arena_free(arena);
}

SECURITY_PROP(alg_none_case_insensitive) {
    /* alg=none must be caught case-insensitively.
     * {"alg":"NONE"} base64url = eyJhbGciOiJOT05FIn0
     * {"alg":"None"} base64url = eyJhbGciOiJOb25lIn0 */
    const char *variants[] = {
        "eyJhbGciOiJOT05FIn0.eyJzdWIiOiJ1In0.c2ln",
        "eyJhbGciOiJOb25lIn0.eyJzdWIiOiJ1In0.c2ln",
    };

    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    for (size_t v = 0; v < 2; v++) {
        finding_set_t fs; findings_init(&fs);
        token_t *tok = NULL;
        tl_error_t err = token_parse(arena, str_from_cstr(variants[v]), &fs, &tok);
        /* Either TL-S001 (none) or TL-V002 (unrecognized) — both halt */
        ASSERT_EQ(err.kind, TL_ERR_TOKEN);
        ASSERT_NULL(tok);
    }

    arena_free(arena);
}

/* ── main ────────────────────────────────────────────────────────────────── */

TEST_MAIN(
    tl_run_parse_full_token,
    tl_run_parse_aud_array,
    tl_run_parse_eddsa,
    tl_run_alg_none_halts_with_s001,
    tl_run_alg_absent_halts_with_v001,
    tl_run_alg_unrecognized_halts_with_v002,
    tl_run_empty_jwt_fails_v000,
    tl_run_two_part_jwt_fails_v000,
    tl_run_garbage_fails,
    tl_run_signing_input_correct,
    tl_run_no_kid_gives_str_null,
    tl_run_alg_none_never_produces_token,
    tl_run_alg_none_case_insensitive,
)
