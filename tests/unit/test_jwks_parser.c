/*
 * tests/unit/test_jwks_parser.c
 *
 * Unit tests for src/parse/jwks_parser.c.
 */

#include "helpers/test_runner.h"
#include "tokenlint.h"
#include "alg.h"
#include "findings.h"
#include "jwks.h"

#include <string.h>

#define FIX(name) "tests/fixtures/jwks/" name

/* ── helper ──────────────────────────────────────────────────────────────── */

static jwks_key_t *find_by_kid(jwks_t *jwks, const char *kid) {
    for (size_t i = 0; i < jwks->count; i++)
        if (str_eq(jwks->keys[i].kid, str_from_cstr(kid)))
            return &jwks->keys[i];
    return NULL;
}

/* ── tests ───────────────────────────────────────────────────────────────── */

TEST(load_rsa_single_key) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, FIX("rsa_rs256.json"), &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(jwks);
    ASSERT_EQ((int)jwks->count, 1);

    jwks_key_t *k = &jwks->keys[0];
    ASSERT_EQ(k->kty, KTY_RSA);
    ASSERT_EQ(k->use, KEY_USE_SIG);
    ASSERT_EQ(k->declared_alg, ALG_RS256);
    ASSERT_TRUE(str_eq(k->kid, STR_LIT("rsa-key-1")));
    ASSERT_EQ(k->crv, CRV_UNSET);

    /* key_ops absent → key_ops_verify is 0 (no restriction assumed by caller) */
    ASSERT_EQ(k->key_ops_verify, 0);

    /* key material bytes stored */
    ASSERT_NOT_NULL(k->key_material);
    ASSERT_GT((int)k->key_material_len, 0);

    arena_free(arena);
}

TEST(load_multi_key_set) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, FIX("multi_key.json"), &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(jwks);
    ASSERT_EQ((int)jwks->count, 3);

    /* RSA key */
    jwks_key_t *rsa = find_by_kid(jwks, "rsa-1");
    ASSERT_NOT_NULL(rsa);
    ASSERT_EQ(rsa->kty, KTY_RSA);

    /* EC P-256 key */
    jwks_key_t *ec256 = find_by_kid(jwks, "ec-1");
    ASSERT_NOT_NULL(ec256);
    ASSERT_EQ(ec256->kty, KTY_EC);
    ASSERT_EQ(ec256->crv, CRV_P256);

    /* EC P-384 key */
    jwks_key_t *ec384 = find_by_kid(jwks, "ec-384");
    ASSERT_NOT_NULL(ec384);
    ASSERT_EQ(ec384->kty, KTY_EC);
    ASSERT_EQ(ec384->crv, CRV_P384);

    arena_free(arena);
}

TEST(key_ops_verify_detected) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, FIX("key_ops_verify.json"), &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(jwks);
    ASSERT_EQ((int)jwks->count, 1);
    ASSERT_EQ(jwks->keys[0].key_ops_verify, 1);

    arena_free(arena);
}

TEST(key_ops_sign_only_not_verify) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, FIX("key_ops_sign_only.json"), &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(jwks);
    ASSERT_EQ(jwks->keys[0].key_ops_verify, 0);

    arena_free(arena);
}

TEST(eddsa_key_parsed) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, FIX("eddsa.json"), &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(jwks);
    ASSERT_EQ((int)jwks->count, 1);

    jwks_key_t *k = &jwks->keys[0];
    ASSERT_EQ(k->kty, KTY_OKP);
    ASSERT_EQ(k->crv, CRV_ED25519);
    ASSERT_TRUE(str_eq(k->kid, STR_LIT("ed-1")));

    arena_free(arena);
}

TEST(hmac_key_parsed) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, FIX("hmac.json"), &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(jwks);
    ASSERT_EQ((int)jwks->count, 1);
    ASSERT_EQ(jwks->keys[0].kty, KTY_OCT);
    ASSERT_EQ(jwks->keys[0].declared_alg, ALG_HS256);

    arena_free(arena);
}

TEST(no_kid_gives_str_null) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, FIX("no_kid.json"), &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(jwks);
    ASSERT_EQ((int)jwks->count, 1);
    ASSERT_TRUE(STR_IS_NULL(jwks->keys[0].kid));

    arena_free(arena);
}

TEST(missing_keys_array_fails) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, FIX("no_keys_array.json"), &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_JWKS);
    ASSERT_NULL(jwks);

    arena_free(arena);
}

TEST(empty_keys_array_fails) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, FIX("empty_keys.json"), &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_JWKS);
    ASSERT_NULL(jwks);

    arena_free(arena);
}

TEST(missing_kty_fails) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, FIX("missing_kty.json"), &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_JWKS);
    ASSERT_NULL(jwks);

    arena_free(arena);
}

TEST(nonexistent_file_fails) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, "/nonexistent/jwks.json", &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_JWKS);
    ASSERT_NULL(jwks);

    arena_free(arena);
}

TEST(kid_lookup_works) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, FIX("multi_key.json"), &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_NONE);

    /* Find by kid */
    ASSERT_NOT_NULL(find_by_kid(jwks, "rsa-1"));
    ASSERT_NOT_NULL(find_by_kid(jwks, "ec-1"));
    /* Non-existent */
    ASSERT_NULL(find_by_kid(jwks, "ghost-key"));

    arena_free(arena);
}

/* ── security properties ─────────────────────────────────────────────────── */

SECURITY_PROP(empty_jwks_never_produces_keyset) {
    /* An empty keyset must always fail — no keys means no verification */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, FIX("empty_keys.json"), &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_JWKS);
    ASSERT_NULL(jwks);

    arena_free(arena);
}

SECURITY_PROP(key_material_always_stored) {
    /* Every successfully loaded key must have non-null, non-zero key_material */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    finding_set_t fs; findings_init(&fs);
    jwks_t *jwks = NULL;

    tl_error_t err = jwks_load(arena, FIX("multi_key.json"), &fs, &jwks);
    ASSERT_EQ(err.kind, TL_ERR_NONE);
    ASSERT_NOT_NULL(jwks);

    for (size_t i = 0; i < jwks->count; i++) {
        ASSERT_NOT_NULL(jwks->keys[i].key_material);
        ASSERT_GT((int)jwks->keys[i].key_material_len, 0);
    }

    arena_free(arena);
}

/* ── main ────────────────────────────────────────────────────────────────── */

TEST_MAIN(
    tl_run_load_rsa_single_key,
    tl_run_load_multi_key_set,
    tl_run_key_ops_verify_detected,
    tl_run_key_ops_sign_only_not_verify,
    tl_run_eddsa_key_parsed,
    tl_run_hmac_key_parsed,
    tl_run_no_kid_gives_str_null,
    tl_run_missing_keys_array_fails,
    tl_run_empty_keys_array_fails,
    tl_run_missing_kty_fails,
    tl_run_nonexistent_file_fails,
    tl_run_kid_lookup_works,
    tl_run_empty_jwks_never_produces_keyset,
    tl_run_key_material_always_stored,
)
