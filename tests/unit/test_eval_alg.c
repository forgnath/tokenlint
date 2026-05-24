/*
 * tests/unit/test_eval_alg.c
 *
 * Unit tests for src/eval/eval_alg.c
 *
 * Tests the algorithm and key compatibility checks:
 *   TL-V003  TOKEN_ALG_NOT_ALLOWED
 *   TL-V004  TOKEN_ALG_KEY_INCOMPATIBLE
 *   TL-V005  TOKEN_ALG_KEY_ALG_CONFLICT
 *   TL-V009  TOKEN_KID_ABSENT_STRICT
 *   TL-V010  TOKEN_KID_NO_MATCH
 *   TL-V011  TOKEN_SIG_UNVERIFIABLE
 *
 * Uses manually constructed policy_t, token_t, jwks_t and eval_ctx_t
 * — no YAML or JWT parsing required.
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

/* Forward declaration of eval_alg (defined in src/eval/eval_alg.c) */
void eval_alg(eval_ctx_t *ctx);


/* =========================================================================
 * Test fixture helpers
 * ========================================================================= */

/* Build a minimal valid policy_t */
static policy_t make_policy(alg_allowset_t algs, int require_kid)
{
    policy_t p;
    memset(&p, 0, sizeof(p));
    p.environment  = ENV_PROD;
    p.algorithms   = algs;
    p.jwks_policy.require_kid = require_kid;
    /* Minimal required claims so audit doesn't fire extra findings */
    p.required_registered_claims = CLAIM_ISS | CLAIM_AUD | CLAIM_EXP;
    return p;
}

/* Build a minimal valid token_t */
static token_t make_token(alg_id_t alg, const char *kid_cstr)
{
    token_t t;
    memset(&t, 0, sizeof(t));
    t.alg = alg;
    if (kid_cstr) {
        t.kid = str_from_cstr(kid_cstr);
    }
    return t;
}

/* Build a jwks_key_t */
static jwks_key_t make_key(const char *kid_cstr, kty_t kty, crv_t crv,
                            alg_id_t declared_alg, int key_ops_verify,
                            key_use_t use)
{
    jwks_key_t k;
    memset(&k, 0, sizeof(k));
    if (kid_cstr) k.kid = str_from_cstr(kid_cstr);
    k.kty           = kty;
    k.crv           = crv;
    k.declared_alg  = declared_alg;
    k.key_ops_verify = key_ops_verify;
    k.use           = use;
    return k;
}

/* Returns 1 if the finding_set contains a finding with this id string */
static int has_finding(const finding_set_t *fs, const char *id_cstr)
{
    str_t id = str_from_cstr(id_cstr);
    for (size_t i = 0; i < fs->count; i++) {
        if (str_eq(fs->findings[i].id, id) &&
            fs->findings[i].status == FINDING_ACTIVE) {
            return 1;
        }
    }
    return 0;
}

/* Count active findings with this id */
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

/* Build a minimal eval_ctx_t; caller fills in token/jwks after */
static eval_ctx_t make_ctx(arena_t *arena, finding_set_t *fs,
                            policy_t *pol, jwks_t *jwks, token_t *tok)
{
    eval_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.arena          = arena;
    ctx.findings       = fs;
    ctx.policy         = pol;
    ctx.jwks           = jwks;
    ctx.token          = tok;
    ctx.reference_time = 1700000000; /* arbitrary fixed time */
    return ctx;
}


/* =========================================================================
 * TL-V003: TOKEN_ALG_NOT_ALLOWED
 * ========================================================================= */

TEST(v003_fires_alg_not_in_allowset) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    /* Allow only RS256, present ES256 token */
    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_ES256, NULL);

    /* One key that matches ES256 so kid/key path doesn't short-circuit */
    jwks_key_t keys[1];
    keys[0] = make_key(NULL, KTY_EC, CRV_P256, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V003"));
    arena_free(arena);
}

TEST(v003_no_fire_alg_in_allowset) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_RS256, NULL);

    jwks_key_t keys[1];
    keys[0] = make_key(NULL, KTY_RSA, CRV_UNSET, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V003"));
    arena_free(arena);
}


/* =========================================================================
 * TL-V009: TOKEN_KID_ABSENT_STRICT
 * ========================================================================= */

TEST(v009_fires_no_kid_require_kid_true) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 1); /* require_kid: true */
    token_t  tok = make_token(ALG_RS256, NULL); /* no kid */

    jwks_key_t keys[1];
    keys[0] = make_key("k1", KTY_RSA, CRV_UNSET, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V009"));
    arena_free(arena);
}

TEST(v009_no_fire_kid_present) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 1); /* require_kid: true */
    token_t  tok = make_token(ALG_RS256, "k1");

    jwks_key_t keys[1];
    keys[0] = make_key("k1", KTY_RSA, CRV_UNSET, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V009"));
    arena_free(arena);
}


/* =========================================================================
 * TL-V010: TOKEN_KID_NO_MATCH
 * ========================================================================= */

TEST(v010_fires_kid_no_match) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_RS256, "unknown-kid");

    jwks_key_t keys[1];
    keys[0] = make_key("k1", KTY_RSA, CRV_UNSET, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V010"));
    arena_free(arena);
}

TEST(v010_no_fire_kid_matches) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_RS256, "k1");

    jwks_key_t keys[1];
    keys[0] = make_key("k1", KTY_RSA, CRV_UNSET, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V010"));
    arena_free(arena);
}


/* =========================================================================
 * TL-V004: TOKEN_ALG_KEY_INCOMPATIBLE
 * ========================================================================= */

TEST(v004_fires_kty_mismatch) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    /* RS256 token but EC key */
    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_RS256, "k1");

    jwks_key_t keys[1];
    keys[0] = make_key("k1", KTY_EC, CRV_P256, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V004"));
    arena_free(arena);
}

TEST(v004_fires_use_enc) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_RS256, "k1");

    jwks_key_t keys[1];
    keys[0] = make_key("k1", KTY_RSA, CRV_UNSET, ALG_NONE_ALG, 1, KEY_USE_ENC);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V004"));
    arena_free(arena);
}

TEST(v004_fires_key_ops_no_verify) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_RS256, "k1");

    jwks_key_t keys[1];
    /* key_ops_verify = 0: not allowed */
    keys[0] = make_key("k1", KTY_RSA, CRV_UNSET, ALG_NONE_ALG, 0, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V004"));
    arena_free(arena);
}

TEST(v004_no_fire_compatible_rsa) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_RS256, "k1");

    jwks_key_t keys[1];
    keys[0] = make_key("k1", KTY_RSA, CRV_UNSET, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V004"));
    arena_free(arena);
}

TEST(v004_fires_ecdsa_curve_mismatch) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    /* ES256 requires P-256 but key has P-384 */
    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_ES256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_ES256, "k1");

    jwks_key_t keys[1];
    keys[0] = make_key("k1", KTY_EC, CRV_P384, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V004"));
    arena_free(arena);
}


/* =========================================================================
 * TL-V005: TOKEN_ALG_KEY_ALG_CONFLICT
 * ========================================================================= */

TEST(v005_fires_declared_alg_mismatch) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    /* Token says PS256, key declares RS256 */
    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_PS256);
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_PS256, "k1");

    jwks_key_t keys[1];
    keys[0] = make_key("k1", KTY_RSA, CRV_UNSET, ALG_RS256, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V005"));
    arena_free(arena);
}

TEST(v005_no_fire_declared_alg_matches) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_RS256, "k1");

    jwks_key_t keys[1];
    keys[0] = make_key("k1", KTY_RSA, CRV_UNSET, ALG_RS256, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V005"));
    arena_free(arena);
}

TEST(v005_no_fire_no_declared_alg) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_RS256, "k1");

    jwks_key_t keys[1];
    /* declared_alg = ALG_NONE_ALG: no alg field on key */
    keys[0] = make_key("k1", KTY_RSA, CRV_UNSET, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V005"));
    arena_free(arena);
}


/* =========================================================================
 * TL-V011: TOKEN_SIG_UNVERIFIABLE (fallback path, no structural candidates)
 * ========================================================================= */

TEST(v011_fires_no_structural_candidates) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    /* ES256 token but only RSA key available */
    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_ES256);

    policy_t pol = make_policy(algs, 0); /* require_kid: false */
    token_t  tok = make_token(ALG_ES256, NULL); /* no kid */

    jwks_key_t keys[1];
    keys[0] = make_key(NULL, KTY_RSA, CRV_UNSET, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V011"));
    arena_free(arena);
}

TEST(v011_no_fire_candidate_exists) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_RS256, NULL); /* no kid */

    jwks_key_t keys[1];
    keys[0] = make_key(NULL, KTY_RSA, CRV_UNSET, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V011"));
    arena_free(arena);
}


/* =========================================================================
 * SECURITY_PROP: alg=none never authorized
 * ========================================================================= */

SECURITY_PROP(alg_none_never_authorized) {
    /* ALG_NONE_ALG (0) must never appear in any allowset and must never
     * pass any kty_compatible() check.  This property is structural:
     * ALLOWSET_CONTAINS with ALG_NONE_ALG checks bit 0, but we verify
     * that a policy that somehow had bit 0 set still won't authorize
     * ALG_NONE_ALG through a key. */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    /* Force ALG_NONE_ALG into an allowset (shouldn't be possible via parser) */
    alg_allowset_t algs;
    algs.bits = (1u << (unsigned)ALG_NONE_ALG);

    policy_t pol = make_policy(algs, 0);

    /* Token with ALG_NONE_ALG — parser would have halted but test directly */
    token_t tok = make_token(ALG_NONE_ALG, NULL);

    jwks_key_t keys[1];
    keys[0] = make_key(NULL, KTY_RSA, CRV_UNSET, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    /* Step 5: ALLOWSET_CONTAINS(set, ALG_NONE_ALG) = 1 via bit0
     * No TL-V003 fires — but the policy allowset having bit0 set is
     * a parser invariant violation.  The real security guarantee is:
     * token->alg == ALG_NONE_ALG never reaches eval_alg because
     * the parser emits TL-S001 and returns TL_ERR_TOKEN.
     * Here we just verify the fallback path emits TL-V011 because
     * no key is structurally compatible with ALG_NONE_ALG. */
    ASSERT_TRUE(has_finding(&fs, "TL-V011"));

    arena_free(arena);
}

SECURITY_PROP(hs_symmetric_in_prod_fires_audit) {
    /* When HS256 is in the allowset and env is prod, TL-A005 must fire.
     * This is checked in eval_audit but we verify the full pipeline here. */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_HS256);

    policy_t pol = make_policy(algs, 0);
    pol.environment = ENV_PROD;

    /* We call eval_alg not eval_audit, but we also need to confirm
     * eval_audit fires TL-A005 independently — do that here. */
    extern void eval_audit(eval_ctx_t *ctx);

    token_t tok = make_token(ALG_HS256, NULL);
    jwks_key_t keys[1];
    keys[0] = make_key(NULL, KTY_OCT, CRV_UNSET, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_audit(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-A005"));

    arena_free(arena);
}

/* =========================================================================
 * Edge cases
 * ========================================================================= */

TEST(edsa_ed25519_compatible) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_ECDSA_EDDSA);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_ECDSA_EDDSA, "k1");

    jwks_key_t keys[1];
    keys[0] = make_key("k1", KTY_OKP, CRV_ED25519, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_FALSE(has_finding(&fs, "TL-V003"));
    ASSERT_FALSE(has_finding(&fs, "TL-V004"));
    arena_free(arena);
}

TEST(ps256_not_compatible_with_rs256_key_alg_field) {
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    /* PS256 token, RSA key, but key declares alg:RS256 → TL-V005 */
    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_PS256);

    policy_t pol = make_policy(algs, 0);
    token_t  tok = make_token(ALG_PS256, "k1");

    jwks_key_t keys[1];
    keys[0] = make_key("k1", KTY_RSA, CRV_UNSET, ALG_RS256, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    ASSERT_TRUE(has_finding(&fs, "TL-V005"));
    arena_free(arena);
}

TEST(multiple_findings_independent) {
    /* V003 and V009 can both fire independently */
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    finding_set_t fs;
    findings_init(&fs);

    /* Policy allows RS256, token is ES256, no kid, require_kid: true */
    alg_allowset_t algs = ALLOWSET_EMPTY;
    ALLOWSET_ADD(algs, ALG_RS256);

    policy_t pol = make_policy(algs, 1); /* require_kid: true */
    token_t  tok = make_token(ALG_ES256, NULL); /* wrong alg, no kid */

    jwks_key_t keys[1];
    keys[0] = make_key("k1", KTY_RSA, CRV_UNSET, ALG_NONE_ALG, 1, KEY_USE_SIG);
    jwks_t jwks = { keys, 1 };

    eval_ctx_t ctx = make_ctx(arena, &fs, &pol, &jwks, &tok);
    eval_alg(&ctx);

    /* Both V003 (wrong alg) and V009 (no kid, strict) should fire */
    ASSERT_TRUE(has_finding(&fs, "TL-V003"));
    ASSERT_TRUE(has_finding(&fs, "TL-V009"));
    arena_free(arena);
}

/* Suppress unused-function warning for count_finding — it's a test utility */
static void _use_count_finding(void) __attribute__((unused));
static void _use_count_finding(void) { (void)count_finding; }

TEST_MAIN(
    tl_run_v003_fires_alg_not_in_allowset,
    tl_run_v003_no_fire_alg_in_allowset,
    tl_run_v009_fires_no_kid_require_kid_true,
    tl_run_v009_no_fire_kid_present,
    tl_run_v010_fires_kid_no_match,
    tl_run_v010_no_fire_kid_matches,
    tl_run_v004_fires_kty_mismatch,
    tl_run_v004_fires_use_enc,
    tl_run_v004_fires_key_ops_no_verify,
    tl_run_v004_no_fire_compatible_rsa,
    tl_run_v004_fires_ecdsa_curve_mismatch,
    tl_run_v005_fires_declared_alg_mismatch,
    tl_run_v005_no_fire_declared_alg_matches,
    tl_run_v005_no_fire_no_declared_alg,
    tl_run_v011_fires_no_structural_candidates,
    tl_run_v011_no_fire_candidate_exists,
    tl_run_edsa_ed25519_compatible,
    tl_run_ps256_not_compatible_with_rs256_key_alg_field,
    tl_run_multiple_findings_independent,
    tl_run_alg_none_never_authorized,
    tl_run_hs_symmetric_in_prod_fires_audit,
)
