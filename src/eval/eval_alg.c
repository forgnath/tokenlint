/*
 * src/eval/eval_alg.c
 *
 * Algorithm and key compatibility evaluation for tokenlint v1.
 *
 * Implements steps 5–9 of the token evaluation order from algorithm-contract.md.
 * Steps 1–4 (parse, alg field presence, alg=none, recognition) are handled
 * by the token parser; by the time eval_alg is called, token->alg is a valid
 * non-NONE alg_id_t.
 *
 * Entry point: eval_alg(ctx)
 *   Called from eval_validate() after token parsing succeeds.
 *   Emits TL-V003, TL-V004, TL-V005, TL-V009, TL-V010, TL-V011, TL-V012.
 *
 * No vendor headers. No raw string comparisons. No strlen().
 */

#include "tokenlint.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"
#include "token.h"
#include "jwks.h"
#include "eval_ctx.h"

#include <stddef.h>
#include <string.h>   /* memset */


/* =========================================================================
 * Internal helpers — finding construction
 * ========================================================================= */

static void emit(eval_ctx_t *ctx,
                 const char *id, const char *title,
                 severity_t sev, const char *detail)
{
    finding_t f;
    memset(&f, 0, sizeof(f));
    f.id         = str_from_cstr(id);
    f.title      = str_from_cstr(title);
    f.detail     = str_from_cstr(detail);
    f.policy_path = ctx->policy->schema_version; /* placeholder path */
    f.severity   = sev;
    f.status     = FINDING_ACTIVE;

    int _r = findings_add(ctx->findings, &f, ctx->arena,
                          ctx->policy->suppressions,
                          ctx->policy->suppression_count);
    TL_UNUSED(_r);
}


/* =========================================================================
 * Key type compatibility
 *
 * Returns 1 if the algorithm is structurally compatible with the key's kty/crv,
 * 0 otherwise.  Does NOT check the alg field on the key (that's check_alg_field).
 * ========================================================================= */

static int kty_compatible(alg_id_t alg, const jwks_key_t *key)
{
    switch (alg) {
    case ALG_RS256: case ALG_RS384: case ALG_RS512:
    case ALG_PS256: case ALG_PS384: case ALG_PS512:
        return key->kty == KTY_RSA;

    case ALG_ES256:
        return key->kty == KTY_EC && key->crv == CRV_P256;
    case ALG_ES384:
        return key->kty == KTY_EC && key->crv == CRV_P384;
    case ALG_ES512:
        return key->kty == KTY_EC && key->crv == CRV_P521;

    case ALG_ECDSA_EDDSA:
        return key->kty == KTY_OKP &&
               (key->crv == CRV_ED25519 || key->crv == CRV_ED448);

    case ALG_HS256: case ALG_HS384: case ALG_HS512:
        return key->kty == KTY_OCT;

    default:
        return 0;
    }
}


/* =========================================================================
 * eval_alg_step5_policy — TL-V003: token alg not in accepts.algorithms
 * ========================================================================= */

static void step5_policy_check(eval_ctx_t *ctx)
{
    alg_id_t alg = ctx->token->alg;
    if (!ALLOWSET_CONTAINS(ctx->policy->algorithms, alg)) {
        emit(ctx, "TL-V003", "TOKEN_ALG_NOT_ALLOWED",
             SEV_FAIL,
             "Token algorithm not permitted by policy accepts.algorithms");
    }
}


/* =========================================================================
 * eval_alg_step6_kid — key selection (kid resolution)
 *
 * Returns the candidate key index (0-based) or -1 if resolution halts.
 *
 * With require_kid: true:
 *   - No kid in token → TL-V009, halt
 *   - kid present, no match → TL-V010, halt
 *   - kid present, match found → return index
 *
 * With require_kid: false:
 *   - kid present → prefer kid; if no match → TL-V010, halt
 *   - no kid → build candidate set; caller handles TL-V011/TL-V012
 *
 * Returns the matched key index when kid resolution succeeds and selects
 * exactly one key.  Returns -2 to signal "no kid, use candidate fallback".
 * ========================================================================= */

#define KEY_SEL_HALT      (-1)   /* halt algorithm checks */
#define KEY_SEL_FALLBACK  (-2)   /* no kid — caller does candidate scan */

static int step6_kid_resolution(eval_ctx_t *ctx)
{
    const token_t *tok   = ctx->token;
    const jwks_t  *jwks  = ctx->jwks;
    int require_kid      = ctx->policy->jwks_policy.require_kid;

    int has_kid = !STR_IS_NULL(tok->kid) && tok->kid.len > 0;

    if (!has_kid) {
        if (require_kid) {
            /* TL-V009: no kid, require_kid: true → halt */
            emit(ctx, "TL-V009", "TOKEN_KID_ABSENT_STRICT",
                 SEV_FAIL,
                 "Token has no kid and require_kid is true");
            return KEY_SEL_HALT;
        }
        /* no kid, require_kid: false → fallback candidate scan */
        return KEY_SEL_FALLBACK;
    }

    /* kid present — search for exact match */
    for (size_t i = 0; i < jwks->count; i++) {
        if (str_eq(tok->kid, jwks->keys[i].kid)) {
            return (int)i;
        }
    }

    /* kid present but no match */
    emit(ctx, "TL-V010", "TOKEN_KID_NO_MATCH",
         SEV_FAIL,
         "Token kid present but no matching key found in JWKS");
    return KEY_SEL_HALT;
}


/* =========================================================================
 * Key compatibility checks for a single candidate key
 * (steps 7 and 8 per algorithm-contract.md)
 * ========================================================================= */

/*
 * check_single_key — check kty/crv/use/key_ops and declared alg for one key.
 * Emits TL-V004 and/or TL-V005 as appropriate.
 * Returns 1 if key is compatible (no hard incompatibility), 0 otherwise.
 */
static int check_single_key(eval_ctx_t *ctx, size_t key_idx)
{
    const jwks_key_t *key = &ctx->jwks->keys[key_idx];
    alg_id_t alg = ctx->token->alg;
    int ok = 1;

    /* Step 7: kty/crv compatibility */
    if (!kty_compatible(alg, key)) {
        emit(ctx, "TL-V004", "TOKEN_ALG_KEY_INCOMPATIBLE",
             SEV_FAIL,
             "Token algorithm incompatible with matched key kty/crv");
        ok = 0;
    }

    /* use field */
    if (key->use == KEY_USE_ENC) {
        emit(ctx, "TL-V004", "TOKEN_ALG_KEY_INCOMPATIBLE",
             SEV_FAIL,
             "Matched key use is 'enc', not 'sig'");
        ok = 0;
    }

    /* key_ops */
    if (!key->key_ops_verify) {
        emit(ctx, "TL-V004", "TOKEN_ALG_KEY_INCOMPATIBLE",
             SEV_FAIL,
             "Matched key key_ops does not contain 'verify'");
        ok = 0;
    }

    /* Step 8: declared alg field on JWKS key */
    if (key->declared_alg != ALG_NONE_ALG && key->declared_alg != alg) {
        emit(ctx, "TL-V005", "TOKEN_ALG_KEY_ALG_CONFLICT",
             SEV_FAIL,
             "Token alg conflicts with explicit alg field on matched JWKS key");
        ok = 0;
    }

    return ok;
}


/* =========================================================================
 * Candidate set fallback (require_kid: false, no kid in token)
 *
 * Build candidate set, run compatibility checks, emit TL-V011 / TL-V012.
 * Does NOT attempt actual signature verification (that's crypto_backend).
 * Signals whether evaluation can proceed to signature verification.
 *
 * Returns 1 if exactly one compatible candidate → proceed to sig verify
 *         0 otherwise (TL-V011 or TL-V012 already emitted)
 *
 * Note: in this layer we can only do structural compatibility.  The crypto
 * backend (Layer 7) performs the actual signature check.  For the fallback
 * path we check structural compatibility and count candidates; the actual
 * multi-key verification result comes back from the crypto layer.  Since the
 * crypto backend is not yet wired, we emit TL-V011 if zero structural
 * candidates exist and leave TL-V012 for when the crypto layer is integrated.
 * ========================================================================= */

static int step6_candidate_fallback(eval_ctx_t *ctx)
{
    const token_t *tok  = ctx->token;
    const jwks_t  *jwks = ctx->jwks;
    alg_id_t alg = tok->alg;

    size_t count = 0;
    for (size_t i = 0; i < jwks->count; i++) {
        const jwks_key_t *key = &jwks->keys[i];

        /* Filter: kty/crv compatible */
        if (!kty_compatible(alg, key)) continue;
        /* Filter: use must allow sig */
        if (key->use == KEY_USE_ENC) continue;
        /* Filter: key_ops must allow verify */
        if (!key->key_ops_verify) continue;
        /* Filter: declared alg must match if set */
        if (key->declared_alg != ALG_NONE_ALG && key->declared_alg != alg)
            continue;

        count++;
    }

    if (count == 0) {
        emit(ctx, "TL-V011", "TOKEN_SIG_UNVERIFIABLE",
             SEV_FAIL,
             "No candidate key found for signature verification");
        return 0;
    }

    /* Multiple structural candidates — TL-V012 is emitted by crypto layer
     * after actual signature verification.  Signal caller to proceed. */
    return 1;
}


/* =========================================================================
 * eval_alg — main entry point
 *
 * Called from eval_validate() after token parsing.
 * Assumes token->alg is a recognized, non-NONE alg_id_t.
 * ========================================================================= */

void eval_alg(eval_ctx_t *ctx)
{
    /* Step 5: policy allowlist check */
    step5_policy_check(ctx);

    /* Step 6: kid resolution */
    int sel = step6_kid_resolution(ctx);

    if (sel == KEY_SEL_HALT) {
        /* key selection failed; no further key checks possible */
        return;
    }

    if (sel == KEY_SEL_FALLBACK) {
        /* no kid — candidate scan; does not run single-key checks */
        step6_candidate_fallback(ctx);
        return;
    }

    /* sel >= 0: a specific key was selected by kid */
    /* Steps 7 & 8: key compatibility */
    check_single_key(ctx, (size_t)sel);
    /* Note: signature verification (step 9) is done in crypto_backend (Layer 7) */
}

/* Public declaration — declared in eval_ctx.h via eval_validate.c which
 * calls this.  Not separately declared in a header; called only from
 * eval_validate.c.  Forward-declare here for clarity. */
void eval_alg(eval_ctx_t *ctx);
