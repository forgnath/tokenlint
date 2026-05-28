/*
 * src/output/report_json.c
 *
 * JSON envelope output for tokenlint v1.
 *
 * Implements report_json() and tl_compute_verdict().
 * Shared helpers tl_alg_name() and tl_env_name() are defined here and
 * exposed via report.h.
 *
 * Output shape follows docs/output-contract.md exactly.
 * All strings pass through jw_* — never raw fprintf to stdout.
 */

#include "tokenlint.h"
#include "report.h"
#include "json_writer.h"
#include "findings.h"
#include "policy.h"
#include "token.h"
#include "jwks.h"
#include "alg.h"
#include "time_util.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>


/* =========================================================================
 * Version string
 * ========================================================================= */

#ifndef TL_VERSION_STR
#define TL_VERSION_STR "0.1.0"
#endif


/* =========================================================================
 * Shared helpers
 * ========================================================================= */

const char *tl_alg_name(alg_id_t alg)
{
    switch (alg) {
        case ALG_RS256:     return "RS256";
        case ALG_RS384:     return "RS384";
        case ALG_RS512:     return "RS512";
        case ALG_PS256:     return "PS256";
        case ALG_PS384:     return "PS384";
        case ALG_PS512:     return "PS512";
        case ALG_ES256:     return "ES256";
        case ALG_ES384:     return "ES384";
        case ALG_ES512:     return "ES512";
        case ALG_ECDSA_EDDSA:     return "EdDSA";
        case ALG_HS256:     return "HS256";
        case ALG_HS384:     return "HS384";
        case ALG_HS512:     return "HS512";
        case ALG_NONE_ALG:  return "none";
        default:            return "unknown";
    }
}

const char *tl_env_name(environment_t env)
{
    switch (env) {
        case ENV_PROD:    return "prod";
        case ENV_STAGE:   return "stage";
        case ENV_DEV:     return "dev";
        case ENV_TEST:    return "test";
        case ENV_UNKNOWN: return "unknown";
        default:          return "unknown";
    }
}

static const char *kty_name(kty_t kty)
{
    switch (kty) {
        case KTY_RSA:     return "RSA";
        case KTY_EC:      return "EC";
        case KTY_OKP:     return "OKP";
        case KTY_OCT:     return "oct";
        default:          return "unknown";
    }
}

static const char *crv_name(crv_t crv)
{
    switch (crv) {
        case CRV_P256:    return "P-256";
        case CRV_P384:    return "P-384";
        case CRV_P521:    return "P-521";
        case CRV_ED25519: return "Ed25519";
        case CRV_ED448:   return "Ed448";
        default:          return NULL;
    }
}

static const char *key_use_name(key_use_t use)
{
    switch (use) {
        case KEY_USE_SIG: return "sig";
        case KEY_USE_ENC: return "enc";
        default:          return NULL;
    }
}

static const char *severity_name(severity_t sev)
{
    switch (sev) {
        case SEV_INFO:     return "info";
        case SEV_WARN:     return "warn";
        case SEV_FAIL:     return "fail";
        case SEV_CRITICAL: return "critical";
        default:           return "unknown";
    }
}

static const char *status_name(finding_status_t s)
{
    switch (s) {
        case FINDING_ACTIVE:             return "active";
        case FINDING_SUPPRESSED_POLICY:  return "suppressed_policy";
        case FINDING_SUPPRESSED_CLI:     return "suppressed_cli";
        case FINDING_SKIPPED:            return "skipped";
        default:                         return "unknown";
    }
}

const char *mode_name(tl_mode_t m)
{
    switch (m) {
        case TL_MODE_AUDIT:    return "audit";
        case TL_MODE_VALIDATE: return "validate";
        case TL_MODE_INSPECT:  return "inspect";
        default:               return "unknown";
    }
}

const char *verdict_name(tl_verdict_t v)
{
    switch (v) {
        case TL_VERDICT_PASS:  return "pass";
        case TL_VERDICT_WARN:  return "warn";
        case TL_VERDICT_FAIL:  return "fail";
        case TL_VERDICT_ERROR: return "error";
        default:               return "error";
    }
}

const char *err_kind_name(tl_err_kind_t k)
{
    switch (k) {
        case TL_ERR_SCHEMA:   return "schema";
        case TL_ERR_JWKS:     return "jwks";
        case TL_ERR_TOKEN:    return "token";
        case TL_ERR_AT_FLAG:  return "at_flag";
        case TL_ERR_IO:       return "io";
        case TL_ERR_INTERNAL: return "internal";
        default:              return "internal";
    }
}


/* =========================================================================
 * tl_compute_verdict
 * ========================================================================= */

void tl_compute_verdict(tl_report_ctx_t *ctx)
{
    /* Error always wins */
    if (!tl_ok(ctx->error) || (ctx->findings && ctx->findings->overflowed)) {
        ctx->verdict   = TL_VERDICT_ERROR;
        ctx->exit_code = 3;
        return;
    }

    if (!ctx->findings) {
        ctx->verdict   = TL_VERDICT_PASS;
        ctx->exit_code = 0;
        return;
    }

    int has_fail = 0;
    int has_warn = 0;

    for (size_t i = 0; i < ctx->findings->count; i++) {
        const finding_t *f = &ctx->findings->findings[i];
        if (f->status != FINDING_ACTIVE) continue;
        if (f->severity >= SEV_FAIL)     { has_fail = 1; break; }
        if (f->severity == SEV_WARN)     { has_warn = 1; }
    }

    if (has_fail) {
        ctx->verdict   = TL_VERDICT_FAIL;
        ctx->exit_code = 1;
    } else if (has_warn) {
        ctx->verdict   = TL_VERDICT_WARN;
        ctx->exit_code = 2;
    } else {
        ctx->verdict   = TL_VERDICT_PASS;
        ctx->exit_code = 0;
    }
}


/* =========================================================================
 * Finding emission
 * ========================================================================= */

static void emit_finding(jw_t *w, const finding_t *f)
{
    jw_object_begin(w);

    jw_key(w, "id");
    jw_str(w, f->id);

    jw_key(w, "name");
    jw_str(w, f->title);

    jw_key(w, "severity");
    jw_string(w, severity_name(f->severity));

    jw_key(w, "status");
    jw_string(w, status_name(f->status));

    jw_key(w, "detail");
    jw_str(w, f->detail);

    /* suppression block */
    if (f->status == FINDING_SUPPRESSED_POLICY ||
        f->status == FINDING_SUPPRESSED_CLI) {
        jw_key(w, "suppression");
        jw_object_begin(w);
        jw_key(w, "source"); jw_str(w, f->suppression.source);
        jw_key(w, "reason"); jw_str(w, f->suppression.reason);
        jw_key(w, "owner");  jw_str(w, f->suppression.owner);
        jw_key(w, "ticket");
        if (STR_IS_NULL(f->suppression.ticket)) jw_null(w);
        else jw_str(w, f->suppression.ticket);
        jw_key(w, "expires");
        if (STR_IS_NULL(f->suppression.expires)) jw_null(w);
        else jw_str(w, f->suppression.expires);
        jw_key(w, "expires_in_days");
        jw_int(w, f->suppression.expires_in_days);
        jw_object_end(w);
    } else {
        jw_key(w, "suppression");
        jw_null(w);
    }

    jw_object_end(w);
}


/* =========================================================================
 * Summary block
 * ========================================================================= */

static void emit_summary(jw_t *w, const finding_set_t *fs)
{
    size_t total = 0, active = 0, suppressed = 0, skipped = 0;
    size_t by_crit = 0, by_fail = 0, by_warn = 0, by_info = 0;

    if (fs) {
        total = fs->count;
        for (size_t i = 0; i < fs->count; i++) {
            const finding_t *f = &fs->findings[i];
            switch (f->status) {
                case FINDING_ACTIVE:            active++;    break;
                case FINDING_SUPPRESSED_POLICY:
                case FINDING_SUPPRESSED_CLI:    suppressed++; break;
                case FINDING_SKIPPED:           skipped++;   break;
            }
            if (f->status == FINDING_ACTIVE) {
                switch (f->severity) {
                    case SEV_CRITICAL: by_crit++; break;
                    case SEV_FAIL:     by_fail++; break;
                    case SEV_WARN:     by_warn++; break;
                    case SEV_INFO:     by_info++; break;
                }
            }
        }
    }

    jw_object_begin(w);
    jw_key(w, "total");      jw_uint(w, (uint64_t)total);
    jw_key(w, "active");     jw_uint(w, (uint64_t)active);
    jw_key(w, "suppressed"); jw_uint(w, (uint64_t)suppressed);
    jw_key(w, "skipped");    jw_uint(w, (uint64_t)skipped);
    jw_key(w, "by_severity");
    jw_object_begin(w);
    jw_key(w, "critical"); jw_uint(w, (uint64_t)by_crit);
    jw_key(w, "fail");     jw_uint(w, (uint64_t)by_fail);
    jw_key(w, "warn");     jw_uint(w, (uint64_t)by_warn);
    jw_key(w, "info");     jw_uint(w, (uint64_t)by_info);
    jw_object_end(w);
    jw_object_end(w);
}


/* =========================================================================
 * details block
 * ========================================================================= */

static void emit_policy_detail_block(jw_t *w, const policy_t *p)
{
    jw_key(w, "policy");
    jw_object_begin(w);
    jw_key(w, "validator_id");  jw_str(w, p->validator_id);
    jw_key(w, "environment");   jw_string(w, tl_env_name(p->environment));
    jw_key(w, "schema_version"); jw_str(w, p->schema_version);
    jw_object_end(w);
}

static void emit_audit_details(jw_t *w, const tl_report_ctx_t *ctx)
{
    jw_object_begin(w);

    if (ctx->policy) {
        emit_policy_detail_block(w, ctx->policy);
    } else {
        jw_key(w, "policy"); jw_null(w);
    }

    jw_key(w, "checks_run");
    jw_array_begin(w);
    jw_string(w, "issuer_safety");
    jw_string(w, "audience_safety");
    jw_string(w, "algorithm_safety");
    jw_string(w, "required_claims");
    jw_string(w, "ttl_bounds");
    jw_array_end(w);

    jw_object_end(w);
}

static void emit_token_detail(jw_t *w, const token_t *t, int64_t ref_time)
{
    char buf[TL_ISO8601Z_BUF_LEN];

    jw_object_begin(w);

    jw_key(w, "alg");
    jw_string(w, tl_alg_name(t->alg));

    jw_key(w, "kid");
    if (STR_IS_NULL(t->kid)) jw_null(w); else jw_str(w, t->kid);

    jw_key(w, "iss");
    if (STR_IS_NULL(t->iss)) jw_null(w); else jw_str(w, t->iss);

    jw_key(w, "aud");
    jw_array_begin(w);
    for (size_t i = 0; i < t->aud_count; i++) jw_str(w, t->aud[i]);
    jw_array_end(w);

    jw_key(w, "exp");
    if (t->exp == 0) {
        jw_null(w);
    } else {
        tl_format_iso8601z(t->exp, buf, sizeof(buf));
        jw_string(w, buf);
    }

    jw_key(w, "iat");
    if (t->iat == 0) {
        jw_null(w);
    } else {
        tl_format_iso8601z(t->iat, buf, sizeof(buf));
        jw_string(w, buf);
    }

    jw_key(w, "nbf");
    if (t->nbf == 0) {
        jw_null(w);
    } else {
        tl_format_iso8601z(t->nbf, buf, sizeof(buf));
        jw_string(w, buf);
    }

    /* ttl_seconds — only if both exp and iat present */
    jw_key(w, "ttl_seconds");
    if (t->exp != 0 && t->iat != 0) {
        jw_int(w, t->exp - t->iat);
    } else {
        jw_null(w);
    }

    /* claims_present — array of claim name strings */
    jw_key(w, "claims_present");
    jw_array_begin(w);
    if (t->present_claims & CLAIM_ISS) jw_string(w, "iss");
    if (t->present_claims & CLAIM_SUB) jw_string(w, "sub");
    if (t->present_claims & CLAIM_AUD) jw_string(w, "aud");
    if (t->present_claims & CLAIM_EXP) jw_string(w, "exp");
    if (t->present_claims & CLAIM_NBF) jw_string(w, "nbf");
    if (t->present_claims & CLAIM_IAT) jw_string(w, "iat");
    if (t->present_claims & CLAIM_JTI) jw_string(w, "jti");
    jw_array_end(w);

    TL_UNUSED(ref_time);

    jw_object_end(w);
}

static void emit_key_used(jw_t *w, const jwks_key_t *key)
{
    if (!key) { jw_null(w); return; }

    jw_object_begin(w);
    jw_key(w, "kid");
    if (STR_IS_NULL(key->kid)) jw_null(w); else jw_str(w, key->kid);
    jw_key(w, "kty");
    jw_string(w, kty_name(key->kty));
    jw_key(w, "crv");
    {
        const char *c = crv_name(key->crv);
        if (c) jw_string(w, c); else jw_null(w);
    }
    jw_key(w, "use");
    {
        const char *u = key_use_name(key->use);
        if (u) jw_string(w, u); else jw_null(w);
    }
    jw_key(w, "alg");
    if (key->declared_alg == ALG_NONE_ALG) jw_null(w);
    else jw_string(w, tl_alg_name(key->declared_alg));
    jw_object_end(w);
}

static void emit_validate_details(jw_t *w, const tl_report_ctx_t *ctx)
{
    jw_object_begin(w);

    if (ctx->policy) {
        emit_policy_detail_block(w, ctx->policy);
    } else {
        jw_key(w, "policy"); jw_null(w);
    }

    jw_key(w, "policy_audit");
    jw_object_begin(w);
    jw_key(w, "executed");
    jw_bool(w, ctx->policy_audit_executed);
    jw_key(w, "finding_count");
    {
        size_t n = 0;
        if (ctx->findings) {
            for (size_t i = 0; i < ctx->findings->count; i++) {
                /* count audit findings (TL-A prefix) */
                const finding_t *f = &ctx->findings->findings[i];
                if (f->id.len >= 4 &&
                    f->id.data[0] == 'T' && f->id.data[1] == 'L' &&
                    f->id.data[2] == '-' && f->id.data[3] == 'A') {
                    n++;
                }
            }
        }
        jw_uint(w, (uint64_t)n);
    }
    jw_key(w, "findings_included"); jw_bool(w, 1);
    jw_object_end(w);

    jw_key(w, "token");
    if (ctx->token) {
        emit_token_detail(w, ctx->token, ctx->reference_time.value);
    } else {
        jw_null(w);
    }

    jw_key(w, "key_used");
    emit_key_used(w, ctx->key_used);

    jw_key(w, "checks_run");
    jw_array_begin(w);
    jw_string(w, "algorithm");
    jw_string(w, "signature");
    jw_string(w, "issuer");
    jw_string(w, "audience");
    jw_string(w, "expiration");
    jw_string(w, "ttl");
    jw_string(w, "required_claims");
    jw_array_end(w);

    jw_object_end(w);
}

static void emit_details(jw_t *w, const tl_report_ctx_t *ctx)
{
    switch (ctx->mode) {
        case TL_MODE_AUDIT:
            emit_audit_details(w, ctx);
            break;
        case TL_MODE_VALIDATE:
            emit_validate_details(w, ctx);
            break;
        case TL_MODE_INSPECT:
            /* inspect detail is v2 / not implemented in v1 eval layer */
            jw_object_begin(w);
            jw_object_end(w);
            break;
    }
}


/* =========================================================================
 * report_json — main entry point
 * ========================================================================= */

void report_json(const tl_report_ctx_t *ctx, FILE *fp)
{
    char time_buf[TL_ISO8601Z_BUF_LEN];
    jw_t w;
    jw_init(&w, fp);

    jw_object_begin(&w);

    /* schema_version */
    jw_key(&w, "schema_version");
    jw_string(&w, "tokenlint.report.v1");

    /* tool */
    jw_key(&w, "tool");
    jw_object_begin(&w);
    jw_key(&w, "name");    jw_string(&w, "tokenlint");
    jw_key(&w, "version"); jw_string(&w, TL_VERSION_STR);
    jw_object_end(&w);

    /* mode */
    jw_key(&w, "mode");
    jw_string(&w, mode_name(ctx->mode));

    /* verdict */
    jw_key(&w, "verdict");
    jw_string(&w, verdict_name(ctx->verdict));

    /* exit_code */
    jw_key(&w, "exit_code");
    jw_int(&w, ctx->exit_code);

    /* reference_time */
    jw_key(&w, "reference_time");
    jw_object_begin(&w);
    jw_key(&w, "value");
    if (tl_format_iso8601z(ctx->reference_time.value, time_buf,
                            sizeof(time_buf)) == 0) {
        jw_string(&w, time_buf);
    } else {
        jw_null(&w);
    }
    jw_key(&w, "source");
    jw_string(&w, tl_time_source_str(ctx->reference_time.source));
    jw_object_end(&w);

    /* summary */
    jw_key(&w, "summary");
    emit_summary(&w, ctx->findings);

    /* inputs */
    jw_key(&w, "inputs");
    jw_object_begin(&w);
    jw_key(&w, "policy");
    if (STR_IS_NULL(ctx->policy_path)) jw_null(&w); else jw_str(&w, ctx->policy_path);
    jw_key(&w, "jwks");
    if (STR_IS_NULL(ctx->jwks_path)) jw_null(&w); else jw_str(&w, ctx->jwks_path);
    jw_key(&w, "token");
    if (STR_IS_NULL(ctx->token_path)) jw_null(&w); else jw_str(&w, ctx->token_path);
    jw_key(&w, "at_flag");
    if (STR_IS_NULL(ctx->at_flag)) jw_null(&w); else jw_str(&w, ctx->at_flag);
    jw_object_end(&w);

    /* findings array */
    jw_key(&w, "findings");
    jw_array_begin(&w);
    if (ctx->findings) {
        for (size_t i = 0; i < ctx->findings->count; i++) {
            emit_finding(&w, &ctx->findings->findings[i]);
        }
    }
    jw_array_end(&w);

    /* details */
    jw_key(&w, "details");
    emit_details(&w, ctx);

    /* error block — only if halt occurred */
    if (!tl_ok(ctx->error)) {
        jw_key(&w, "error");
        jw_object_begin(&w);
        jw_key(&w, "kind");
        jw_string(&w, err_kind_name(ctx->error.kind));
        jw_key(&w, "message");
        jw_str(&w, ctx->error.message);
        jw_key(&w, "context");
        if (STR_IS_NULL(ctx->error.context)) jw_null(&w);
        else jw_str(&w, ctx->error.context);
        jw_object_end(&w);
    }

    jw_object_end(&w);
    jw_finish(&w);
}
