/*
 * include/policy.h
 *
 * Normalised policy model for tokenlint v1.
 *
 * policy_t is the output of policy_parse() (src/parse/policy_parser.c).
 * It is the compiled, evaluation-ready trust model — evaluation code works
 * exclusively against policy_t, never against raw YAML strings or fields.
 *
 * The evaluator never asks `if (strcmp(mode, "exact") == 0)`.  That question
 * was answered at parse time.  By the time evaluation runs, the model
 * contains compiled matchers, bitmasks, and typed structs.
 *
 * Claim presence bitmask (shared with token_t.present_claims):
 *   CLAIM_ISS  (1u << 0)   — iss
 *   CLAIM_SUB  (1u << 1)   — sub
 *   CLAIM_AUD  (1u << 2)   — aud
 *   CLAIM_EXP  (1u << 3)   — exp
 *   CLAIM_NBF  (1u << 4)   — nbf
 *   CLAIM_IAT  (1u << 5)   — iat
 *   CLAIM_JTI  (1u << 6)   — jti
 *
 * Dependencies:
 *   tokenlint.h   — str_t, arena_t, tl_error_t, TL_NODISCARD, TL_NONNULL
 *   alg.h         — alg_id_t, alg_allowset_t
 *   findings.h    — finding_set_t, suppression_t
 *
 * Include order: tokenlint.h → alg.h → findings.h → policy.h
 *
 * No vendor headers included here.  Safe to include from src/eval/.
 *
 * C11 required.
 */

#ifndef TOKENLINT_POLICY_H
#define TOKENLINT_POLICY_H

#include "tokenlint.h"
#include "alg.h"
#include "findings.h"

#include <stdint.h>   /* uint32_t, int64_t */
#include <stddef.h>   /* size_t            */

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * Claim presence / required-claim bitmask constants
 *
 * These bit positions are shared between:
 *   policy_t.required_registered_claims  — claims the policy requires
 *   token_t.present_claims               — claims actually in the token
 *
 * This allows O(1) cross-checking: missing = required & ~present.
 * ========================================================================= */

#define CLAIM_ISS  (1u << 0)
#define CLAIM_SUB  (1u << 1)
#define CLAIM_AUD  (1u << 2)
#define CLAIM_EXP  (1u << 3)
#define CLAIM_NBF  (1u << 4)
#define CLAIM_IAT  (1u << 5)
#define CLAIM_JTI  (1u << 6)


/* =========================================================================
 * environment_t — deployment environment
 *
 * Controls severity of symmetric algorithm findings (TL-A005) and whether
 * suppression expiry is mandatory (TL-S024).
 *
 * ENV_UNKNOWN is treated identically to ENV_PROD for all security decisions.
 * WARN TL-W001 is emitted when ENV_UNKNOWN is used (v2).
 * ========================================================================= */

typedef enum {
    ENV_PROD    = 0,
    ENV_STAGE   = 1,
    ENV_DEV     = 2,
    ENV_TEST    = 3,
    ENV_UNKNOWN = 4
} environment_t;


/* =========================================================================
 * issuer_mode_t / audience_mode_t — matcher modes
 *
 * v1 supports only EXACT matching.  Additional modes are reserved for v2.
 * The parser emits TL-S008 for any other value and halts.
 * ========================================================================= */

typedef enum {
    ISSUER_MODE_EXACT = 0
} issuer_mode_t;

typedef enum {
    AUDIENCE_MODE_EXACT = 0
} audience_mode_t;


/* =========================================================================
 * issuer_matcher_t — compiled issuer allowlist
 *
 * values is an arena-allocated array of str_t.
 * Trailing slashes are normalised by the parser before storage.
 * ========================================================================= */

typedef struct {
    issuer_mode_t  mode;    /* ISSUER_MODE_EXACT in v1          */
    str_t         *values;  /* arena-allocated array of str_t   */
    size_t         count;   /* number of values                 */
} issuer_matcher_t;


/* =========================================================================
 * audience_matcher_t — compiled audience allowlist
 * ========================================================================= */

typedef struct {
    audience_mode_t  mode;    /* AUDIENCE_MODE_EXACT in v1        */
    str_t           *values;  /* arena-allocated array of str_t   */
    size_t           count;   /* number of values                 */
} audience_matcher_t;


/* =========================================================================
 * time_limits_t — compiled time constraint settings
 *
 * max_ttl_seconds:
 *   > 0  — TTL limit is active; both iat and exp implicitly required
 *   == 0 — not set; TL-A007 (TTL_UNBOUNDED) is emitted
 *
 * max_clock_skew_seconds:
 *   Default: 60 (applied when field is absent from YAML)
 *   Applies to nbf check only; never to exp (expired means expired).
 * ========================================================================= */

typedef struct {
    int64_t  max_ttl_seconds;          /* 0 = unset (TL-A007)    */
    int64_t  max_clock_skew_seconds;   /* default 60             */
} time_limits_t;


/* =========================================================================
 * jwks_policy_t — JWKS loading policy embedded in policy_t
 *
 * source      — local file path to the JWKS file (arena str_t)
 * require_kid — if 1, tokens without kid → FAIL TL-V009 immediately;
 *               if 0, fallback candidate resolution is used
 * ========================================================================= */

typedef struct {
    str_t  source;       /* local file path; never a URL in v1 */
    int    require_kid;  /* default 0 (false)                  */
} jwks_policy_t;


/* =========================================================================
 * claim_rule_operator_t — operator enum for claim_rule_t
 *
 * Full evaluation engine is v2.  In v1 only the required field is evaluated
 * (producing TL-C001 on absence).  The operator and values/pattern fields
 * are parsed and stored for forward compatibility but not evaluated.
 * ========================================================================= */

typedef enum {
    CLAIM_OP_DENY_ANY      = 0,
    CLAIM_OP_ALLOW_ONLY    = 1,
    CLAIM_OP_REQUIRE_MATCH = 2,
    CLAIM_OP_DENY_MATCH    = 3,
    CLAIM_OP_REQUIRE_ANY   = 4,
    CLAIM_OP_REQUIRE_ALL   = 5
} claim_rule_operator_t;

typedef enum {
    CLAIM_TYPE_UNSET       = 0,
    CLAIM_TYPE_STRING      = 1,
    CLAIM_TYPE_STRING_LIST = 2,
    CLAIM_TYPE_NUMBER      = 3,
    CLAIM_TYPE_BOOLEAN     = 4
} claim_type_t;

typedef enum {
    CLAIM_NORMALIZE_NONE           = 0,
    CLAIM_NORMALIZE_SPACE_DELIMITED = 1
} claim_normalize_t;


/* =========================================================================
 * claim_rule_t — one entry in the claim_rules array
 *
 * In v1 only required is evaluated.  All other fields are stored for v2.
 * ========================================================================= */

typedef struct {
    str_t                 claim;       /* claim name                        */
    claim_rule_operator_t op;          /* operator enum                     */
    int                   required;    /* if 1: absent claim = TL-C001      */
    claim_type_t          type;        /* CLAIM_TYPE_UNSET if not specified  */
    claim_normalize_t     normalize;   /* CLAIM_NORMALIZE_NONE by default   */

    /* Populated for deny_any / allow_only / require_any / require_all */
    str_t  *values;       /* arena-allocated array; NULL if not applicable */
    size_t  value_count;

    /* Populated for require_match / deny_match */
    str_t   pattern;      /* POSIX ERE string; STR_NULL if not applicable  */

    str_t   description;  /* audit trail only; not evaluated               */
} claim_rule_t;


/* =========================================================================
 * policy_t — the normalised trust model
 *
 * The central data structure.  All evaluation functions consume this.
 * Produced by policy_parse(); never mutated after that point.
 *
 * A _Static_assert in src/parse/policy_parser.c enforces sizeof(policy_t) < 4096.
 * ========================================================================= */

typedef struct {
    /* Identity */
    str_t           validator_id;    /* non-empty; max 128 chars            */
    environment_t   environment;

    /* Compiled matchers */
    issuer_matcher_t    issuers;
    audience_matcher_t  audiences;
    alg_allowset_t      algorithms;

    /* Required claims bitmask (CLAIM_* bits) */
    uint32_t  required_registered_claims;

    /* Custom required claims (from claim_rules with required:true in v1) */
    str_t    *required_custom_claims;
    size_t    required_custom_claim_count;

    /* Time limits */
    time_limits_t  time_limits;

    /* JWKS policy */
    jwks_policy_t  jwks_policy;

    /* Claim rules (stored for v2 evaluation; v1 uses only required field) */
    claim_rule_t  *claim_rules;
    size_t         claim_rule_count;

    /* Suppressions */
    suppression_t  *suppressions;
    size_t          suppression_count;

    /* Schema version (always "tokenlint.validator.v1" in v1) */
    str_t  schema_version;
} policy_t;


/* =========================================================================
 * policy_parse — parse and validate a policy YAML file into a policy_t
 *
 * Declared here; implemented in src/parse/policy_parser.c.
 *
 * Reads the YAML file at path, validates schema, emits TL-S findings into fs,
 * and returns a fully-populated policy_t via *out on success.
 *
 * On schema halt (e.g. TL-S001, TL-S002):
 *   Adds the finding to fs and returns TL_ERR_SCHEMA.
 *   *out is not modified.
 *
 * On I/O failure:
 *   Returns TL_ERR_IO.  No findings added (the file itself is unreadable).
 *
 * On success:
 *   Returns TL_OK.
 *   *out points to an arena-allocated, fully-populated policy_t.
 *   Non-fatal schema findings (e.g. TL-S021, TL-S022) are in fs but
 *   TL_OK is still returned.
 *
 * Parameters:
 *   arena — run arena; all allocations made here
 *   path  — NUL-terminated path to the policy YAML file
 *   fs    — finding set; schema findings added here
 *   out   — receives pointer to parsed policy_t on success
 *
 * TL_NONNULL(1, 2, 3, 4): all parameters must not be NULL.
 */
TL_NODISCARD TL_NONNULL(1, 2, 3, 4)
tl_error_t policy_parse(arena_t       *arena,
                         const char    *path,
                         finding_set_t *fs,
                         policy_t     **out);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKENLINT_POLICY_H */
