# Architecture — tokenlint v1

---

## The parse/eval boundary

The most important architectural decision in tokenlint is the hard boundary between
the parse layer and the evaluation layer.

```
YAML file
    ↓
src/parse/policy_parser.c    libyaml → raw fields → policy_t
    ↓
policy_t                     compiled, evaluation-ready trust model
    ↓
src/eval/eval_audit.c        pure logic against policy_t
src/eval/eval_validate.c     pure logic against policy_t + token_t + jwks_t
```

**The evaluator never asks `if (strcmp(mode, "exact") == 0)`.**  
That question was answered at parse time. By the time evaluation runs, the model
contains compiled matchers, bitmasks, and typed structs.

The boundary is enforced mechanically by include path control. `src/eval/` has no
access to `vendor/libyaml/include/` or `vendor/mbedtls/include/`. This is not a
convention — it is a compile error if violated.

---

## Memory model

### Arena allocation

All memory for a single run comes from one arena. Free the arena, free everything.
No ownership tracking, no per-struct free logic.

```c
arena_t *arena = arena_new(MB(4));
// ... all allocations via arena_alloc(arena, ...) ...
arena_free(arena);   // frees everything
```

This eliminates an entire class of memory bugs and is natural for a tool that
parses once, evaluates, and exits.

### String representation

All strings are length-carrying `str_t` structs. No `strlen()` calls in evaluation
code. No null-terminator assumptions.

```c
typedef struct {
    const char *data;   /* points into arena, not owned */
    size_t      len;
} str_t;
```

### Finding collection

Fixed-capacity array of 256 findings. Overflow is explicit and never silent.

```c
#define TL_MAX_FINDINGS 256

typedef struct {
    finding_t findings[TL_MAX_FINDINGS];
    size_t    count;
    int       overflowed;    /* set if count would exceed cap */
} finding_set_t;
```

If overflow occurs: `TL_ERR_INTERNAL` is emitted in the error envelope. The first
256 findings are included. Nothing is silently dropped.

---

## Core structs

### Primitive types

```c
/* Bounded string — no strlen() in evaluation code */
typedef struct {
    const char *data;
    size_t      len;
} str_t;

#define STR_NULL    ((str_t){ NULL, 0 })
#define STR_IS_NULL(s) ((s).data == NULL)

static inline int str_eq(str_t a, str_t b) {
    return a.len == b.len &&
           memcmp(a.data, b.data, a.len) == 0;
}
```

### Finding

```c
typedef enum {
    SEV_INFO     = 0,
    SEV_WARN     = 1,
    SEV_FAIL     = 2,
    SEV_CRITICAL = 3
} severity_t;

typedef enum {
    FINDING_ACTIVE,
    FINDING_SUPPRESSED_POLICY,
    FINDING_SUPPRESSED_CLI,
    FINDING_SKIPPED
} finding_status_t;

typedef struct {
    str_t            id;
    str_t            title;
    str_t            detail;
    str_t            policy_path;
    severity_t       severity;
    finding_status_t status;

    struct {
        str_t  source;
        str_t  reason;
        str_t  owner;
        str_t  ticket;
        str_t  expires;
        int    expires_in_days;
        int    affects_exit;
    } suppression;
} finding_t;
```

### Tool error (halt condition)

```c
typedef enum {
    TL_ERR_NONE = 0,
    TL_ERR_SCHEMA,
    TL_ERR_JWKS,
    TL_ERR_TOKEN,
    TL_ERR_AT_FLAG,
    TL_ERR_IO,
    TL_ERR_INTERNAL
} tl_err_kind_t;

typedef struct {
    tl_err_kind_t kind;
    str_t         message;
    str_t         context;
} tl_error_t;

#define TL_OK ((tl_error_t){ TL_ERR_NONE, STR_NULL, STR_NULL })
```

`finding_t` and `tl_error_t` are distinct types. A finding is data — collected,
reported, and output. An error is a halt condition — print and exit.

### Compiled matchers (the normalized layer)

```c
/* Issuer matcher — v1: exact only */
typedef struct {
    issuer_mode_t  mode;      /* ISSUER_MODE_EXACT */
    str_t         *values;    /* arena-allocated array */
    size_t         count;
} issuer_matcher_t;

/* Audience matcher — v1: exact only */
typedef struct {
    audience_mode_t  mode;
    str_t           *values;
    size_t           count;
} audience_matcher_t;

/* Algorithm allowset — bitmask over alg_id_t */
typedef enum {
    ALG_NONE_ALG = 0,
    ALG_RS256, ALG_RS384, ALG_RS512,
    ALG_PS256, ALG_PS384, ALG_PS512,
    ALG_ES256, ALG_ES384, ALG_ES512,
    ALG_ECDSA_EDDSA,
    ALG_HS256, ALG_HS384, ALG_HS512,
    ALG_COUNT_
} alg_id_t;

typedef struct {
    uint32_t bits;
} alg_allowset_t;

_Static_assert(ALG_COUNT_ <= 32, "alg_id_t exceeds bitmask capacity");

#define ALLOWSET_CONTAINS(s, alg) (((s).bits & (1u << (alg))) != 0)
```

### policy_t — the normalized trust model

```c
typedef struct {
    /* identity */
    str_t           validator_id;
    environment_t   environment;

    /* compiled matchers */
    issuer_matcher_t    issuers;
    audience_matcher_t  audiences;
    alg_allowset_t      algorithms;

    /* required claims */
    uint32_t  required_registered_claims;   /* bitmask */
    str_t    *required_custom_claims;
    size_t    required_custom_claim_count;

    /* limits */
    time_limits_t  time_limits;

    /* JWKS policy */
    jwks_policy_t  jwks_policy;

    /* suppressions */
    suppression_t  *suppressions;
    size_t          suppression_count;

    /* schema version */
    str_t  schema_version;
} policy_t;

/* Required claim bitmask positions */
#define CLAIM_ISS  (1u << 0)
#define CLAIM_SUB  (1u << 1)
#define CLAIM_AUD  (1u << 2)
#define CLAIM_EXP  (1u << 3)
#define CLAIM_NBF  (1u << 4)
#define CLAIM_IAT  (1u << 5)
#define CLAIM_JTI  (1u << 6)
```

### token_t — normalized JWT

```c
typedef struct {
    /* header */
    alg_id_t  alg;
    str_t     kid;

    /* registered claims */
    str_t    iss;
    str_t    sub;
    str_t   *aud;
    size_t   aud_count;
    int64_t  exp;       /* 0 if absent */
    int64_t  nbf;       /* 0 if absent */
    int64_t  iat;       /* 0 if absent */
    str_t    jti;

    /* presence bitmask */
    uint32_t present_claims;

    /* raw bytes for verification */
    const uint8_t *sig;
    size_t         sig_len;
    const uint8_t *signing_input;
    size_t         signing_input_len;
} token_t;
```

`aud` is always normalized to an array, regardless of whether the source JWT had
a string or array value.

### jwks_t — frozen key set

```c
typedef struct {
    str_t       kid;
    kty_t       kty;
    crv_t       crv;
    key_use_t   use;
    alg_id_t    declared_alg;
    const void *key_material;
    size_t      key_material_len;
} jwks_key_t;

typedef struct {
    jwks_key_t *keys;
    size_t      count;
} jwks_t;
```

### eval_ctx_t — evaluation context

```c
typedef struct {
    const policy_t    *policy;
    const jwks_t      *jwks;
    const token_t     *token;        /* NULL during audit mode */
    int64_t            reference_time;
    reftime_source_t   reference_time_source;
    finding_set_t     *findings;
    arena_t           *arena;
} eval_ctx_t;
```

The `eval_ctx_t` is the complete universe of an evaluation. All `eval_*` functions
take a pointer to `eval_ctx_t`. No global state.

---

## Parse/eval boundary — enforced by function signatures

```c
/*
 * Parse layer — produce normalized structs.
 * These are the ONLY functions that touch raw YAML, raw JWT strings,
 * or mbedTLS APIs.
 */
tl_error_t policy_parse(arena_t *a, const char *path,
                         finding_set_t *fs, policy_t **out);

tl_error_t jwks_load(arena_t *a, const char *path,
                      finding_set_t *fs, jwks_t **out);

tl_error_t token_parse(arena_t *a, str_t raw_jwt,
                        finding_set_t *fs, token_t **out);

/*
 * Evaluation layer — consume normalized structs only.
 * No string parsing. No mode checking. No normalization.
 * Pure logic against compiled model.
 */
void eval_audit   (eval_ctx_t *ctx);
void eval_validate(eval_ctx_t *ctx);
```

---

## Dependency isolation

Third-party APIs must not leak into core evaluation code.

| Dependency | Permitted in | Enforced by |
|---|---|---|
| libyaml | `src/parse/` only | Makefile include path control |
| mbedTLS | `src/crypto/` only | Makefile include path control |
| json_writer | `src/output/` only | Convention |

Attempting to `#include <yaml.h>` from `src/eval/` is a compile error — the
header is not in the include path for that directory.

### Crypto adapter interface

mbedTLS is never called directly from outside `src/crypto/crypto_backend.c`.
The adapter exposes:

```c
typedef enum {
    TL_VERIFY_OK,
    TL_VERIFY_FAIL,
    TL_VERIFY_UNSUPPORTED,
    TL_VERIFY_ERROR
} tl_verify_result_t;

tl_verify_result_t tl_verify_signature(
    alg_id_t          alg,
    const jwks_key_t *key,
    const uint8_t    *signing_input,
    size_t            signing_input_len,
    const uint8_t    *sig,
    size_t            sig_len
);

tl_error_t tl_base64url_decode(
    arena_t       *arena,
    const char    *input,
    size_t         input_len,
    uint8_t      **out,
    size_t        *out_len
);
```

No mbedTLS types are visible outside `src/crypto/crypto_backend.c`.

---

## File layout

```
tokenlint/
│
├── VERSION
├── README.md
├── LICENSE
├── Makefile
│
├── include/                    shared headers
│   ├── tokenlint.h             str_t, arena_t, tl_error_t
│   ├── policy.h                policy_t, matchers
│   ├── token.h                 token_t
│   ├── jwks.h                  jwks_t, jwks_key_t
│   ├── findings.h              finding_t, finding_set_t
│   ├── eval_ctx.h              eval_ctx_t
│   └── alg.h                   alg_id_t, alg_allowset_t
│
├── src/
│   ├── main.c                  CLI dispatch only, no business logic
│   ├── cli/
│   │   ├── cli.h
│   │   └── cli.c               argument parsing, stdin detection
│   ├── parse/                  ← only dir that may use libyaml
│   │   ├── policy_parser.c     libyaml → policy_t
│   │   ├── token_parser.c      JWT string → token_t
│   │   └── jwks_parser.c       JWKS JSON → jwks_t
│   ├── crypto/                 ← only dir that may use mbedTLS
│   │   ├── crypto_backend.h    tl_verify_signature(), tl_base64url_decode()
│   │   └── crypto_backend.c    mbedTLS calls only
│   ├── eval/                   ← no vendor headers permitted
│   │   ├── eval_audit.c        TL-A findings
│   │   ├── eval_validate.c     TL-V, TL-C findings
│   │   ├── eval_alg.c          algorithm + key checks
│   │   ├── eval_time.c         time-sensitive claim checks
│   │   ├── eval_issuer.c
│   │   ├── eval_audience.c
│   │   └── findings.c          findings_add(), overflow detection
│   ├── output/
│   │   ├── json_writer.c       jw_* interface, jw_escape()
│   │   ├── report_json.c       finding_set_t → JSON envelope
│   │   └── report_text.c       finding_set_t → text output
│   └── util/
│       ├── arena.c
│       ├── str.c
│       └── time_util.c
│
├── tests/
│   ├── unit/                   per-module unit tests
│   ├── integration/            end-to-end mode tests
│   ├── security_properties/    named regression tests
│   ├── cli/                    shell contract tests
│   ├── fixtures/               static test data
│   │   ├── policies/
│   │   ├── tokens/
│   │   ├── jwks/
│   │   ├── expected/
│   │   ├── gen_fixtures.sh     fixture generation script
│   │   └── MANIFEST.md         fixture documentation
│   └── helpers/
│       ├── test_runner.h
│       ├── policy_builder.h    construct policy_t without YAML
│       └── token_builder.h     construct token_t without JWT parsing
│
├── vendor/
│   ├── libyaml/
│   │   ├── UPSTREAM_VERSION
│   │   └── ...
│   └── mbedtls/
│       ├── UPSTREAM_VERSION
│       └── ...
│
└── docs/
```

---

## _Static_assert usage

Used to catch configuration errors at compile time:

```c
/* src/crypto/crypto_backend.c */
_Static_assert(ALG_COUNT_ <= 32,
    "alg_id_t exceeds bitmask capacity of alg_allowset_t");

/* src/eval/findings.c */
_Static_assert(TL_MAX_FINDINGS <= 256,
    "finding capacity exceeds intended maximum");

/* src/parse/policy_parser.c */
_Static_assert(sizeof(policy_t) < 4096,
    "policy_t unexpectedly large; check for padding issues");
```

---

## No global state

Every function that needs evaluation context receives it via `eval_ctx_t *`.  
No global variables. No thread-local storage. No hidden state.  
The same evaluation code can be called multiple times with different contexts
(multi-token batch mode, v2) without interference.
