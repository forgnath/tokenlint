# Schema Contract — tokenlint.validator.v1

The policy file is a YAML document that describes what a service believes it
enforces about JWT trust. tokenlint audits the policy itself, then validates
tokens against it.

---

## Schema governance

### Strict mode (default)

| Condition | Behavior |
|---|---|
| Unknown field | FAIL TL-S002 with typo suggestion if edit distance ≤ 2 |
| Missing required field | FAIL TL-S002 |
| Deprecated field | WARN TL-S003 |
| Unknown `x_*` field | WARN TL-S004 |

### Lenient mode (`--lenient`)

| Condition | Behavior |
|---|---|
| Unknown field | WARN TL-S002 (not FAIL) |
| Missing required field | FAIL (never relaxed — required means required) |
| Deprecated field | WARN TL-S003 |
| Unknown `x_*` field | PASS (silently ignored) |

### Typo detection

On unknown field: compute Levenshtein distance against all known field names at
the same nesting level.
- Distance ≤ 2: `FAIL — Unknown field 'accepted_audience'. Did you mean: 'accepted_audiences'?`
- Distance > 2: `FAIL — Unknown field. See schema reference.`

### Schema versioning

- `v1 → v2`: breaking changes require a new `schema_version` string
- Deprecated fields carry a deprecation notice for one full major version before becoming errors
- No silent field removal

### Extension namespace

Any field prefixed `x_` at any nesting level is permitted as an extension.
- Unknown `x_*` fields: WARN in strict mode, PASS in lenient mode
- Extension fields are never evaluated by the audit or validate engine
- Purpose: metadata, ownership, ticket references, org context only

---

## Annotated schema

```yaml
schema_version: tokenlint.validator.v1   # required

validator:
  id: payments-api                        # required
  environment: prod                       # required

accepts:
  token_types:
    - jwt                                 # required; only "jwt" valid in v1

  issuers:
    mode: exact                           # required; only "exact" valid in v1
    values:
      - https://auth.company.com          # required; at least one value

  audiences:
    mode: exact                           # required; only "exact" valid in v1
    values:
      - payments-api                      # required; at least one value

  algorithms:
    - RS256                               # required; at least one value
    - PS256

jwks:
  source: ./keys.json                     # required; local path only in v1
  require_kid: true                       # optional; default false

requires:
  claims:                                 # required block
    - iss
    - sub
    - aud
    - exp
    - iat

limits:                                   # optional block; absence triggers TL-A007
  max_ttl_seconds: 3600
  max_clock_skew_seconds: 60

claim_rules:                              # optional; default []
  - claim: scope
    operator: deny_any
    required: true
    values:
      - "*"
      - "admin:*"

suppressions: []                          # optional; default []

x_company:                               # extension namespace; not evaluated
  owner: platform-security
  ticket: SEC-1234
```

---

## Field reference

### `schema_version`

| Property | Value |
|---|---|
| Type | string |
| Required | yes |
| Valid | `"tokenlint.validator.v1"` only |
| Invalid | Any other string — FAIL TL-S001, halt immediately |

### `validator`

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | yes | Non-empty, printable ASCII, max 128 chars. Used in output only, not trust logic. |
| `environment` | enum | yes | `prod \| stage \| dev \| test \| unknown` |

#### Environment behavior

| Environment | Symmetric alg severity | Suppression expiry | `forbid_dev_issuers` default |
|---|---|---|---|
| `prod` | critical (FAIL) | required | true |
| `stage` / `dev` / `test` | warn | optional | false |
| `unknown` | critical (FAIL) | required | true |

`unknown` is treated as `prod` for all security decisions. WARN TL-W001 emitted.

### `accepts`

#### `accepts.token_types`

| Property | Value |
|---|---|
| Type | string array |
| Required | yes |
| Valid | `["jwt"]` only in v1 |
| Empty | FAIL TL-S005 |
| Unknown value | FAIL TL-S006 |
| Multiple values | FAIL TL-S007 |

#### `accepts.issuers`

| Field | Type | Required | Notes |
|---|---|---|---|
| `mode` | enum | yes | `exact` only in v1. Other values: FAIL TL-S008 |
| `values` | string array | yes | Must be non-empty. Each value must be valid URI (RFC 3986). |

Issuer value rules:
- Trailing slash normalized before comparison
- Duplicate values: WARN TL-W002
- `http://` scheme in prod: FAIL TL-A002
- `localhost` / `127.0.0.1` / `::1` in prod: FAIL TL-A003
- More than one value in prod: WARN TL-W003 (v2)

#### `accepts.audiences`

| Field | Type | Required | Notes |
|---|---|---|---|
| `mode` | enum | yes | `exact` only in v1. Other values: FAIL TL-S008 |
| `values` | string array | yes | Must be non-empty. |

Audience value rules:
- `"*"` or `""` in values: FAIL TL-A004
- Duplicate values: WARN TL-W002 (v2)
- Multiple values: WARN TL-W004 (v2)

#### `accepts.algorithms`

| Property | Value |
|---|---|
| Type | string array |
| Required | yes |
| Empty | FAIL TL-S009 |
| `none` | FAIL TL-S002, non-suppressible |
| Unknown string | FAIL TL-S010 |
| Duplicate values | WARN TL-W002 (v2) |

Recognized algorithm strings:

| String | Family | Notes |
|---|---|---|
| `RS256` | RSA PKCS1-v1_5 | permitted |
| `RS384` | RSA PKCS1-v1_5 | permitted |
| `RS512` | RSA PKCS1-v1_5 | permitted |
| `PS256` | RSA-PSS | permitted |
| `PS384` | RSA-PSS | permitted |
| `PS512` | RSA-PSS | permitted |
| `ES256` | ECDSA P-256 | permitted |
| `ES384` | ECDSA P-384 | permitted |
| `ES512` | ECDSA P-521 | permitted |
| `EdDSA` | Ed25519 / Ed448 | Ed25519 supported; Ed448 recognized but fails TL-V002 |
| `HS256` | HMAC SHA-256 | prod: FAIL TL-A005; non-prod: WARN |
| `HS384` | HMAC SHA-384 | prod: FAIL TL-A005; non-prod: WARN |
| `HS512` | HMAC SHA-512 | prod: FAIL TL-A005; non-prod: WARN |
| `none` | no signature | FAIL TL-S002 always, non-suppressible |

### `jwks`

| Field | Type | Required | Notes |
|---|---|---|---|
| `source` | string | yes | Local file path only in v1. URL: FAIL TL-S011 |
| `require_kid` | boolean | no | Default: `false`. `false` in prod: WARN TL-W006 (v2) |

### `requires`

| Field | Type | Required | Notes |
|---|---|---|---|
| `claims` | string array | yes | List of claim names that must be present in every token |

Registered claims tokenlint understands natively: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`.

- `exp` absent from `requires.claims`: FAIL TL-A014
- `iss` absent from `requires.claims`: FAIL TL-A014
- `aud` absent from `requires.claims`: FAIL TL-A014
- `sub` absent: WARN TL-W008 (v2)
- Empty `claims` array: WARN TL-W007 (v2)

**Implicit requirements from `limits.max_ttl_seconds`:**  
If `max_ttl_seconds` is set, both `iat` and `exp` are implicitly required regardless
of `requires.claims` content. Absence of either produces TL-V020 or TL-V021 at
token evaluation time.

### `limits`

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `max_ttl_seconds` | positive integer | no | unset | Absence: FAIL TL-A007 |
| `max_clock_skew_seconds` | non-negative integer | no | 60 | > 300: WARN TL-A009 (v2); > 900: FAIL TL-A009 (v2) |

- `max_ttl_seconds` ≤ 0: FAIL TL-S003
- `max_ttl_seconds` > 604800 (7 days): FAIL TL-A008 (v2)
- `max_clock_skew_seconds` < 0: FAIL TL-S003
- Missing `limits` block entirely: WARN TL-W009 (v2)

### `claim_rules`

Each entry in the `claim_rules` array:

| Field | Type | Required | Notes |
|---|---|---|---|
| `claim` | string | yes | Claim name to evaluate |
| `operator` | enum | yes | `deny_any \| allow_only \| require_match \| deny_match \| require_any \| require_all` |
| `required` | boolean | no | Default: `false`. If `true`, absent claim = FAIL TL-C001 |
| `type` | enum | no | `string \| string_list \| number \| boolean` |
| `normalize` | enum | no | `space_delimited \| none`. Default: `none` |
| `values` | string array | conditional | Required for `deny_any`, `allow_only`, `require_any`, `require_all` |
| `pattern` | string | conditional | Required for `require_match`, `deny_match`. POSIX ERE. |
| `description` | string | no | Audit trail only, not evaluated |

**Conflict rules (same claim, multiple rules):**
- `deny_any` + `allow_only`: FAIL TL-S013 (contradictory)
- `require_any` + `allow_only`: FAIL TL-S013 (contradictory)
- Same operator, different values: merged, WARN TL-W011 (v2)
- `deny_any` + `deny_match`: valid, both evaluated
- `allow_only` + `require_match`: valid, both evaluated
- `require_all` value matches `deny_any` pattern: FAIL TL-S014 (unsatisfiable)

**Note:** Full claim rule evaluation is v2. In v1, only `required: true` (presence
check) is evaluated at token validation time, producing TL-C001 if absent.

### `suppressions`

See [suppression-contract.md](suppression-contract.md) for full specification.

```yaml
suppressions:
  - id: TL-A009                    # required; finding code
    reason: "..."                  # required; non-empty string
    owner: "platform-security"     # required; non-empty string
    ticket: "SEC-1234"             # optional
    expires: "2026-09-01"          # required if environment: prod
```

---

## Required fields summary

Fields where absence causes immediate FAIL:

```
schema_version
validator.id
validator.environment
accepts.token_types
accepts.issuers.mode
accepts.issuers.values
accepts.audiences.mode
accepts.audiences.values
accepts.algorithms
jwks.source
requires.claims
```

Fields where absence causes a finding (not halt):

```
limits block               → WARN TL-W009 (v2)
limits.max_ttl_seconds     → FAIL TL-A007
```

Fields where absence is silently defaulted:

```
jwks.require_kid           → false
limits.max_clock_skew_seconds → 60
claim_rules                → []
suppressions               → []
```
