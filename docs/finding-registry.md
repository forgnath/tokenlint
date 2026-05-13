# Finding Registry — tokenlint v1

All 41 findings shipped in v1. Every finding has a stable ID, symbolic name,
severity, suppressibility status, and brief description.

The finding registry is the test manifest. Every finding listed here requires:
- `test_<ID>_fires()` — proves the finding fires correctly
- `test_<ID>_no_fire()` — proves the finding does not fire incorrectly

CI enforces this. A finding without both tests blocks release.

---

## Namespace overview

| Prefix | Namespace | Count |
|---|---|---|
| TL-S | Schema and structural findings | 20 |
| TL-A | Audit findings (policy-only) | 6 |
| TL-V | Token validation findings | 13 |
| TL-C | Claim findings | 1 |
| TL-I | Input/invocation errors | 1 |
| **Total** | | **41** |

---

## Suppressibility rules

- **Non-suppressible**: finding is always active regardless of suppression entries or flags
- **Suppressible**: finding can be suppressed via policy suppression block with owner/reason/expiry
- **Never suppressible**: TL-S0xx schema findings — if the policy is malformed, tokenlint cannot reason about trust

---

## TL-S — Schema and structural findings

These fire during policy parsing and schema validation. They indicate that the
policy file itself is malformed, ambiguous, or self-contradictory.

Schema findings (TL-S0xx) are never suppressible. A suppression entry in a broken
policy file is meaningless.

| ID | Name | Severity | Suppressible | Description |
|---|---|---|---|---|
| TL-S001 | TOKEN_ALG_NONE | critical | **No** | `alg=none` seen in token header. Halt. No verification attempted. |
| TL-S002 | POLICY_ALG_NONE | critical | **No** | `none` present in `accepts.algorithms`. Schema parse halt. |
| TL-S003 | FIELD_VALUE_INVALID | fail | No | Zero, negative, or semantically impossible field value. |
| TL-S004 | ENVIRONMENT_INVALID | fail | No | `environment` not in `prod\|stage\|dev\|test\|unknown`. |
| TL-S005 | TOKEN_TYPE_EMPTY | fail | No | `accepts.token_types` is empty array. |
| TL-S006 | TOKEN_TYPE_UNSUPPORTED | fail | No | Token type value not `jwt` in v1. |
| TL-S007 | TOKEN_TYPE_MULTIPLE | fail | No | More than one `token_type` declared. |
| TL-S008 | MODE_UNSUPPORTED | fail | No | Issuer or audience `mode` not `exact` in v1. |
| TL-S009 | FIELD_EMPTY | fail | No | Required array or string field is empty. |
| TL-S010 | ALG_UNRECOGNIZED | fail | No | Algorithm string not in v1 recognized set. |
| TL-S011 | JWKS_URL_SOURCE | fail | No | `jwks.source` is a URL, not a local path. |
| TL-S012 | REGEX_INVALID | fail | No | Unparseable POSIX ERE pattern in claim rule. |
| TL-S013 | CLAIM_RULE_CONFLICT | fail | No | `deny_any` + `allow_only` on same claim — contradictory operators. |
| TL-S014 | CLAIM_RULE_UNSATISFIABLE | fail | No | `require_all` value matches `deny_any` pattern — rule can never be satisfied. |
| TL-S015 | CLAIM_RULE_MISSING_FIELD | fail | No | Operator declared without required `values` or `pattern` field. |
| TL-S020 | SUPPRESSION_MISSING_REQUIRED_FIELD | fail | No | Suppression entry missing `reason` or `owner`. |
| TL-S021 | SUPPRESSION_UNKNOWN_FINDING_ID | warn | No | Suppression references finding code not in v1 registry. |
| TL-S022 | SUPPRESSION_EXPIRED | warn | No | Suppression expiry date is in the past. Finding reactivated. |
| TL-S023 | SUPPRESSION_EXPIRING_SOON | warn | No | Suppression expires within 14 days (configurable). |
| TL-S024 | SUPPRESSION_PROD_MISSING_EXPIRY | fail | No | Prod environment suppression has no `expires` field. |

---

## TL-A — Audit findings

These fire during `tokenlint audit` against a policy file alone. No token needed.
They represent dangerous trust assumptions that are detectable from the policy
alone, before any token ever arrives.

| ID | Name | Severity | Suppressible | Description |
|---|---|---|---|---|
| TL-A002 | ISSUER_HTTP_PROD | critical | Yes | `http://` scheme issuer declared in prod policy. Non-TLS issuer cannot be trusted. |
| TL-A003 | ISSUER_LOCALHOST_PROD | critical | Yes | `localhost`, `127.0.0.1`, or `::1` issuer in prod policy. |
| TL-A004 | AUDIENCE_WILDCARD | critical | Yes | `*` or empty string in `accepts.audiences.values`. |
| TL-A005 | POLICY_ALG_SYMMETRIC_PROD | critical | Yes | `HS256`, `HS384`, or `HS512` in `accepts.algorithms` with `environment: prod`. |
| TL-A007 | TTL_UNBOUNDED | fail | Yes | `max_ttl_seconds` absent from `limits` block. Token lifetime is unconstrained. |
| TL-A014 | REQUIRED_CLAIM_MISSING | fail | Yes | `exp`, `iss`, or `aud` absent from `requires.claims`. |

---

## TL-V — Token validation findings

These fire during `tokenlint validate`. They require both a token and a policy.
They represent violations of the declared trust model by the token under evaluation.

| ID | Name | Severity | Suppressible | Description |
|---|---|---|---|---|
| TL-V000 | TOKEN_UNPARSEABLE | fail | No | JWT structure invalid or unreadable. Halt. |
| TL-V001 | TOKEN_ALG_ABSENT | fail | No | `alg` field missing from token header. |
| TL-V002 | TOKEN_ALG_UNRECOGNIZED | fail | No | Token `alg` not in v1 recognized algorithm set. |
| TL-V003 | TOKEN_ALG_NOT_ALLOWED | fail | Yes | Token `alg` not in `accepts.algorithms`. |
| TL-V004 | TOKEN_ALG_KEY_INCOMPATIBLE | fail | Yes | Token `alg` incompatible with matched key `kty`/`crv`. |
| TL-V005 | TOKEN_ALG_KEY_ALG_CONFLICT | fail | Yes | Token `alg` conflicts with explicit `alg` field on JWKS key. |
| TL-V006 | TOKEN_SIG_INVALID | critical | No | Signature verification failed. |
| TL-V009 | TOKEN_KID_ABSENT_STRICT | fail | Yes | `require_kid: true` and token has no `kid` in header. |
| TL-V010 | TOKEN_KID_NO_MATCH | fail | Yes | `kid` present in token but no matching key found in JWKS. |
| TL-V011 | TOKEN_SIG_UNVERIFIABLE | fail | Yes | No candidate key verified token signature. |
| TL-V012 | TOKEN_SIG_AMBIGUOUS | fail | Yes | Multiple JWKS keys verified token signature. Trust model is ambiguous. |
| TL-V020 | IAT_ABSENT_TTL_UNVERIFIABLE | fail | Yes | `iat` absent; `max_ttl_seconds` set in policy. Cannot verify token lifetime. |
| TL-V021 | EXP_ABSENT_TTL_UNVERIFIABLE | fail | Yes | `exp` absent; `max_ttl_seconds` set in policy. Cannot verify token lifetime. |
| TL-V022 | TOKEN_EXPIRED | fail | No | `reference_time >= exp`. Expired means expired. No grace period. |
| TL-V023 | TOKEN_NOT_YET_VALID | fail | Yes | `reference_time < nbf - clock_skew`. Token not yet valid. |
| TL-V024 | TOKEN_TTL_INVALID | fail | No | `exp - iat <= 0`. Token expired at or before issuance. Malformed. |
| TL-V025 | TOKEN_TTL_EXCEEDED | fail | Yes | `exp - iat > max_ttl_seconds`. Token lifetime exceeds policy limit. |

---

## TL-C — Claim findings

The full claim rule evaluation engine is v2. Only the presence check ships in v1.

| ID | Name | Severity | Suppressible | Description |
|---|---|---|---|---|
| TL-C001 | CLAIM_ABSENT_REQUIRED | fail | Yes | Claim absent from token; claim rule has `required: true`. |

---

## TL-I — Input and invocation errors

These fire before evaluation begins. They indicate invalid CLI input that prevents
tokenlint from constructing a valid evaluation context.

| ID | Name | Severity | Suppressible | Description |
|---|---|---|---|---|
| TL-I001 | AT_FLAG_INVALID | fail | No | `--at` value is unparseable, ambiguous (missing timezone), or out of range. |

---

## Non-suppressible findings summary

The following findings can never be suppressed, regardless of policy suppression
entries, `--suppress` flags, or `--lenient` mode:

```
TL-S001  TOKEN_ALG_NONE
TL-S002  POLICY_ALG_NONE
TL-S003  FIELD_VALUE_INVALID
TL-S004  ENVIRONMENT_INVALID
TL-S005  TOKEN_TYPE_EMPTY
TL-S006  TOKEN_TYPE_UNSUPPORTED
TL-S007  TOKEN_TYPE_MULTIPLE
TL-S008  MODE_UNSUPPORTED
TL-S009  FIELD_EMPTY
TL-S010  ALG_UNRECOGNIZED
TL-S011  JWKS_URL_SOURCE
TL-S012  REGEX_INVALID
TL-S013  CLAIM_RULE_CONFLICT
TL-S014  CLAIM_RULE_UNSATISFIABLE
TL-S015  CLAIM_RULE_MISSING_FIELD
TL-S020  SUPPRESSION_MISSING_REQUIRED_FIELD
TL-S021  SUPPRESSION_UNKNOWN_FINDING_ID
TL-S022  SUPPRESSION_EXPIRED
TL-S023  SUPPRESSION_EXPIRING_SOON
TL-S024  SUPPRESSION_PROD_MISSING_EXPIRY
TL-V000  TOKEN_UNPARSEABLE
TL-V001  TOKEN_ALG_ABSENT
TL-V002  TOKEN_ALG_UNRECOGNIZED
TL-V006  TOKEN_SIG_INVALID
TL-V022  TOKEN_EXPIRED
TL-V024  TOKEN_TTL_INVALID
TL-I001  AT_FLAG_INVALID
```

---

## v2 reserved namespaces

| Prefix | Namespace | Status |
|---|---|---|
| TL-C002+ | Claim rule evaluation engine | v2 |
| TL-G | Gap mode findings | v2 |
| TL-W | Warning and advisory findings | v2 |
| TL-A001 | ISSUER_WILDCARD | v2 |
| TL-A008 | TTL_EXCESSIVE | v2 |
| TL-A009 | CLOCK_SKEW_EXCESSIVE | v2 |
| TL-A010 | KID_NOT_REQUIRED | v2 |
| TL-A011 | JWKS_REMOTE_PROD | v2 (caught by TL-S011 in v1) |
| TL-A012 | DEV_ISSUER_PROD | v2 |
