# Time Contract — tokenlint v1

---

## Core principle

Time is the only source of non-determinism in tokenlint's evaluation. All
time-sensitive evaluation uses a single `reference_time` fixed at invocation start.
`reference_time` never changes during a run.

**Unknown against declared policy is a failure.**  
If the policy declares `max_ttl_seconds` but the token lacks `iat`, tokenlint
cannot verify the constraint. This is FAIL, not WARN.

---

## Reference time

### Source and precedence

| Source | Behavior |
|---|---|
| `--at` absent | Use system clock |
| `--at now` | Use system clock; record source as `cli_at_now` |
| `--at <unix>` | Use exact Unix epoch seconds |
| `--at <ISO8601Z>` | Use parsed timestamp |

`reference_time` is fixed at the moment of JWKS load, before any token evaluation.
The same value is used for all checks in the run and all tokens in multi-token runs.

### `--at` format contract

| Format | Example | Valid |
|---|---|---|
| Unix epoch integer | `1746000000` | yes |
| ISO 8601 with Z | `2026-04-30T12:00:00Z` | yes |
| ISO 8601 with offset | `2026-04-30T08:00:00-04:00` | yes |
| Shorthand | `now` | yes |
| ISO 8601 without timezone | `2026-04-30T12:00:00` | **NO** → FAIL TL-I001 |
| Negative integer | `-1` | **NO** → FAIL TL-I001 |
| Before Unix epoch | any pre-1970 | **NO** → FAIL TL-I001 |
| Future timestamp | any future | yes (no finding) |
| Unparseable string | `yesterday` | **NO** → FAIL TL-I001 |

### Output block

Always present in JSON output:

```json
{
  "reference_time": {
    "value": "2026-04-30T12:00:00Z",
    "source": "system_clock | cli_at | cli_at_now"
  }
}
```

`value` is always ISO 8601 with Z suffix, even if `--at` was provided as a Unix
timestamp. Consumers never need to handle multiple time formats.

---

## Time-sensitive claims

| Claim | Role | Absence behavior |
|---|---|---|
| `exp` | Expiration time — token must not be accepted at or after | No expiration (unbounded TTL) |
| `nbf` | Not before — token must not be accepted before | Valid from issuance |
| `iat` | Issued at — used to compute TTL (`exp - iat`) | TTL unverifiable |
| `jti` | JWT ID | Not a time claim — excluded from time checks |

---

## Clock skew

**Clock skew applies to `nbf` only. It never applies to `exp`.**

Expired means expired. Clock skew is a practical accommodation for distributed
systems where a token might arrive slightly before clocks agree. It is not a
grace period for expiration.

### `exp` check (no skew)

```
FAIL if: reference_time >= exp
```

No skew applied. Ever. The `--lenient` flag does not affect this check.

### `nbf` check (with skew)

```
FAIL if: reference_time < (nbf - max_clock_skew_seconds)
PASS if: reference_time >= (nbf - max_clock_skew_seconds)
```

Skew source: `limits.max_clock_skew_seconds`  
Default: 60 seconds  
Max before finding: 300s (WARN TL-A009, v2); 900s (FAIL TL-A009, v2)

---

## `iat` and TTL verification

### Implicit requirements

If `limits.max_ttl_seconds` is set:
- Both `iat` **and** `exp` are implicitly required
- Regardless of `requires.claims` content
- `iat` absent + `max_ttl_seconds` set → FAIL TL-V020
- `exp` absent + `max_ttl_seconds` set → FAIL TL-V021

Rationale: `max_ttl_seconds` is a policy trust claim. "I require bounded token
lifetime." Without `iat`, that claim cannot be verified. Unverifiable = FAIL.

These findings are suppressible (unlike schema findings) because teams working
toward full TTL enforcement can suppress with accountability while they migrate.

### TTL computation

When both `exp` and `iat` are present:

```
token_ttl = exp - iat

token_ttl <= 0:
  FAIL TL-V024 TOKEN_TTL_INVALID
  Token expired at or before issuance — malformed

token_ttl > max_ttl_seconds:
  FAIL TL-V025 TOKEN_TTL_EXCEEDED

token_ttl <= max_ttl_seconds:
  PASS
```

### `iat` in the future

```
iat > reference_time:
  WARN TL-W021 TOKEN_IAT_FUTURE (v2)
  Not a FAIL — clock skew can legitimately cause this
  Informational finding for engineer judgment
```

---

## Evaluation order

All time checks are independent. No short-circuit between them.

```
1. Resolve reference_time from --at or system clock
2. Check exp presence (if in requires.claims)
3. Check exp validity: reference_time >= exp → FAIL TL-V022
4. Check nbf presence (if in requires.claims)
5. Check nbf validity: reference_time < nbf - skew → FAIL TL-V023
6. Check iat presence (if max_ttl_seconds set)
7. If exp + iat both present: compute and verify TTL
8. Emit all time findings
```

---

## Forensic usage

```bash
# Reproduce exactly what tokenlint would have seen at incident time
tokenlint validate \
  --token incident.jwt \
  --policy payments-api.yaml \
  --jwks keys-at-incident.json \
  --at 2026-03-15T14:32:00Z \
  --format json
```

Output includes:
```json
{
  "reference_time": {
    "value": "2026-03-15T14:32:00Z",
    "source": "cli_at"
  }
}
```

Result is fully reproducible. Same command produces same output regardless of
when it is run. Safe for incident reports, runbooks, and audit trails.

---

## Finding summary

| ID | Name | Suppressible | Description |
|---|---|---|---|
| TL-I001 | AT_FLAG_INVALID | No | `--at` value unparseable, ambiguous, or out of range |
| TL-V020 | IAT_ABSENT_TTL_UNVERIFIABLE | Yes | `iat` absent, `max_ttl_seconds` set |
| TL-V021 | EXP_ABSENT_TTL_UNVERIFIABLE | Yes | `exp` absent, `max_ttl_seconds` set |
| TL-V022 | TOKEN_EXPIRED | No | `reference_time >= exp` |
| TL-V023 | TOKEN_NOT_YET_VALID | Yes | `reference_time < nbf - clock_skew` |
| TL-V024 | TOKEN_TTL_INVALID | No | `exp - iat <= 0` |
| TL-V025 | TOKEN_TTL_EXCEEDED | Yes | `exp - iat > max_ttl_seconds` |
| TL-W021 | TOKEN_IAT_FUTURE | Yes (v2) | `iat` is ahead of `reference_time` |
| TL-A007 | TTL_UNBOUNDED | Yes | `max_ttl_seconds` absent from policy |
