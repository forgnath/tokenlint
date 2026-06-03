# Output Contract — tokenlint v1

---

## Design decisions

- **JSON default**: primary consumer is CI and scripts; human text is explicit (`--format text`)
- **Batch output**: collect all findings, emit once at end; no streaming in v1
- **Unified envelope**: every mode produces the same outer JSON shape
- **No TTY detection**: determinism over convenience; same flags = same output always
- **No SARIF in v1**: deferred to v2; finding shape is designed for easy SARIF mapping

---

## Formats

```
--format json    default
--format text    human-readable; explicit only

Unknown --format value:
  FAIL TL-I001 immediately
  "Unknown format 'xyz'. Valid values: json, text"
```

---

## JSON envelope

Every mode, every run produces this outer shape:

```json
{
  "schema_version": "tokenlint.report.v1",

  "tool": {
    "name": "tokenlint",
    "version": "1.0.0"
  },

  "mode": "audit | validate | inspect",

  "verdict": "pass | fail | warn | error",

  "exit_code": 0,

  "reference_time": {
    "value": "2026-04-30T12:00:00Z",
    "source": "system_clock | cli_at | cli_at_now"
  },

  "summary": {
    "total": 3,
    "active": 2,
    "suppressed": 1,
    "skipped": 0,
    "by_severity": {
      "critical": 0,
      "fail": 1,
      "warn": 1,
      "info": 0
    }
  },

  "inputs": {
    "policy": "./payments-api.yaml",
    "jwks": "./keys.json",
    "token": "stdin | <path> | null",
    "at_flag": "2026-04-30T12:00:00Z | null"
  },

  "findings": [],

  "details": {}
}
```

### Envelope field notes

| Field | Notes |
|---|---|
| `schema_version` | Always `"tokenlint.report.v1"` in v1. Consumers check this for version changes. |
| `tool.version` | Embedded at compile time via `-DTL_VERSION="..."`. Sourced from `VERSION` file. |
| `mode` | `"audit" \| "validate" \| "inspect"` — no other values in v1 |
| `verdict` | `"pass"` / `"warn"` / `"fail"` / `"error"` — matches exit code semantics |
| `exit_code` | Redundant with process exit code; useful for audit trails in JSON |
| `reference_time.value` | Always ISO 8601 with Z suffix, even if `--at` was a Unix timestamp |
| `summary.skipped` | TL-I001 class findings; only in verbose output for text format |
| `inputs.token` | `"stdin"` if read from stdin; file path if `--token <path>`; `null` for audit mode |
| `details` | Mode-specific content; empty object `{}` if mode has no additional detail |

---

## Finding object

```json
{
  "id": "TL-V003",
  "name": "TOKEN_ALG_NOT_ALLOWED",
  "severity": "fail",
  "status": "active",
  "message": "Token algorithm 'ES256' is not permitted by policy.",
  "detail": "Policy accepts: [RS256]. Token header declares: ES256. The token algorithm must appear in accepts.algorithms.",
  "location": {
    "input": "token",
    "path": "$.header.alg"
  },
  "help": "Add ES256 to accepts.algorithms only if intentionally supported. Verify key material supports ES256.",
  "suppression": null
}
```

### Finding field contract

| Field | Type | Notes |
|---|---|---|
| `id` | string | Finding code, e.g. `"TL-V003"`. Stable across versions within same major schema. |
| `name` | string | Symbolic name, e.g. `"TOKEN_ALG_NOT_ALLOWED"`. Screaming snake case. 1:1 with `id`. |
| `severity` | enum | `"critical" \| "fail" \| "warn" \| "info"` |
| `status` | enum | `"active" \| "suppressed_policy" \| "suppressed_cli" \| "skipped"` |
| `message` | string | One sentence, present tense, no trailing period. What was found. |
| `detail` | string | Full explanation including observed vs expected values. Never null. |
| `location.input` | enum | `"policy" \| "token" \| "jwks" \| "cli"` |
| `location.path` | string | JSONPath into relevant input. `null` if not applicable. |
| `help` | string | Actionable remediation, 1-2 sentences. `null` for non-suppressible findings. |
| `suppression` | object or null | See [suppression-contract.md](suppression-contract.md) |

### Severity semantics

| Severity | Exit code effect | Notes |
|---|---|---|
| `critical` | Causes exit 1 | Most dangerous findings; always block CI |
| `fail` | Causes exit 1 | Policy or token violations |
| `warn` | Causes exit 2 | Only if no critical/fail findings |
| `info` | No effect | Only emitted with `--verbose` |

### Location path examples

| Path | Meaning |
|---|---|
| `$.header.alg` | Token header field |
| `$.payload.exp` | Token claim |
| `$.accepts.algorithms[1]` | Policy field |
| `$.keys[0].alg` | JWKS key field |
| `$` | Top-level, no specific path |

---

## Mode-specific details blocks

### Audit mode

```json
{
  "details": {
    "policy": {
      "validator_id": "payments-api",
      "environment": "prod",
      "schema_version": "tokenlint.validator.v1"
    },
    "checks_run": [
      "issuer_safety",
      "audience_safety",
      "algorithm_safety",
      "required_claims",
      "ttl_bounds"
    ]
  }
}
```

### Validate mode

```json
{
  "details": {
    "policy": {
      "validator_id": "payments-api",
      "environment": "prod",
      "schema_version": "tokenlint.validator.v1"
    },
    "policy_audit": {
      "executed": true,
      "finding_count": 0,
      "findings_included": true
    },
    "token": {
      "alg": "RS256",
      "kid": "key-2026-01",
      "iss": "https://auth.company.com",
      "aud": ["payments-api"],
      "exp": "2026-04-30T13:00:00Z",
      "iat": "2026-04-30T12:00:00Z",
      "nbf": null,
      "ttl_seconds": 3600,
      "claims_present": ["iss", "sub", "aud", "exp", "iat"]
    },
    "key_used": {
      "kid": "key-2026-01",
      "kty": "EC",
      "crv": "P-256",
      "use": "sig",
      "alg": "ES256"
    },
    "checks_run": [
      "algorithm",
      "signature",
      "issuer",
      "audience",
      "expiration",
      "ttl",
      "required_claims"
    ]
  }
}
```

Notes:
- `details.token` time fields shown as ISO 8601 strings, not raw numeric values
- `details.token.aud` always shown as array
- `details.key_used` is `null` if signature verification was not reached
- `details.key_used` shows metadata only, never key material
- `policy_audit.executed: false` when `--skip-policy-audit` passed

### Inspect mode

```json
{
  "details": {
    "token": {
      "header": {
        "alg": "RS256",
        "kid": "key-2026-01",
        "alg_recognized": true,
        "alg_family": "asymmetric"
      },
      "claims": {
        "iss": "https://auth.company.com",
        "sub": "user-abc123",
        "aud": ["payments-api"],
        "exp": "2026-04-30T13:00:00Z",
        "exp_status": "valid | expired | unknown",
        "iat": "2026-04-30T12:00:00Z",
        "nbf": null,
        "jti": null,
        "ttl_seconds": 3600,
        "custom_claims": ["scope", "env"]
      },
      "signature": {
        "present": true,
        "verified": false,
        "note": "No JWKS provided. Signature not verified."
      }
    }
  }
}
```

---

## Error envelope

When a halt condition occurs, the envelope is still emitted. Findings collected
before the halt are included. The error appears in a top-level `error` field:

```json
{
  "schema_version": "tokenlint.report.v1",
  "tool": { "name": "tokenlint", "version": "1.0.0" },
  "mode": "validate",
  "verdict": "error",
  "exit_code": 3,
  "reference_time": { "value": "...", "source": "system_clock" },
  "summary": { "total": 0, "active": 0, "suppressed": 0, "skipped": 0,
               "by_severity": { "critical": 0, "fail": 0, "warn": 0, "info": 0 } },
  "inputs": { "policy": "./payments-api.yaml", "jwks": null, "token": null, "at_flag": null },
  "findings": [],
  "details": {},
  "error": {
    "kind": "schema",
    "message": "Unknown field 'accepted_audience' at policy root.",
    "context": "./payments-api.yaml",
    "hint": "Did you mean: accepts.audiences?"
  }
}
```

### Error kinds

| Kind | Description |
|---|---|
| `schema` | Policy file parse or validation failure |
| `jwks` | JWKS file unreadable or malformed |
| `token` | Token unparseable at input stage |
| `at_flag` | `--at` value invalid |
| `io` | File unreadable |
| `internal` | Finding cap exceeded or unexpected internal error |

On `internal` (finding cap exceeded):
- `error.kind = "internal"`
- `error.message = "Finding capacity exceeded (256). Report may be incomplete."`
- `findings` array contains first 256 collected
- Never silently truncated — always surfaced as error

---

## Text output format

```
tokenlint validate — payments-api [prod]
════════════════════════════════════════

  FAIL  TL-V003  TOKEN_ALG_NOT_ALLOWED
        Token algorithm 'ES256' is not permitted by policy.
        location: token → $.header.alg
        help:     Add ES256 to accepts.algorithms only if
                  intentionally supported.

  PASS  TL-V006  signature verified
        key: key-2026-01 (EC P-256)

  ░░░░  TL-A009  CLOCK_SKEW_EXCESSIVE  [suppressed]
        owner:   platform-security
        ticket:  SEC-1234
        expires: 2026-09-01 (119 days)

────────────────────────────────────────
verdict:  FAIL
findings: 3 total  2 active  1 suppressed
exit:     1
```

### Color control

Color is **off by default**. No TTY detection.

| Flag | Behavior |
|---|---|
| `--no-color` | Force color off (default) |
| `--color` | Force color on |
| Both provided | `--no-color` wins |

Color is only meaningful with `--format text`. With `--format json`, color flags
are accepted but have no effect.

No ANSI codes are ever embedded in JSON output.

---

## Exit code contract

| Code | Verdict | Condition |
|---|---|---|
| `0` | PASS | No active findings at warn or above |
| `1` | FAIL | One or more active findings with severity `fail` or `critical` |
| `2` | WARN | Active `warn` findings; no `fail`/`critical` |
| `3` | ERROR | Schema parse failure, JWKS load failure, file unreadable, finding cap exceeded |
| `4` | INTERNAL | Unexpected failure in tokenlint itself; should never occur in normal operation |

**Precedence**: `3 > 1 > 2 > 0`. Exit code `4` overrides everything.

Non-suppressible findings (TL-S001, TL-S002, TL-V006, etc.) always produce exit
1 or 3. `--suppress`, `--lenient`, and `--exit-zero` have no effect on them.

### CI patterns

```bash
# Block on fail/critical; allow warn
tokenlint audit --policy validator.yaml
# Exit 0 = pass, 1 = fail (blocked), 2 = warn (not blocked), 3 = error (blocked)

# Block on warn too
tokenlint audit --policy validator.yaml
[ $? -le 1 ] || exit 1   # fail if exit code > 1

# Never block (investigation mode)
tokenlint audit --policy validator.yaml --exit-zero || true

# Pipeline-safe with jq
tokenlint validate --token token.jwt --policy validator.yaml --jwks keys.json \
  | jq '.findings[] | select(.status == "active" and .severity == "critical")'
```

---

## Stdout vs stderr

| Stream | Content |
|---|---|
| stdout | All report output (JSON or text); `--version`; `--help` |
| stderr | Only pre-output halt conditions (unknown subcommand, unknown flag, catastrophic internal failure before envelope) |

In normal operation, stderr is empty. The error envelope handles all other failures.
Pipelines that capture stdout always get complete, parseable output.

---

## SARIF readiness (v2)

The finding object is designed to map cleanly to SARIF result objects:

| tokenlint field | SARIF field |
|---|---|
| `id` | `ruleId` |
| `name` | `rule.name` |
| `severity` | `level` |
| `message` | `message.text` |
| `location.path` | `locations[0].logicalLocations[0].fullyQualifiedName` |
| `help` | `rule.helpUri` or `rule.help.text` |

v2 SARIF output is a thin translation layer over the existing JSON shape, not a redesign.
