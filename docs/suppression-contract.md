# Suppression Contract — tokenlint v1

---

## Core principle

> Suppression annotates risk acceptance. It does not erase findings.

A suppressed finding:
- Is still computed
- Is still visible in output
- Has an owner on record
- Has a reason documented
- May have an expiry date
- Never has its severity changed

**Severity is immutable. No overrides. Ever.**

---

## Suppression sources and precedence

### Source 1: Policy file (persistent, auditable)

```yaml
suppressions:
  - id: TL-A009
    reason: "clock skew set by platform team, reviewed SEC-1234"
    owner: "platform-security"
    ticket: "SEC-1234"
    expires: "2026-09-01"
```

Policy suppressions:
- Affect exit code normally
- Are version-controlled (reviewed in PRs)
- Require owner and reason always
- Require expiry in prod environments

### Source 2: CLI flag (ephemeral, investigation only)

```bash
tokenlint audit --policy validator.yaml --suppress TL-A009,TL-A010
```

CLI suppressions:
- Do **not** affect exit code unless `--suppress-affects-exit` is explicitly passed
- Are always visible in output, marked `[CLI-SUPPRESSED]`
- Cannot unsuppress a finding suppressed in the policy file
- Cannot suppress TL-S0xx schema findings (ever)
- Are ephemeral — not recorded anywhere beyond the run's output

### Precedence rules

- CLI cannot unsuppress a finding suppressed in policy
- CLI cannot change severity
- Policy suppressions affect exit code normally
- CLI suppressions affect exit code only with `--suppress-affects-exit`

---

## Policy suppression schema

### Required fields (all environments)

| Field | Type | Notes |
|---|---|---|
| `id` | string | Finding code, exact match only (e.g. `TL-A009`) |
| `reason` | string | Non-empty free text |
| `owner` | string | Team or individual, non-empty |

### Conditional fields

| Field | Condition | Notes |
|---|---|---|
| `expires` | Required when `environment: prod` | ISO 8601 date string (`YYYY-MM-DD`) |
| `ticket` | Optional everywhere | Reference string, not validated by tokenlint |

### Suppression validation

| Condition | Finding |
|---|---|
| Missing `reason` or `owner` | FAIL TL-S020 |
| Suppressing a finding ID not in v1 registry | WARN TL-S021 |
| `expires` date is in the past | WARN TL-S022 — finding reactivated |
| `expires` within 14 days (configurable) | WARN TL-S023 |
| `environment: prod` suppression without `expires` | FAIL TL-S024 |

### Expiry behavior

- **Expired suppression**: finding is reactivated. TL-S022 emitted. The finding
  appears as active in the output.
- **Soon-to-expire**: TL-S023 emitted. Finding remains suppressed. Default
  threshold is 14 days (configurable).
- **No expiry (non-prod)**: permitted. No finding. Engineers encouraged to set
  expiry anyway.

---

## What cannot be suppressed

Schema findings (TL-S0xx) are **never suppressible**:

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
TL-S020  through TL-S024 (suppression integrity findings)
```

Rationale: if the policy file is malformed, tokenlint cannot reason about trust
at all. A suppression entry in a broken policy file is meaningless.

Additionally, these token findings are non-suppressible:

```
TL-V000  TOKEN_UNPARSEABLE
TL-V001  TOKEN_ALG_ABSENT
TL-V002  TOKEN_ALG_UNRECOGNIZED
TL-V006  TOKEN_SIG_INVALID
TL-V022  TOKEN_EXPIRED
TL-V024  TOKEN_TTL_INVALID
TL-I001  AT_FLAG_INVALID
```

---

## No severity overrides

The following is **not permitted** and will never be added to v1:

```yaml
suppressions:
  - id: TL-A008
    severity_override: low    # NOT VALID — rejected at schema parse time
    reason: "reviewed"
    owner: "platform-security"
```

Downgrading a critical finding to low means it stops blocking CI without being
explicitly suppressed. This creates false green. There is no middle ground:
either a finding is active (at its declared severity) or it is suppressed
(with accountability).

---

## Output representation

### Active finding

```json
{
  "id": "TL-A009",
  "severity": "warn",
  "status": "active",
  "suppression": null
}
```

### Policy-suppressed finding

```json
{
  "id": "TL-A009",
  "severity": "warn",
  "status": "suppressed_policy",
  "suppression": {
    "source": "policy",
    "reason": "clock skew set by platform team",
    "owner": "platform-security",
    "ticket": "SEC-1234",
    "expires": "2026-09-01",
    "expires_in_days": 119,
    "affects_exit": false
  }
}
```

### CLI-suppressed finding

```json
{
  "id": "TL-A009",
  "severity": "warn",
  "status": "suppressed_cli",
  "suppression": {
    "source": "cli",
    "reason": null,
    "owner": null,
    "ticket": null,
    "expires": null,
    "expires_in_days": null,
    "affects_exit": false
  }
}
```

`affects_exit` is `true` only when `--suppress-affects-exit` was explicitly passed.

---

## Exit code behavior

Policy suppressions follow normal exit code rules:

```
0  PASS  — no active unsuppressed findings at warn or above
1  FAIL  — one or more active unsuppressed FAIL findings
2  WARN  — active warn findings, no fail findings
3  ERROR — schema error or halt condition
```

CLI suppressions without `--suppress-affects-exit`:
- Finding is visually suppressed in output
- Exit code is **unchanged** from what it would be without suppression
- This is intentional: `--suppress` is for investigation, not CI green-washing

CLI suppressions with `--suppress-affects-exit`:
- Finding affects exit code as if it were policy-suppressed
- Use sparingly; document why in CI scripts
