# CLI Contract — tokenlint v1

---

## Top-level structure

```
tokenlint <subcommand> [options]
```

### Subcommands (v1)

| Subcommand | Purpose |
|---|---|
| `audit` | Validate a policy file for dangerous assumptions |
| `validate` | Validate a token against a policy and JWKS |
| `inspect` | Parse and display token structure (no policy needed) |

### Subcommands (reserved, v2)

`gap`, `import`, `watch`, `batch`

### Error handling

```
Unknown subcommand:
  stderr: "Unknown subcommand 'foo'. Valid subcommands: audit, validate, inspect"
  exit 4

Unknown flag (any subcommand):
  stderr: "Unknown flag '--foo'. Run 'tokenlint <subcommand> --help' for usage."
  exit 4
```

---

## tokenlint audit

Validate a policy file for dangerous trust assumptions. No token or JWKS required.

```bash
tokenlint audit --policy <path> [options]
```

### Required flags

| Flag | Description |
|---|---|
| `--policy <path>` | Path to validator policy YAML file |

### Options

| Flag | Default | Description |
|---|---|---|
| `--severity <levels>` | all | Comma-separated filter: `critical,fail,warn,info` |
| `--suppress <ids>` | — | Comma-separated finding IDs to suppress for this run |
| `--suppress-affects-exit` | false | CLI suppressions affect exit code |
| `--lenient` | false | Treat unknown fields as WARN not FAIL |
| `--at <time>` | system clock | Reference time for time-dependent checks |
| `--format <fmt>` | json | `json \| text` |
| `--verbose` | false | Include info/skipped findings |
| `--color` | false | Enable ANSI color in text output |
| `--no-color` | true | Disable ANSI color (default) |

Note: `--skip-policy-audit` is invalid for the `audit` subcommand. FAIL if provided.

### Examples

```bash
tokenlint audit --policy payments-api.yaml

tokenlint audit --policy payments-api.yaml --format text --color

tokenlint audit --policy payments-api.yaml --severity critical,fail

tokenlint audit --policy payments-api.yaml \
  --suppress TL-A007 --suppress-affects-exit
```

---

## tokenlint validate

Validate a token against a policy and JWKS. Runs policy audit first by default.

```bash
tokenlint validate [--token <path|-|stdin>] \
                   --policy <path>           \
                   --jwks <path>             \
                   [options]
```

### Required flags

| Flag | Description |
|---|---|
| `--policy <path>` | Path to validator policy YAML file |
| `--jwks <path>` | Path to JWKS file (local only in v1) |
| token input | See token input section below |

### Token input

| Method | Behavior |
|---|---|
| `--token <path>` | Read token from file |
| `--token -` | Read token from stdin (explicit) |
| `--token` absent + stdin piped | Read token from stdin (implicit) |
| `--token` absent + no stdin | ERROR: exit 3 |

**Precedence**: `--token <path>` wins over all. If `--token <path>` is provided
and stdin is also piped, stdin is silently ignored (piped stdin in scripts is
often accidental).

### Options

| Flag | Default | Description |
|---|---|---|
| `--skip-policy-audit` | false | Skip policy audit phase; token validation only |
| `--at <time>` | system clock | Reference time |
| `--severity <levels>` | all | Severity filter |
| `--suppress <ids>` | — | CLI finding suppression |
| `--suppress-affects-exit` | false | CLI suppressions affect exit code |
| `--lenient` | false | Lenient schema parsing |
| `--format <fmt>` | json | `json \| text` |
| `--verbose` | false | Include info/skipped findings |
| `--color` | false | Enable color |
| `--no-color` | true | Disable color (default) |

### Execution order

**Default (full):**
1. Parse and validate policy schema — TL-S findings
2. Run policy audit — TL-A findings
3. Load and validate JWKS
4. Parse token — TL-V000 if unparseable
5. Run token validation — TL-V, TL-C findings
6. Collect all findings
7. Apply suppressions
8. Emit report
9. Exit

**With `--skip-policy-audit`:**
Steps 1, 3, 4, 5, 6, 7, 8, 9 (step 2 skipped)

### Halt conditions

| Condition | Behavior |
|---|---|
| Schema parse failure (step 1) | Emit error envelope; exit 3; do not proceed |
| JWKS load failure (step 3) | Emit partial report (policy findings included); exit 3 |
| Token unparseable (step 4) | Emit partial report; TL-V000 as finding; exit 1 |

### Examples

```bash
# File token
tokenlint validate \
  --token token.jwt \
  --policy payments-api.yaml \
  --jwks keys.json

# Stdin pipe
cat token.jwt | tokenlint validate \
  --policy payments-api.yaml \
  --jwks keys.json

# Explicit stdin
tokenlint validate \
  --token - \
  --policy payments-api.yaml \
  --jwks keys.json

# Forensic replay
tokenlint validate \
  --token incident.jwt \
  --policy payments-api.yaml \
  --jwks keys-at-incident.json \
  --at 2026-03-15T14:32:00Z \
  --format json

# Skip policy audit (CI with separate audit step)
tokenlint validate \
  --token token.jwt \
  --policy payments-api.yaml \
  --jwks keys.json \
  --skip-policy-audit

# Human review
tokenlint validate \
  --token token.jwt \
  --policy payments-api.yaml \
  --jwks keys.json \
  --format text --color
```

---

## tokenlint inspect

Parse and display token structure. No policy, no JWKS, no validation.

```bash
tokenlint inspect [--token <path|-|stdin>] [options]
```

### Token input

Same contract as `validate` subcommand.

### Options

| Flag | Default | Description |
|---|---|---|
| `--at <time>` | system clock | Reference time for exp/nbf display only; does not affect exit code |
| `--format <fmt>` | json | `json \| text` |
| `--verbose` | false | Include raw header/payload bytes |
| `--color` | false | Enable color |
| `--no-color` | true | Disable color (default) |

### Notes

- `inspect` never verifies signatures (no JWKS)
- `inspect` never evaluates policy conformance
- `inspect` verdict is always `"pass"` if token parses, regardless of claim content
- Purpose is display and exploration only

### Exit codes

| Code | Condition |
|---|---|
| 0 | Token parsed successfully |
| 3 | Token unparseable or unreadable |
| 4 | Internal error |

---

## Global flags

Valid for all subcommands:

| Flag | Description |
|---|---|
| `--format <fmt>` | `json \| text`. Default: `json`. Invalid value: exit 4. |
| `--verbose` | Include info/skipped findings. Boolean, no value. |
| `--color` | Enable ANSI color in text output. |
| `--no-color` | Disable ANSI color (default). If both `--color` and `--no-color` provided, `--no-color` wins. |
| `--version` | Print `tokenlint 1.0.0`; exit 0. No other flags required. |
| `--help` | Print help for subcommand or top-level; exit 0. |

### `--at` format

| Format | Example | Valid |
|---|---|---|
| Unix epoch integer | `--at 1746000000` | yes |
| ISO 8601 with Z | `--at 2026-04-30T12:00:00Z` | yes |
| ISO 8601 with offset | `--at 2026-04-30T08:00:00-04:00` | yes |
| Shorthand `now` | `--at now` | yes |
| ISO 8601 without timezone | `--at 2026-04-30T12:00:00` | **NO** → exit 4 |
| Negative integer | `--at -1` | **NO** → exit 4 |
| Unparseable | `--at yesterday` | **NO** → exit 4 |

---

## Complete flag matrix

| Flag | audit | validate | inspect |
|---|---|---|---|
| `--policy <path>` | required | required | — |
| `--jwks <path>` | — | required | — |
| `--token <path\|-\|stdin>` | — | required* | required* |
| `--at <time>` | optional | optional | optional |
| `--format <fmt>` | optional | optional | optional |
| `--verbose` | optional | optional | optional |
| `--color` | optional | optional | optional |
| `--no-color` | optional | optional | optional |
| `--severity <levels>` | optional | optional | — |
| `--suppress <ids>` | optional | optional | — |
| `--suppress-affects-exit` | optional | optional | — |
| `--lenient` | optional | optional | — |
| `--skip-policy-audit` | invalid | optional | — |
| `--version` | global | global | global |
| `--help` | global | global | global |

*Token input via file, explicit stdin (`--token -`), or implicit stdin (piped).

---

## Stdout vs stderr

| Stream | Content |
|---|---|
| `stdout` | All report output; `--version`; `--help` |
| `stderr` | Only pre-output halt conditions (unknown subcommand, unknown flag before envelope can be constructed) |

In normal operation, stderr is empty. The error envelope handles all other failures.

---

## Exit code summary

| Code | Meaning |
|---|---|
| 0 | PASS — no active findings at warn or above |
| 1 | FAIL — active fail or critical findings |
| 2 | WARN — active warn findings only |
| 3 | ERROR — halt condition (schema, JWKS, IO failure) |
| 4 | INTERNAL — unexpected tokenlint failure; file a bug |

Precedence: `3 > 1 > 2 > 0`. Exit code 4 overrides everything.
