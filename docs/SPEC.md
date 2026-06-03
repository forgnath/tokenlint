# tokenlint — Master Specification

Version: 1.0.0  
Status: Released  
Schema: tokenlint.validator.v1

---

## Design philosophy

tokenlint is a **trust model verifier**, not a token parser.

The central question is not "is this JWT well-formed?" It is:

> "What does this service believe it enforces, and is that belief safe, consistent,
> and honored by real tokens?"

### Core principles

**The token declares its algorithm. The token never authorizes its algorithm.**  
Authorization requires the algorithm to appear in the policy allowlist AND be
compatible with the matched key material. Both checks are mandatory and independent.

**Unknown against declared policy is a failure.**  
If a policy declares bounded token lifetime but the token lacks `iat`, tokenlint
cannot verify the constraint. Unverifiable policy = FAIL.

**Suppression annotates risk acceptance. It does not erase findings.**  
Every suppression must be visible, owned, reasoned, and expiring in production.
Severity never changes.

**Strict by default.**  
Unknown fields in a trust declaration are policy ambiguity, not harmless metadata.
A typo in `accepted_audiences` that silently removes an audience constraint is a
security bug, not a formatting issue.

**Deterministic above all.**  
Same inputs + same flags = identical output, always. No TTY detection. No
time-dependent behavior except via explicit `--at`. This is a forensic tool as
much as a CI tool.

**Small, portable, auditable.**  
Single static binary on Linux. No runtime dependencies. Three vendored dependencies,
each isolated behind a wrapper layer. Plain C11.

---

## The normalized trust model

The YAML policy file is an input format, not the program's mental model.

```
YAML file
    ↓
yaml_parse()        reads raw text, validates field presence
    ↓
policy_validate()   checks semantics, emits TL-S findings
    ↓
policy_t            the internal model, evaluation-ready
    ↓
eval_audit()        works only against policy_t
eval_validate()     works only against policy_t + token_t + jwks_t
```

The evaluator never asks `if (strcmp(mode, "exact") == 0)`. That question was
answered at parse time. By the time evaluation starts, the model contains compiled
matchers, bitmasks, and typed structs — not raw strings.

---

## Three evaluation modes

### audit
Validate a policy file for dangerous trust assumptions.  
No token required. No JWKS required.  
Catches misconfigured policies before any token arrives.

### validate
Validate a token against a policy and JWKS.  
Runs policy audit first by default.  
A token that passes validation against a dangerously misconfigured policy is not safe.

### inspect
Parse and display token structure.  
No policy, no JWKS, no validation.  
Useful for understanding token contents before writing a policy.

---

## Finding tiers

### Tier 0 — Safety-critical
Non-negotiable hard fails. The identity equivalent of memory corruption or an
invalid TLS certificate. These must never regress.

Examples: `alg=none`, unknown algorithm, invalid signature, ambiguous key verification.

### Tier 1 — Trust contract failures
Policy violations that break the declared trust model. Still fail CI, but
conceptually different from catastrophic trust violations.

Examples: expired token, TTL exceeded, required claim absent, issuer mismatch.

### Tier 2 — Hygiene and maturity
Warnings and advisory findings. Mostly deferred to v2.

---

## v1 scope

v1 ships 41 findings. Everything else is explicitly reserved for v2.

**Ships in v1:**
- Strict schema governance (TL-S namespace)
- Core audit findings for catastrophic policy misconfiguration (TL-A)
- Full token validation including algorithm, signature, JWKS, and time (TL-V)
- Claim presence check (TL-C001 only)
- Security property regression tests

**Deferred to v2:**
- Claim rule evaluation engine (TL-C002+)
- Gap mode (TL-G namespace)
- Warning/advisory findings (TL-W namespace)
- SARIF output format
- Config adapters (Spring, nginx, Kubernetes, Envoy)
- Windows native support
- Remote JWKS sources

---

## Document index

| Document | Contents |
|---|---|
| [finding-registry.md](finding-registry.md) | All 41 v1 findings with codes, severities, suppressibility |
| [schema-contract.md](schema-contract.md) | Policy YAML schema, every field formally specified |
| [algorithm-contract.md](algorithm-contract.md) | Algorithm handling, key compatibility matrix, evaluation order |
| [jwks-contract.md](jwks-contract.md) | JWKS loading, key selection, kid resolution |
| [time-contract.md](time-contract.md) | exp/nbf/iat semantics, clock skew, `--at` flag |
| [suppression-contract.md](suppression-contract.md) | Suppression model, expiry, severity immutability |
| [output-contract.md](output-contract.md) | JSON envelope, finding shape, text format, exit codes |
| [cli-contract.md](cli-contract.md) | Subcommands, flags, stdin handling, flag matrix |
| [architecture.md](architecture.md) | Object model, C structs, parse/eval boundary |
| [build-contract.md](build-contract.md) | C11, dependencies, targets, static binary |
| [test-strategy.md](test-strategy.md) | Framework, finding coverage, security properties, fuzzing |
| [example-policy.yaml](example-policy.yaml) | Annotated reference policy file |

## Other key files

| File | Purpose |
|---|---|
| `CONTRIBUTING.md` | How to add findings, build rules, vendor policy, commit format |
| `CHANGELOG.md` | v1/v2 scope, roadmap, version history |
| `finding_registry.def` | C X-macro file — the authoritative finding list, drives test coverage |
| `tools/scaffold.sh` | Creates full directory structure with stub files — run once after clone |
| `tools/check_coverage.py` | CI script — verifies every finding has both test functions |
