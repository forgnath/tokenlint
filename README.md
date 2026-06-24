# Use-case pitch

Ever audited what your service actually enforces about the JWTs it accepts?

Not "does the signature verify" — but the broader trust model. Are you allowing symmetric algorithms in prod? Is your token lifetime actually bounded? Would you catch a misconfigured issuer before a token arrived?

I built a small CLI tool called tokenlint that makes this explicit. You write a YAML file describing what your service believes it enforces — issuers, audiences, algorithms, TTL limits, required claims — and it audits the policy for dangerous assumptions and validates real tokens against it.

Static binary, no runtime deps, JSON output, designed to drop into CI or run forensically with a fixed reference time.

# tokenlint description

A small, portable, air-gapped-first CLI tool for verifying JWT trust boundaries.

tokenlint is not a token parser. It is a **trust model verifier**.

Given a policy file that describes what a service believes it enforces — issuers,
audiences, algorithms, TTL, required claims — tokenlint checks whether that belief
is safe, self-consistent, and honored by real tokens.

## What it is

- A static policy auditor: catches dangerous trust assumptions before any token arrives
- A token validator: checks whether a token conforms to a declared trust model
- A forensic tool: deterministic evaluation at any reference time via `--at`
- A CI primitive: machine-readable JSON output, stable exit codes, composable

## What it is not

- Not an IdP or token issuer
- Not a platform agent or daemon
- Not a replacement for a proper JWT library in application code
- Not a cloud-specific tool

## Design principles

- Air-gapped first: no network calls, no remote JWKS, no metadata endpoints
- Strict by default: unknown fields in policy files are errors, not warnings
- Deterministic: same inputs always produce identical output
- Small: single static binary, no runtime dependencies on Linux
- Auditable: minimal dependencies, clean parse/eval boundary, plain C11

## v1 feature set

tokenlint v1.0.0 ships 41 findings across five namespaces:

- **TL-S** (20) — strict schema governance; unknown fields, bad values, contradictory rules
- **TL-A** (6) — policy-only audit findings; dangerous trust assumptions caught before any token arrives
- **TL-V** (13) — token validation; algorithm, signature, JWKS key selection, expiration, TTL
- **TL-C** (1) — claim presence enforcement
- **TL-I** (1) — input and invocation errors

Three evaluation modes: `audit`, `validate`, `inspect`. JSON output by default. Fully deterministic.

## Installation

```bash
git clone https://github.com/forgnath/tokenlint
cd tokenlint
make release
cp build/release/tokenlint /usr/local/bin/
```

For a fully static binary (Linux, requires musl-gcc):

```bash
make static
cp build/static/tokenlint /usr/local/bin/
```

Verify:

```bash
tokenlint --version
```

## Getting started

Start with the example policy in `docs/example-policy.yaml`. The typical workflow
is audit first, then validate:

```bash
# Step 1 — audit your policy for dangerous assumptions
tokenlint audit --policy payments-api.yaml

# Step 2 — validate a token against the policy
tokenlint validate \
  --token token.jwt \
  --policy payments-api.yaml \
  --jwks keys.json

# Step 3 — forensic replay at a fixed point in time
tokenlint validate \
  --token incident.jwt \
  --policy payments-api.yaml \
  --jwks keys-at-incident.json \
  --at 2026-03-15T14:32:00Z

# Inspect a token's structure without a policy
tokenlint inspect --token token.jwt --format text
```

Output is JSON by default. Pipe to `jq` for filtering:

```bash
tokenlint validate --token token.jwt --policy payments-api.yaml --jwks keys.json \
  | jq '.findings[] | select(.status == "active")'
```

## Documentation

- [SPEC.md](docs/SPEC.md) — Master index and design philosophy
- [finding-registry.md](docs/finding-registry.md) — All 41 v1 findings
- [schema-contract.md](docs/schema-contract.md) — Policy schema specification
- [algorithm-contract.md](docs/algorithm-contract.md) — Algorithm handling
- [jwks-contract.md](docs/jwks-contract.md) — JWKS loading and key selection
- [time-contract.md](docs/time-contract.md) — Time semantics and `--at`
- [suppression-contract.md](docs/suppression-contract.md) — Suppression model
- [output-contract.md](docs/output-contract.md) — JSON and text output
- [cli-contract.md](docs/cli-contract.md) — CLI interface
- [architecture.md](docs/architecture.md) — Object model and internal design
- [build-contract.md](docs/build-contract.md) — Build system and targets
- [test-strategy.md](docs/test-strategy.md) — Test approach and coverage

## License

[Apache 2.0](LICENSE)
