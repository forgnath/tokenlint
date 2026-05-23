# tokenlint

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

## Status

Full specification in `docs/`. Implementation in progress. Layer 1-3 complete. 

## Quick example

```bash
# Audit a policy for dangerous assumptions
tokenlint audit --policy payments-api.yaml

# Validate a token against a policy
cat token.jwt | tokenlint validate --policy payments-api.yaml --jwks keys.json

# Forensic replay at incident time
tokenlint validate \
  --token incident.jwt \
  --policy payments-api.yaml \
  --jwks keys.json \
  --at 2026-03-15T14:32:00Z

# Inspect a token's structure
tokenlint inspect --token token.jwt --format text
```

## Documentation

- [SPEC.md](docs/SPEC.md) — Master index and design philosophy
- [finding-registry.md](docs/finding-registry.md) — All v1 findings
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

TBD
