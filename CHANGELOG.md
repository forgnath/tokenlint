# Changelog

All notable changes to tokenlint are documented here.

Format: [version] — date — description  
Status values: planned | in-progress | released

---

## Roadmap summary

### v1.0.0 — 2026-06-02 — released

The narrow, precise core. Does four things exceptionally well:

1. Parses policy files safely with strict schema enforcement
2. Parses JWT tokens safely with no unsafe fallback behavior
3. Verifies signatures safely (alg confusion, kid semantics, key compatibility)
4. Enforces core trust boundaries (issuer, audience, expiration, TTL, algorithm allowlist)

**41 findings. No claim rule engine. No gap mode. No adapters.**

The goal is credibility of signal. A tool that does 10 things with complete
precision earns the right to do 30 things in v2.

### v1.1.0 — planned

- SARIF output format (`--format sarif`)
- macOS notarization
- Remaining TL-A audit findings (TTL_EXCESSIVE, CLOCK_SKEW_EXCESSIVE, DEV_ISSUER_PROD, KID_NOT_REQUIRED)
- TL-W warning findings (advisory/hygiene layer)
- Windows native support

### v2.0.0 — planned

- Full claim rule evaluation engine (TL-C namespace)
- Gap mode: trust gap analysis between policy and key material (TL-G namespace)
- Config adapters: Spring Security, nginx-lua, Kubernetes, Envoy → normalized policy
- Remote JWKS sources (with explicit opt-in, air-gapped environments remain the primary target)
- Batch mode: validate multiple tokens against one policy in a single run
- Watch mode: continuous validation daemon

---

## v1 scope — explicit boundaries

### Ships in v1

```
TL-S  (20 findings)  schema governance, structural validation
TL-A  (6 findings)   catastrophic policy misconfiguration
TL-V  (13 findings)  token validation: algorithm, signature, JWKS, time
TL-C  (1 finding)    claim presence check only (TL-C001)
TL-I  (1 finding)    input/invocation errors
```

### Deferred to v2

```
TL-C002+   full claim rule evaluation engine
           (type system, normalization, operators, conflict detection)
TL-G       gap mode findings
TL-W       all warning/advisory findings
TL-A001    ISSUER_WILDCARD
TL-A008    TTL_EXCESSIVE
TL-A009    CLOCK_SKEW_EXCESSIVE
TL-A010    KID_NOT_REQUIRED
TL-A011    JWKS_REMOTE_PROD (caught by TL-S011 in v1)
TL-A012    DEV_ISSUER_PROD
```

### Never

```
Severity overrides on suppressions
Silent field dropping in strict mode
TTY-based output format detection
Mid-run JWKS rotation
Global state in evaluation code
```

---

## Version history

### 1.0.0 — 2026-06-02 — initial release

- Policy audit mode: strict schema validation, 20 TL-S findings, 6 TL-A findings
- Token validation mode: algorithm allowlist, JWKS key selection, signature verification
- Time enforcement: exp, nbf, iat, TTL bounds, clock skew, `--at` flag
- Claim presence enforcement (TL-C001)
- Inspect mode: parse and display token structure without a policy
- 41 findings total; all non-suppressible findings enforced unconditionally
- 12 named security property tests; separate exit code 2 on regression
- Full test suite: unit, integration, security properties, CLI contract tests
- Static Linux binary (musl); reproducible builds via VERSION-embedded version string
- Three vendored dependencies: libyaml, mbedTLS, custom json_writer
- Hard parse/eval boundary enforced by Makefile include path control

### 0.1.0 — 2026-05-12 — initial specification

- Complete pre-implementation specification committed
- All v1 contracts defined: schema, algorithm, JWKS, time, suppression, output, CLI
- Object model and C struct definitions
- Build contract: C11, vendored libyaml + mbedTLS, static Linux binary
- Test strategy: finding registry coverage, 12 named security properties, fuzzing plan
- 41-finding v1 registry locked
- No code yet
