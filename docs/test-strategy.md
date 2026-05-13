# Test Strategy — tokenlint v1

---

## Philosophy

For tokenlint, **passing** means:

- The contracts hold
- The findings are exact
- The security properties never regress
- The output is stable
- The CLI behavior is deterministic

Not: "we hit 90% line coverage."

Line coverage is a dangerous metric for a security tool. 90% line coverage means
nothing if the 10% uncovered is the `alg=none` check.

---

## Test categories

### Category 1 — Correctness tests

Does the tool produce the right finding for this input?  
Binary: finding present or absent, correct severity, correct status.

### Category 2 — Contract tests

Does the tool honor its stated contracts?  
Exit codes, output shape, suppression behavior, `--at` reproducibility, stdin handling.

### Category 3 — Security property tests

Do specific known-bad inputs fail in exactly the right way regardless of other
configuration?

**Category 3 is the most important and most often missing in security tool test suites.**  
A regression in category 1 is a bug. A regression in category 3 is a vulnerability.

---

## Test framework

Custom minimal C framework. ~200 lines. No external dependencies. Fully auditable.

```c
/* Registration */
TEST(name) { ... }           /* correctness and contract tests */
SECURITY_PROP(name) { ... }  /* security property tests; release-blocking */

/* Assertions */
ASSERT_TRUE(expr)
ASSERT_FALSE(expr)
ASSERT_EQ(a, b)
ASSERT_STR_EQ(a, b)
ASSERT_NULL(ptr)
ASSERT_NOT_NULL(ptr)

/* Finding assertions */
ASSERT_FINDING(fs, "TL-V003")        /* finding present and active */
ASSERT_NO_FINDING(fs, "TL-V003")     /* finding absent */
ASSERT_FINDING_SEV(fs, "TL-V003", SEV_FAIL)
ASSERT_FINDING_SUPPRESSED(fs, "TL-A009")
ASSERT_CLEAN(fs)                     /* no active fail/critical findings */
ASSERT_VERDICT(fs, "pass")
ASSERT_EXIT_CODE(result, 0)
```

### Runner exit codes

| Code | Meaning |
|---|---|
| 0 | All tests passed |
| 1 | Any correctness/contract test failed |
| 2 | Any security property test failed (distinct for CI) |

---

## Finding coverage requirement

**The finding registry drives the test manifest.**

Every finding in the v1 registry requires two test functions:

```
test_TL_V003_fires()      proves finding fires correctly
test_TL_V003_no_fire()    proves finding does not fire incorrectly
```

### Enforcement

`make check-coverage` runs before compilation in CI:

```bash
# For each finding ID in finding_registry.def:
#   grep for test_<ID>_fires in tests/
#   grep for test_<ID>_no_fire in tests/
#   if either missing: print error, exit 1
```

**A finding without both tests blocks release.** This is enforced mechanically,
not by convention.

### Finding registry format

```c
/* finding_registry.def — processed by check-coverage script */
X(TL_S001, "TOKEN_ALG_NONE")
X(TL_S002, "POLICY_ALG_NONE")
X(TL_S003, "FIELD_VALUE_INVALID")
/* ... all 41 findings ... */
```

---

## Security property tests

Named properties. Release-blocking. Separate test binary.  
Runner exits `2` on any property failure — distinct from test failures (exit `1`).

Located in `tests/security_properties/`.

### Property definitions

```
PROP_ALG_NONE_ALWAYS_FAILS
  Input:  any token with alg=none
  Policy: any valid policy (even if none listed in algorithms)
  Expect: TL-S001 present, active, non-suppressible
  Verify: --suppress TL-S001 has no effect
  Verify: exit code never 0

PROP_POLICY_ALG_NONE_SCHEMA_FAILS
  Input:  policy with none in accepts.algorithms
  Expect: TL-S002 present, active, non-suppressible
  Verify: --lenient does not suppress it
  Verify: exit code 3

PROP_BAD_SIGNATURE_ALWAYS_FAILS
  Input:  token with valid structure, tampered payload
  Policy: valid, matching algorithm
  JWKS:   correct key
  Expect: TL-V006 present, active
  Verify: no other finding masks it
  Verify: exit code 1

PROP_UNKNOWN_ALG_ALWAYS_FAILS
  Input:  token with alg: "XYZ999"
  Expect: TL-V002 present
  Verify: evaluation halts at algorithm check
  Verify: no signature verification attempted

PROP_AMBIGUOUS_KEY_MATCH_FAILS
  Input:  token with no kid, require_kid: false
  JWKS:   two keys with same kty, both verify token
  Expect: TL-V012 present
  Verify: verdict is fail, not pass

PROP_REQUIRE_KID_PREVENTS_FALLBACK
  Input:  token with no kid header field
  Policy: require_kid: true
  Expect: TL-V009 present
  Verify: no key matching attempted
  Verify: TL-V011 not present (fallback not reached)

PROP_EXPIRED_TOKEN_ALWAYS_FAILS
  Input:  token with exp in the past
  Policy: exp in requires.claims
  Expect: TL-V022 present
  Verify: --lenient does not affect it
  Verify: no clock skew applied to exp

PROP_SUPPRESSION_CANNOT_HIDE_SCHEMA_ERRORS
  Input:  policy with unknown field
  Suppression: TL-S002 in suppressions block
  Expect: TL-S002 still active
  Verify: suppression entry generates TL-S021
  Verify: exit code 3

PROP_CLI_SUPPRESSION_NEVER_AFFECTS_EXIT_BY_DEFAULT
  Input:  any failing token
  CLI:    --suppress TL-V003 (without --suppress-affects-exit)
  Expect: finding marked CLI-SUPPRESSED
  Expect: exit code unchanged

PROP_AT_FLAG_PRODUCES_DETERMINISTIC_OUTPUT
  Input:  same token, same policy, same JWKS
  Run 1:  --at 1746000000 (system time T1)
  Run 2:  --at 1746000000 (system time T2, T2 != T1)
  Expect: identical JSON output
  Verify: sha256 of outputs match

PROP_SCHEMA_VERSION_MISMATCH_HALTS
  Input:  policy with schema_version: tokenlint.validator.v99
  Expect: schema error fires immediately
  Verify: no other fields parsed
  Verify: exit code 3

PROP_FINDING_OVERFLOW_NEVER_SILENT
  Input:  crafted to generate > 256 findings
  Expect: findings array contains first 256
  Expect: error envelope with kind: internal
  Expect: exit code 3, never 0 or 1
```

**Total: 12 security properties. All release-blocking.**

---

## Test layers

### Layer 1 — Unit tests (`tests/unit/`)

One function or module per test file. Use `policy_builder` and `token_builder`
helpers — no YAML parser or JWT parser involved.

Fast: entire unit suite < 1 second.

| File | What it tests |
|---|---|
| `test_arena.c` | Allocation, alignment, overflow, free |
| `test_str.c` | `str_eq`, null handling, `STR_IS_NULL` |
| `test_alg.c` | `alg_from_str` for all algs, bitmask ops, `_Static_assert` |
| `test_policy_parser.c` | Valid + invalid policies, typo detection, suppressions |
| `test_token_parser.c` | Valid JWTs, missing fields, aud normalization |
| `test_jwks_parser.c` | Valid keys, empty set, malformed entries, use/key_ops |
| `test_eval_audit.c` | All TL-A findings, clean policy baseline |
| `test_eval_validate.c` | All TL-V time/claim findings, passing baseline |
| `test_eval_alg.c` | All algorithm + key compatibility combinations |
| `test_eval_time.c` | exp/nbf/iat/TTL checks, --at behavior |
| `test_findings.c` | Capacity, overflow flag, max severity, non-suppressible |
| `test_json_writer.c` | Escaping, types, nesting, UTF-8 passthrough |
| `test_suppressions.c` | Policy suppression, expiry, CLI suppression, TL-S findings |

### Layer 2 — Integration tests (`tests/integration/`)

Complete mode execution end-to-end. Uses fixture files. Invokes `run_audit()`,
`run_validate()`, `run_inspect()` directly (not via shell).

| File | Scenario |
|---|---|
| `test_audit_pass.c` | Minimal valid policy → exit 0 |
| `test_audit_fail.c` | http issuer, alg:none, unknown field → correct findings + exit codes |
| `test_validate_pass.c` | RS256 + ES256 valid tokens → exit 0 |
| `test_validate_fail.c` | Expired, alg:none, bad sig, alg confused, no kid |
| `test_validate_forensic.c` | `--at` past/present comparison, `reference_time_source` |
| `test_cli_contract.c` | No token input, CLI suppression, bad `--format`, bad `--at` |

### Layer 3 — Security property tests (`tests/security_properties/`)

All 12 named properties. Separate binary. Exit 2 on failure.

### Layer 4 — CLI contract tests (`tests/cli/`)

Shell scripts. Invoke actual binary. Verify stdin pipe behavior, exit codes,
stdout/stderr split.

| Script | What it tests |
|---|---|
| `test_stdin_pipe.sh` | Pipe, `--token -`, `--token file` |
| `test_exit_codes.sh` | All exit code scenarios |
| `test_output_format.sh` | JSON validity (`jq`), text verdict line, `--color` |

---

## Test helpers

### `policy_builder.h`

Construct `policy_t` directly in tests without touching the YAML parser.

```c
policy_t p = policy_builder_new(arena)
    .environment(ENV_PROD)
    .issuer_exact("https://auth.company.com")
    .audience_exact("payments-api")
    .algorithm(ALG_RS256)
    .require_claim(CLAIM_EXP | CLAIM_ISS | CLAIM_AUD)
    .max_ttl(3600)
    .build();
```

This means `eval_*` tests are pure logic tests. Parser bugs cannot contaminate
evaluator tests. Evaluator can be tested before parsers are complete.

### `token_builder.h`

Construct `token_t` directly in tests without JWT parsing.

```c
token_t t = token_builder_new(arena)
    .alg(ALG_RS256)
    .kid("key-2026-01")
    .iss("https://auth.company.com")
    .aud_single("payments-api")
    .exp(reference_time + 3600)
    .iat(reference_time)
    .build();
```

---

## Fixtures

### Static committed fixtures

All test fixtures are committed to the repository. Tests are deterministic and
offline. Fixtures never change without explicit intent.

```
tests/fixtures/
├── policies/
│   ├── valid/
│   │   ├── minimal.yaml         only required fields
│   │   ├── prod_strict.yaml     all limits set
│   │   └── nonprod.yaml         stage environment
│   └── invalid/
│       ├── alg_none.yaml        → TL-S002
│       ├── http_issuer.yaml     → TL-A002
│       ├── unknown_field.yaml   → TL-S002
│       ├── typo_field.yaml      → typo suggestion
│       └── missing_req.yaml     → TL-S003
├── tokens/
│   ├── valid/
│   │   ├── rs256.jwt
│   │   ├── es256.jwt
│   │   └── ps256.jwt
│   └── invalid/
│       ├── alg_none.jwt         → TL-S001
│       ├── expired.jwt          → TL-V022
│       ├── alg_confused.jwt     → TL-V003
│       ├── no_kid.jwt           → TL-V009
│       └── bad_sig.jwt          → TL-V006
├── jwks/
│   ├── rsa_rs256.json
│   ├── ec_es256.json
│   ├── rsa_ps256.json
│   ├── oct_hs256.json
│   ├── multi_key.json
│   └── empty.json               → TL-S012
├── gen_fixtures.sh              generation script (committed)
└── MANIFEST.md                  documents every fixture file
```

### Fixture manifest (`MANIFEST.md`)

Every fixture file is documented:
- Filename
- Purpose
- Algorithm / key file used
- Expected findings
- Line in `gen_fixtures.sh` that created it

Fixtures without MANIFEST entries fail CI. Fixture changes require explicit
reviewer sign-off.

### Generation script

`tests/fixtures/gen_fixtures.sh` is committed. It documents exactly how each
fixture was created. Run manually when fixtures need regeneration (e.g. key
rotation, new test scenarios). Not run during CI.

---

## CI test execution order

```
Stage 1 — Pre-build (no compilation, fast)
  make check-coverage       finding registry completeness
  MANIFEST.md coverage      all fixtures documented
  make lint                 clang-tidy

Stage 2 — Build
  make debug    (GCC + Clang)
  make release  (GCC + Clang)
  make static   (musl GCC, Linux)
  make asan     (GCC)

Stage 3 — Unit tests
  build/test/unit_tests
  Must exit 0

Stage 4 — Security property tests
  build/test/security_props
  Must exit 0
  Exit 2 = release blocked, security review required

Stage 5 — Integration tests
  build/test/integration_tests
  Must exit 0

Stage 6 — CLI contract tests
  tests/cli/run_all.sh
  Requires release binary in PATH
  Must exit 0

Stage 7 — Sanitizer run
  build/asan/unit_tests
  build/asan/integration_tests
  build/asan/security_props
  All must exit 0, no sanitizer errors

Stage 8 — Static binary verification (Linux only)
  ldd build/static/tokenlint
  Must output: "not a dynamic executable"

Total CI time target: < 2 minutes
```

---

## Regression policy

| Event | Policy |
|---|---|
| Any test failure | Blocks merge. No exceptions. |
| Security property failure | Treated as potential vulnerability. Security review required before re-opening PR. Root cause must be documented. |
| Finding behavior change | Test catches it. Requires: updated test, updated `finding-registry.md`, CHANGELOG entry, PR label `finding-behavior-change`. |
| New finding added | Must add `test_<ID>_fires` and `test_<ID>_no_fire` before merge. `make check-coverage` enforces this. |
| Fixture change | Requires MANIFEST.md update and explicit reviewer sign-off. |

---

## Fuzzing (additional track, not v1 gate)

### Targets

| Target | Input |
|---|---|
| `fuzz_yaml_policy` | Arbitrary bytes → `policy_parse()` |
| `fuzz_jwt_parse` | Arbitrary bytes → `token_parse()` |
| `fuzz_jwks_parse` | Arbitrary bytes → `jwks_load()` |
| `fuzz_json_escape` | Arbitrary strings → `jw_escape()` |

### Acceptance criteria

- No crash
- No sanitizer error
- No assertion failure
- Graceful `tl_error_t` return on all inputs

### When to run

Not in standard CI pipeline (too slow for < 2 min target). Options:
- Dedicated continuous fuzzing infrastructure
- Nightly CI with fixed time budget (e.g. 60 seconds per target)

Crashes filed as security issues, not bugs.

### Corpus

```
tests/fuzz/corpus/yaml/    seed YAML inputs
tests/fuzz/corpus/jwt/     seed JWT inputs
tests/fuzz/corpus/jwks/    seed JWKS inputs
```

Interesting inputs discovered by fuzzing are committed to the corpus.

---

## First files to write

Before any application code, write the foundation and its tests:

```
1. include/tokenlint.h      str_t, arena_t, tl_error_t
2. src/util/arena.c
3. src/util/str.c
4. tests/unit/test_arena.c
5. tests/unit/test_str.c
```

Get these right. Everything else builds on them. The eval layer cannot be written
until `policy_t` exists. `policy_t` cannot exist until `str_t` and arena work.
Start at the bottom.
