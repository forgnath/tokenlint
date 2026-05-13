# Contributing to tokenlint

This document explains how to work on tokenlint. Read it before writing code.

---

## The most important rule

**The parse/eval boundary is inviolable.**

- `src/parse/` produces normalized structs. It may use libyaml and mbedTLS.
- `src/eval/` consumes normalized structs. It may not use libyaml or mbedTLS.
- `src/crypto/` wraps mbedTLS. Nothing outside this directory calls mbedTLS directly.

This is enforced by the Makefile's include path control. Violating it is a
compile error, not a convention violation. If you find yourself wanting to parse
a string inside an `eval_*` function, stop — that work belongs in the parse layer.

---

## Directory structure

```
include/        shared headers (policy_t, token_t, jwks_t, finding_t, etc.)
src/
  main.c        CLI dispatch only — no business logic
  cli/          argument parsing, stdin detection
  parse/        YAML → policy_t, JWT → token_t, JWKS JSON → jwks_t
  crypto/       mbedTLS wrapper (tl_verify_signature, tl_base64url_decode)
  eval/         evaluation logic — pure logic against normalized structs
  output/       report generation (JSON and text)
  util/         arena, str_t, time utilities
tests/
  unit/         per-module unit tests
  integration/  end-to-end mode tests
  security_properties/  named regression tests (release-blocking)
  cli/          shell contract tests
  fixtures/     static test data (policies, tokens, JWKS)
  helpers/      test_runner.h, policy_builder.h, token_builder.h
vendor/
  libyaml/      vendored, pinned version in UPSTREAM_VERSION
  mbedtls/      vendored, pinned version in UPSTREAM_VERSION
tools/
  check_coverage.py   finding registry test coverage enforcement
docs/           full specification (read before implementing anything)
```

---

## Before writing any code

1. Read `docs/SPEC.md` — master index and design philosophy
2. Read `docs/architecture.md` — object model and C structs
3. Read `docs/finding-registry.md` — all 41 v1 findings
4. Read the contract document relevant to what you're implementing

The spec is the source of truth. Code is written against the spec, not the other
way around.

---

## How to add a new finding

Findings are the unit of output. Adding one correctly requires touching several
files. Do all of them or do none of them.

### Step 1 — Check the registry

Is this finding already reserved? Check `finding_registry.def` and
`docs/finding-registry.md`. If it's listed as v2, it is not in scope for v1.

### Step 2 — Add to `finding_registry.def`

```c
X(TL_V026, "TL-V026")   /* YOUR_FINDING_NAME   brief note */
```

Place it in the correct namespace block, in numeric order.

### Step 3 — Add evaluation logic

In the appropriate `src/eval/*.c` file, add the check and call `findings_add()`.

Follow the existing pattern exactly:

```c
if (/* condition */) {
    findings_add(ctx->findings, (finding_t){
        .id          = str_from_cstr("TL-V026"),
        .name        = str_from_cstr("YOUR_FINDING_NAME"),
        .severity    = SEV_FAIL,
        .status      = FINDING_ACTIVE,
        .message     = str_from_cstr("One sentence. Present tense. No period"),
        .detail      = str_from_cstr("Full explanation with observed vs expected."),
        .policy_path = str_from_cstr("$.relevant.field"),
        .help        = str_from_cstr("Actionable remediation in 1-2 sentences."),
    });
}
```

### Step 4 — Add tests (required, enforced by CI)

In `tests/unit/` or `tests/integration/`, add both:

```c
TEST(TL_V026_fires) {
    /* construct minimal scenario that triggers TL-V026 */
    /* ASSERT_FINDING(fs, "TL-V026"); */
}

TEST(TL_V026_no_fire) {
    /* construct scenario that should NOT trigger TL-V026 */
    /* ASSERT_NO_FINDING(fs, "TL-V026"); */
}
```

`make check-coverage` will fail until both functions exist.

### Step 5 — Update docs

- `docs/finding-registry.md` — add to the appropriate table
- `docs/` relevant contract file — add to finding summary table

### Step 6 — Update CHANGELOG.md

Add an entry under the current version.

### That's it. Do not skip steps.

---

## How to use policy_builder and token_builder

Never construct `policy_t` or `token_t` manually in tests. Use the builders:

```c
#include "helpers/policy_builder.h"
#include "helpers/token_builder.h"

void test_something(void) {
    arena_t *arena = arena_new(MB(1));
    finding_set_t fs = {0};

    policy_t policy = policy_builder_new(arena)
        .environment(ENV_PROD)
        .issuer_exact("https://auth.example.com")
        .audience_exact("my-service")
        .algorithm(ALG_RS256)
        .require_claims(CLAIM_EXP | CLAIM_ISS | CLAIM_AUD)
        .max_ttl(3600)
        .build();

    /* test eval logic directly */
    eval_ctx_t ctx = {
        .policy         = &policy,
        .findings       = &fs,
        .reference_time = 1746000000,
        .arena          = arena,
    };

    eval_audit(&ctx);

    ASSERT_CLEAN(&fs);
    arena_free(arena);
}
```

This keeps parser bugs out of evaluator tests and lets you test eval logic before
the parsers exist.

---

## Suppression in tests

To test that a finding is suppressed correctly:

```c
ASSERT_FINDING_SUPPRESSED(&fs, "TL-A009");
```

To test that a non-suppressible finding remains active despite suppression:

```c
/* add suppression for TL-S001 to the policy */
/* run eval */
ASSERT_FINDING(&fs, "TL-S001");   /* must still be active */
```

---

## Adding a vendored dependency

Do not add vendored dependencies without discussion. The current three (libyaml,
mbedTLS, json_writer) are the complete set for v1.

If a new dependency is approved:

1. Download exact version
2. Place under `vendor/<name>/`
3. Create `vendor/<name>/UPSTREAM_VERSION` with the pinned version string
4. Create `vendor/<name>/LICENSE`
5. Add to Makefile with correct include path isolation
6. Update `docs/build-contract.md`
7. Vendor updates are always a dedicated PR — never bundled with features

---

## Updating a vendored dependency

1. Download new version
2. Replace files in `vendor/<name>/`
3. Update `vendor/<name>/UPSTREAM_VERSION`
4. Run full CI: `make test && make asan && make static`
5. Commit as dedicated PR with explicit reviewer sign-off
6. Never bundle with feature changes

---

## Build commands

```bash
make              # debug build
make release      # optimized release build
make static       # fully static Linux binary (requires musl-gcc)
make test         # build and run full test suite
make asan         # address + undefined behavior sanitizers
make lint         # clang-tidy (if installed)
make format       # clang-format (if installed)
make check-coverage  # verify finding registry test coverage
make clean        # remove build artifacts
```

---

## CI requirements

Every PR must pass:

1. `make check-coverage` — finding registry completeness
2. `make lint` — clang-tidy clean
3. `make debug` + `make release` — GCC and Clang
4. `make test` — full test suite
5. `make asan` — sanitizer build + tests clean
6. `make static` — static binary verification (Linux)

Security property test failures (`build/test/security_props` exit 2) require
security review before the PR can be reopened. They are not treated as ordinary
test failures.

---

## Commit message format

```
<type>: <short description>

<body — what and why, not how>
```

Types: `feat`, `fix`, `docs`, `test`, `build`, `refactor`, `security`

Examples:

```
feat: implement arena allocator

Add arena_new, arena_alloc, arena_str, arena_free.
All tokenlint memory for a single run comes from one arena.
Free the arena, free everything. No ownership tracking needed.
```

```
security: fix TL-V006 non-suppressibility

TL-V006 (TOKEN_SIG_INVALID) was incorrectly allowed to be
suppressed via policy suppression entries. Signature failures
are non-suppressible by contract. Added test_TL_V006_non_suppressible
to security_properties suite.
```

Finding behavior changes require the label `finding-behavior-change` and an
entry in CHANGELOG.md.

---

## What "done" means for a feature

A feature is done when:

- [ ] Implementation matches the relevant contract document exactly
- [ ] Every affected finding has `test_<ID>_fires` and `test_<ID>_no_fire`
- [ ] Security properties that touch the feature still pass
- [ ] `make asan` is clean
- [ ] `docs/` updated if behavior changed
- [ ] CHANGELOG.md updated
- [ ] CI passes on GCC and Clang
