#!/usr/bin/env bash
# tools/scaffold.sh
#
# Creates the full tokenlint directory structure with .gitkeep files.
# Run once after cloning or extracting the spec archive.
#
# Usage:
#   bash tools/scaffold.sh
#
# Safe to run multiple times — will not overwrite existing files.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Scaffolding tokenlint directory structure in: $ROOT"

# ── include/ ────────────────────────────────────────────────────────────────
dirs=(
    "include"

    # source tree
    "src/cli"
    "src/parse"
    "src/crypto"
    "src/eval"
    "src/output"
    "src/util"

    # tests
    "tests/unit"
    "tests/integration"
    "tests/security_properties"
    "tests/cli"
    "tests/helpers"
    "tests/fuzz/corpus/yaml"
    "tests/fuzz/corpus/jwt"
    "tests/fuzz/corpus/jwks"
    "tests/fuzz/crashes"

    # fixtures
    "tests/fixtures/policies/valid"
    "tests/fixtures/policies/invalid"
    "tests/fixtures/tokens/valid"
    "tests/fixtures/tokens/invalid"
    "tests/fixtures/jwks"
    "tests/fixtures/expected"

    # vendor stubs (actual source added separately)
    "vendor/libyaml/include"
    "vendor/libyaml/src"
    "vendor/mbedtls/include"
    "vendor/mbedtls/library"

    # build output (gitignored)
    "build/debug"
    "build/release"
    "build/static"
    "build/asan"
    "build/test"

    # tools
    "tools"
)

for dir in "${dirs[@]}"; do
    mkdir -p "$dir"
    # place .gitkeep only in non-build, non-vendor dirs
    case "$dir" in
        build/*|vendor/*)
            ;;
        *)
            if [ ! "$(ls -A "$dir" 2>/dev/null)" ]; then
                touch "$dir/.gitkeep"
            fi
            ;;
    esac
done

# ── vendor UPSTREAM_VERSION stubs ────────────────────────────────────────────
if [ ! -f vendor/libyaml/UPSTREAM_VERSION ]; then
    echo "0.2.5" > vendor/libyaml/UPSTREAM_VERSION
    echo "  created vendor/libyaml/UPSTREAM_VERSION"
fi

if [ ! -f vendor/mbedtls/UPSTREAM_VERSION ]; then
    echo "3.5.x" > vendor/mbedtls/UPSTREAM_VERSION
    echo "  created vendor/mbedtls/UPSTREAM_VERSION"
fi

# ── tests/fixtures/MANIFEST.md stub ──────────────────────────────────────────
if [ ! -f tests/fixtures/MANIFEST.md ]; then
    cat > tests/fixtures/MANIFEST.md << 'EOF'
# Fixture Manifest

Every fixture file must be documented here before CI will pass.

Format per entry:
  **filename**: purpose, algorithm/key, expected findings, gen_fixtures.sh line

---

## policies/valid/

<!-- document each .yaml file here -->

## policies/invalid/

<!-- document each .yaml file here -->

## tokens/valid/

<!-- document each .jwt file here -->

## tokens/invalid/

<!-- document each .jwt file here -->

## jwks/

<!-- document each .json file here -->

## expected/

<!-- document each expected output .json file here -->
EOF
    echo "  created tests/fixtures/MANIFEST.md"
fi

# ── tests/fixtures/gen_fixtures.sh stub ──────────────────────────────────────
if [ ! -f tests/fixtures/gen_fixtures.sh ]; then
    cat > tests/fixtures/gen_fixtures.sh << 'EOF'
#!/usr/bin/env bash
# tests/fixtures/gen_fixtures.sh
#
# Generates all JWT and JWKS test fixtures.
# Commit the outputs — do not regenerate during CI.
# Run manually when fixtures need to be updated.
#
# Requirements:
#   openssl    key generation
#   python3    JWT construction (pip install pyjwt cryptography)
#
# Usage:
#   bash tests/fixtures/gen_fixtures.sh

set -euo pipefail

FIXTURES="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Generating fixtures in: $FIXTURES"
echo ""
echo "TODO: implement fixture generation"
echo ""
echo "Each fixture should be documented in MANIFEST.md"
echo "with the line number in this script that created it."
echo ""
echo "Suggested structure:"
echo ""
echo "  # Line N: generate RSA keypair for RS256 tests"
echo "  openssl genrsa -out \$FIXTURES/jwks/rsa_rs256_private.pem 2048"
echo "  openssl rsa -in \$FIXTURES/jwks/rsa_rs256_private.pem \\"
echo "    -pubout -out \$FIXTURES/jwks/rsa_rs256_public.pem"
echo "  # convert to JWKS ..."
echo ""
echo "  # Line N: generate valid RS256 token"
echo "  python3 - << 'PYEOF'"
echo "  import jwt, json"
echo "  # ..."
echo "  PYEOF"

EOF
    chmod +x tests/fixtures/gen_fixtures.sh
    echo "  created tests/fixtures/gen_fixtures.sh"
fi

# ── header stubs ─────────────────────────────────────────────────────────────
# Create stub header files so includes resolve during early development

stub_header() {
    local path="$1"
    local guard="$2"
    local comment="$3"
    if [ ! -f "$path" ]; then
        cat > "$path" << EOF
#ifndef ${guard}
#define ${guard}

/* ${comment} */
/* TODO: implement */

#endif /* ${guard} */
EOF
        echo "  created $path"
    fi
}

stub_header "include/tokenlint.h"  "TOKENLINT_H"  "Core primitives: str_t, arena_t, tl_error_t"
stub_header "include/policy.h"     "POLICY_H"     "policy_t and compiled matchers"
stub_header "include/token.h"      "TOKEN_H"      "token_t — normalized JWT"
stub_header "include/jwks.h"       "JWKS_H"       "jwks_t, jwks_key_t"
stub_header "include/findings.h"   "FINDINGS_H"   "finding_t, finding_set_t, severity_t"
stub_header "include/eval_ctx.h"   "EVAL_CTX_H"   "eval_ctx_t, reftime_source_t"
stub_header "include/alg.h"        "ALG_H"        "alg_id_t, alg_allowset_t"

# ── source stubs ──────────────────────────────────────────────────────────────
stub_c() {
    local path="$1"
    local comment="$2"
    if [ ! -f "$path" ]; then
        cat > "$path" << EOF
/* ${comment} */
/* TODO: implement */
/* See docs/architecture.md for struct definitions */
/* See docs/SPEC.md for design philosophy */

#include "tokenlint.h"

EOF
        echo "  created $path"
    fi
}

stub_c "src/main.c"                  "Entry point — CLI dispatch only, no business logic"
stub_c "src/cli/cli.c"               "Argument parsing, stdin detection, --at parsing"
stub_c "src/parse/policy_parser.c"   "libyaml -> policy_t. Only file that calls libyaml."
stub_c "src/parse/token_parser.c"    "JWT string -> token_t. Base64url via crypto adapter."
stub_c "src/parse/jwks_parser.c"     "JWKS JSON -> jwks_t. Key material via crypto adapter."
stub_c "src/crypto/crypto_backend.c" "mbedTLS wrapper. Only file that calls mbedTLS."
stub_c "src/eval/eval_audit.c"       "Audit mode evaluation. TL-A findings."
stub_c "src/eval/eval_validate.c"    "Validate mode evaluation. TL-V, TL-C findings."
stub_c "src/eval/eval_alg.c"         "Algorithm + key compatibility checks."
stub_c "src/eval/eval_time.c"        "Time-sensitive claim checks. TL-V020 through TL-V025."
stub_c "src/eval/eval_issuer.c"      "Issuer validation."
stub_c "src/eval/eval_audience.c"    "Audience validation."
stub_c "src/eval/findings.c"         "findings_add(), findings_max_severity(), overflow."
stub_c "src/output/json_writer.c"    "jw_* interface. All strings through jw_escape()."
stub_c "src/output/report_json.c"    "finding_set_t -> JSON envelope."
stub_c "src/output/report_text.c"    "finding_set_t -> text output."
stub_c "src/util/arena.c"            "Arena allocator. Start here — everything depends on it."
stub_c "src/util/str.c"              "str_t utilities."
stub_c "src/util/time_util.c"        "--at parsing, ISO8601 formatting, unix timestamp conversion."

# ── test stubs ────────────────────────────────────────────────────────────────
stub_test() {
    local path="$1"
    local comment="$2"
    if [ ! -f "$path" ]; then
        cat > "$path" << EOF
/* ${comment} */
#include "../helpers/test_runner.h"

/* TODO: add tests */
/* See docs/test-strategy.md for test patterns */
/* See docs/finding-registry.md for finding codes */

int main(void) {
    test_case_t tests[] = {
        /* { "test_name", test_fn, is_security_property } */
    };
    return tl_run_tests(tests, sizeof(tests) / sizeof(tests[0]));
}
EOF
        echo "  created $path"
    fi
}

stub_test "tests/unit/test_arena.c"           "Arena allocator unit tests"
stub_test "tests/unit/test_str.c"             "str_t unit tests"
stub_test "tests/unit/test_alg.c"             "Algorithm table and bitmask unit tests"
stub_test "tests/unit/test_policy_parser.c"   "Policy parser unit tests"
stub_test "tests/unit/test_token_parser.c"    "Token parser unit tests"
stub_test "tests/unit/test_jwks_parser.c"     "JWKS parser unit tests"
stub_test "tests/unit/test_eval_audit.c"      "Audit evaluation unit tests"
stub_test "tests/unit/test_eval_validate.c"   "Validate evaluation unit tests"
stub_test "tests/unit/test_eval_alg.c"        "Algorithm evaluation unit tests"
stub_test "tests/unit/test_eval_time.c"       "Time evaluation unit tests"
stub_test "tests/unit/test_findings.c"        "Finding set unit tests"
stub_test "tests/unit/test_json_writer.c"     "JSON writer unit tests"
stub_test "tests/unit/test_suppressions.c"    "Suppression logic unit tests"

stub_test "tests/integration/test_audit_pass.c"          "Audit mode passing scenarios"
stub_test "tests/integration/test_audit_fail.c"          "Audit mode failing scenarios"
stub_test "tests/integration/test_validate_pass.c"       "Validate mode passing scenarios"
stub_test "tests/integration/test_validate_fail.c"       "Validate mode failing scenarios"
stub_test "tests/integration/test_validate_forensic.c"   "Forensic --at flag scenarios"
stub_test "tests/integration/test_cli_contract.c"        "CLI contract scenarios"

# ── test helper stubs ─────────────────────────────────────────────────────────
if [ ! -f tests/helpers/test_runner.h ]; then
    cat > tests/helpers/test_runner.h << 'EOF'
#ifndef TEST_RUNNER_H
#define TEST_RUNNER_H

/* Minimal C test framework for tokenlint */
/* See docs/test-strategy.md for usage */

#include <stdio.h>
#include <string.h>
#include "../../include/findings.h"

typedef void (*test_fn_t)(void);

typedef struct {
    const char *name;
    test_fn_t   fn;
    int         is_security_property;
} test_case_t;

/* TODO: implement tl_assert, tl_run_tests, finding assertion helpers */

#define TEST(name) static void test_##name(void)
#define SECURITY_PROP(name) static void prop_##name(void)

#define ASSERT_TRUE(expr) \
    tl_assert((expr), #expr, __FILE__, __LINE__)
#define ASSERT_FALSE(expr) \
    tl_assert(!(expr), "!(" #expr ")", __FILE__, __LINE__)
#define ASSERT_EQ(a, b) \
    tl_assert((a) == (b), #a " == " #b, __FILE__, __LINE__)
#define ASSERT_NULL(ptr) \
    tl_assert((ptr) == NULL, #ptr " == NULL", __FILE__, __LINE__)
#define ASSERT_NOT_NULL(ptr) \
    tl_assert((ptr) != NULL, #ptr " != NULL", __FILE__, __LINE__)

#define ASSERT_FINDING(fs, id) \
    tl_assert_finding_present((fs), (id), 1, __FILE__, __LINE__)
#define ASSERT_NO_FINDING(fs, id) \
    tl_assert_finding_present((fs), (id), 0, __FILE__, __LINE__)
#define ASSERT_FINDING_SUPPRESSED(fs, id) \
    tl_assert_finding_suppressed((fs), (id), __FILE__, __LINE__)
#define ASSERT_CLEAN(fs) \
    tl_assert_no_active_fail((fs), __FILE__, __LINE__)

void tl_assert(int cond, const char *expr, const char *file, int line);
void tl_assert_finding_present(const finding_set_t *fs, const char *id,
                                int expect_present,
                                const char *file, int line);
void tl_assert_finding_suppressed(const finding_set_t *fs, const char *id,
                                   const char *file, int line);
void tl_assert_no_active_fail(const finding_set_t *fs,
                               const char *file, int line);

int tl_run_tests(const test_case_t *tests, size_t count);

#endif /* TEST_RUNNER_H */
EOF
    echo "  created tests/helpers/test_runner.h"
fi

if [ ! -f tests/helpers/policy_builder.h ]; then
    cat > tests/helpers/policy_builder.h << 'EOF'
#ifndef POLICY_BUILDER_H
#define POLICY_BUILDER_H

/* Construct policy_t directly in tests without touching the YAML parser.
 * See docs/test-strategy.md and docs/architecture.md.
 * TODO: implement builder pattern */

#include "../../include/policy.h"
#include "../../include/tokenlint.h"

/* Example intended usage:
 *
 * policy_t p = policy_builder_new(arena)
 *     .environment(ENV_PROD)
 *     .issuer_exact("https://auth.example.com")
 *     .audience_exact("my-service")
 *     .algorithm(ALG_RS256)
 *     .require_claims(CLAIM_EXP | CLAIM_ISS | CLAIM_AUD)
 *     .max_ttl(3600)
 *     .build();
 */

#endif /* POLICY_BUILDER_H */
EOF
    echo "  created tests/helpers/policy_builder.h"
fi

if [ ! -f tests/helpers/token_builder.h ]; then
    cat > tests/helpers/token_builder.h << 'EOF'
#ifndef TOKEN_BUILDER_H
#define TOKEN_BUILDER_H

/* Construct token_t directly in tests without JWT parsing.
 * See docs/test-strategy.md and docs/architecture.md.
 * TODO: implement builder pattern */

#include "../../include/token.h"
#include "../../include/tokenlint.h"

/* Example intended usage:
 *
 * token_t t = token_builder_new(arena)
 *     .alg(ALG_RS256)
 *     .kid("key-2026-01")
 *     .iss("https://auth.example.com")
 *     .aud_single("my-service")
 *     .exp(reference_time + 3600)
 *     .iat(reference_time)
 *     .build();
 */

#endif /* TOKEN_BUILDER_H */
EOF
    echo "  created tests/helpers/token_builder.h"
fi

# ── security property stubs ───────────────────────────────────────────────────
if [ ! -f tests/security_properties/security_props.c ]; then
    cat > tests/security_properties/security_props.c << 'EOF'
/* Security property tests — release-blocking.
 * Runner exits 2 (not 1) on any failure.
 * See docs/test-strategy.md for all 12 property definitions.
 */

#include "../helpers/test_runner.h"

/* TODO: implement all 12 named security properties:
 *
 * PROP_ALG_NONE_ALWAYS_FAILS
 * PROP_POLICY_ALG_NONE_SCHEMA_FAILS
 * PROP_BAD_SIGNATURE_ALWAYS_FAILS
 * PROP_UNKNOWN_ALG_ALWAYS_FAILS
 * PROP_AMBIGUOUS_KEY_MATCH_FAILS
 * PROP_REQUIRE_KID_PREVENTS_FALLBACK
 * PROP_EXPIRED_TOKEN_ALWAYS_FAILS
 * PROP_SUPPRESSION_CANNOT_HIDE_SCHEMA_ERRORS
 * PROP_CLI_SUPPRESSION_NEVER_AFFECTS_EXIT_BY_DEFAULT
 * PROP_AT_FLAG_PRODUCES_DETERMINISTIC_OUTPUT
 * PROP_SCHEMA_VERSION_MISMATCH_HALTS
 * PROP_FINDING_OVERFLOW_NEVER_SILENT
 */

int main(void) {
    test_case_t props[] = {
        /* { "PROP_NAME", prop_fn, 1 } */
    };
    return tl_run_tests(props, sizeof(props) / sizeof(props[0]));
}
EOF
    echo "  created tests/security_properties/security_props.c"
fi

# ── CLI test stub ─────────────────────────────────────────────────────────────
if [ ! -f tests/cli/run_all.sh ]; then
    cat > tests/cli/run_all.sh << 'EOF'
#!/usr/bin/env bash
# tests/cli/run_all.sh
# Shell-level CLI contract tests.
# Requires tokenlint binary in PATH or passed as TL_BIN env var.
# See docs/test-strategy.md for full list of scenarios.

set -euo pipefail

TL_BIN="${TL_BIN:-tokenlint}"

pass=0
fail=0

check() {
    local desc="$1"
    local expected_exit="$2"
    shift 2
    local actual_exit=0
    "$TL_BIN" "$@" > /dev/null 2>&1 || actual_exit=$?
    if [ "$actual_exit" -eq "$expected_exit" ]; then
        echo "PASS  $desc"
        pass=$((pass + 1))
    else
        echo "FAIL  $desc (expected exit $expected_exit, got $actual_exit)"
        fail=$((fail + 1))
    fi
}

# TODO: add CLI contract tests
# Example:
# check "unknown subcommand exits 4" 4 badsubcmd
# check "--version exits 0"          0 --version

echo ""
echo "CLI tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
EOF
    chmod +x tests/cli/run_all.sh
    echo "  created tests/cli/run_all.sh"
fi

echo ""
echo "Scaffold complete."
echo ""
echo "Next steps:"
echo "  1. Vendor libyaml and mbedTLS into vendor/"
echo "     See docs/build-contract.md for pinned versions"
echo "  2. Start with the foundation:"
echo "     include/tokenlint.h  (str_t, arena_t, tl_error_t)"
echo "     src/util/arena.c"
echo "     src/util/str.c"
echo "     tests/unit/test_arena.c"
echo "     tests/unit/test_str.c"
echo "  3. Read docs/architecture.md before writing any struct"
echo "  4. Read docs/CONTRIBUTING.md before writing any code"
echo ""
echo "See docs/SPEC.md for the full specification index."
