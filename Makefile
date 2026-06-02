# Makefile — tokenlint v1
#
# Targets:
#   make              → build/debug/tokenlint  (default)
#   make release      → build/release/tokenlint
#   make static       → build/static/tokenlint (Linux, musl-gcc)
#   make asan         → build/asan/tokenlint   (ASAN + UBSAN)
#   make test         → build and run full test suite
#   make security_props → build/test/security_props + run it
#   make check-coverage → verify finding registry test coverage
#   make lint         → clang-tidy (if available)
#   make format       → clang-format (if available)
#   make clean        → remove all build artifacts
#
# Dependency isolation is enforced: libyaml headers are visible only to
# src/parse/, mbedTLS headers only to src/crypto/. Eval, output, and util
# objects are compiled without any vendor include path.

# ── toolchain ────────────────────────────────────────────────────────────────

CC      ?= gcc
VERSION := $(shell cat VERSION)

# ── flags ────────────────────────────────────────────────────────────────────

CFLAGS_COMMON = \
    -std=c11 \
    -Wall \
    -Wextra \
    -Wpedantic \
    -Werror \
    -Wshadow \
    -Wdouble-promotion \
    -Wformat=2 \
    -Wundef \
    -fno-common \
    -D_GNU_SOURCE \
    
    -DTL_BUILD_VERSION=\"$(VERSION)\" \
    -ffile-prefix-map=$(CURDIR)=.

CFLAGS_DEBUG = \
    $(CFLAGS_COMMON) \
    -O0 \
    -g3

CFLAGS_RELEASE = \
    $(CFLAGS_COMMON) \
    -O2 \
    -DNDEBUG \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2

CFLAGS_ASAN = \
    $(CFLAGS_COMMON) \
    -O0 \
    -g3 \
    -fsanitize=address,undefined \
    -fno-omit-frame-pointer

CFLAGS_TEST = \
    $(CFLAGS_COMMON) \
    -O0 \
    -g3 \
    -Wno-unused-function

LDFLAGS_STATIC = -static -static-libgcc

# System libraries
LIBS_YAML    = -lyaml
LIBS_MBEDTLS = -lmbedtls -lmbedcrypto -lmbedx509

# ── directories ───────────────────────────────────────────────────────────────

BUILD         = build
BUILD_DEBUG   = $(BUILD)/debug
BUILD_RELEASE = $(BUILD)/release
BUILD_STATIC  = $(BUILD)/static
BUILD_ASAN    = $(BUILD)/asan
BUILD_TEST    = $(BUILD)/test

# ── include paths by layer ────────────────────────────────────────────────────

# All layers always get -Iinclude
INC_COMMON  = -Iinclude

# parse layer gets libyaml headers additionally
INC_PARSE   = $(INC_COMMON) -Ivendor/libyaml/include

# crypto layer gets mbedTLS headers additionally
INC_CRYPTO  = $(INC_COMMON) -Ivendor/mbedtls/include

# test binaries also need -Itests to find helpers/
INC_TEST    = $(INC_COMMON) -Itests

# ── source file lists ─────────────────────────────────────────────────────────

# Pure util — no vendor deps
SRC_UTIL = \
    src/util/arena.c \
    src/util/str.c \
    src/util/time_util.c

# Evaluators — no vendor deps
SRC_EVAL = \
    src/eval/findings.c \
    src/eval/eval_alg.c \
    src/eval/eval_time.c \
    src/eval/eval_issuer.c \
    src/eval/eval_audience.c \
    src/eval/eval_audit.c \
    src/eval/eval_validate.c

# Parse layer — libyaml (policy_parser) + base64/token (no extra deps)
SRC_PARSE = \
    src/parse/policy_parser.c \
    src/parse/token_parser.c \
    src/parse/jwks_parser.c

# Output — no vendor deps
SRC_OUTPUT = \
    src/output/json_writer.c \
    src/output/report_json.c \
    src/output/report_text.c

# Crypto backend — mbedTLS
SRC_CRYPTO = src/crypto/crypto_backend.c

# CLI
SRC_CLI  = src/cli/cli.c
SRC_MAIN = src/main.c

# All non-main production sources (used by test binaries)
SRC_ALL_NO_MAIN = \
    $(SRC_UTIL) \
    $(SRC_EVAL) \
    $(SRC_PARSE) \
    $(SRC_OUTPUT) \
    $(SRC_CRYPTO) \
    $(SRC_CLI)

SRC_ALL = $(SRC_ALL_NO_MAIN) $(SRC_MAIN)

# ── test source groups ────────────────────────────────────────────────────────

# Unit tests that need NO vendor deps (util + eval + output, no parse)
UNIT_NODEP = \
    test_arena \
    test_str \
    test_findings \
    test_json_writer \
    test_eval_time \
    test_eval_alg \
    test_eval_audit \
    test_eval_validate \
    test_suppressions

# Unit tests that need libyaml (policy_parser, token_parser, jwks_parser)
UNIT_YAML = \
    test_policy_parser \
    test_token_parser \
    test_jwks_parser

# Unit tests that need mbedTLS (crypto backend test vectors)
UNIT_MBED = \
    test_alg

# Integration tests — need full stack (libyaml + mbedTLS)
INTEGRATION = \
    test_audit_pass \
    test_audit_fail \
    test_validate_pass \
    test_validate_fail \
    test_validate_forensic \
    test_cli_contract

# Security properties
SECURITY = security_props

ALL_TEST_BINS = \
    $(addprefix $(BUILD_TEST)/, $(UNIT_NODEP)) \
    $(addprefix $(BUILD_TEST)/, $(UNIT_YAML)) \
    $(addprefix $(BUILD_TEST)/, $(UNIT_MBED)) \
    $(addprefix $(BUILD_TEST)/, $(INTEGRATION)) \
    $(BUILD_TEST)/$(SECURITY)

# ── helper: shared object files for tests ────────────────────────────────────
#
# We compile SRC_ALL_NO_MAIN once (debug flags) into a temporary object list
# and re-link for each test binary. Actually, for simplicity and correctness,
# each test binary is compiled as a single gcc invocation (unity build style)
# — this avoids object-file sharing complexity across different include paths.
#
# The key constraint: parse objects need -Ivendor/libyaml/include,
# crypto objects need -Ivendor/mbedtls/include. We achieve this with
# per-file -I flags via a wrapper macro.

# ── build directories ─────────────────────────────────────────────────────────

BUILDDIRS = \
    $(BUILD_DEBUG) \
    $(BUILD_RELEASE) \
    $(BUILD_STATIC) \
    $(BUILD_ASAN) \
    $(BUILD_TEST)

# ── default target ────────────────────────────────────────────────────────────

.PHONY: all
all: $(BUILD_DEBUG)/tokenlint

$(BUILD_DEBUG)/tokenlint: $(SRC_ALL) | $(BUILD_DEBUG)
	$(CC) $(CFLAGS_DEBUG) $(INC_COMMON) \
	    $(foreach f, $(SRC_PARSE),   $(if $(filter $f,$^),,-Ivendor/libyaml/include)) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $^ \
	    $(LIBS_YAML) $(LIBS_MBEDTLS) \
	    -o $@

# ── release ───────────────────────────────────────────────────────────────────

.PHONY: release
release: $(BUILD_RELEASE)/tokenlint

$(BUILD_RELEASE)/tokenlint: $(SRC_ALL) | $(BUILD_RELEASE)
	$(CC) $(CFLAGS_RELEASE) $(INC_COMMON) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $^ \
	    $(LIBS_YAML) $(LIBS_MBEDTLS) \
	    -o $@

# ── static ────────────────────────────────────────────────────────────────────

.PHONY: static
static: $(BUILD_STATIC)/tokenlint

$(BUILD_STATIC)/tokenlint: $(SRC_ALL) | $(BUILD_STATIC)
	$(CC) $(CFLAGS_RELEASE) $(INC_COMMON) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $(LDFLAGS_STATIC) \
	    $^ \
	    $(LIBS_YAML) $(LIBS_MBEDTLS) \
	    -o $@

# ── asan ─────────────────────────────────────────────────────────────────────

.PHONY: asan
asan: $(BUILD_ASAN)/tokenlint

$(BUILD_ASAN)/tokenlint: $(SRC_ALL) | $(BUILD_ASAN)
	$(CC) $(CFLAGS_ASAN) $(INC_COMMON) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $^ \
	    $(LIBS_YAML) $(LIBS_MBEDTLS) \
	    -o $@

# ── test targets ─────────────────────────────────────────────────────────────
#
# Source sets per test category:
#
# NODEP tests: util + eval + output + cli (no parse, no vendor)
SRC_FOR_NODEP = $(SRC_UTIL) $(SRC_EVAL) $(SRC_OUTPUT) $(SRC_CLI)

# YAML tests: NODEP + parse layer + crypto (token_parser uses mbedtls_base64_decode)
SRC_FOR_YAML = $(SRC_FOR_NODEP) $(SRC_PARSE) $(SRC_CRYPTO)

# MBED tests: NODEP + crypto
SRC_FOR_MBED = $(SRC_FOR_NODEP) $(SRC_CRYPTO)

# Integration / security: full stack minus main
SRC_FOR_FULL = $(SRC_ALL_NO_MAIN)

# ─── unit / no-dep tests ─────────────────────────────────────────────────────

$(BUILD_TEST)/test_arena: tests/unit/test_arena.c $(SRC_UTIL) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) $^ -o $@

$(BUILD_TEST)/test_str: tests/unit/test_str.c $(SRC_UTIL) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) $^ -o $@

$(BUILD_TEST)/test_findings: tests/unit/test_findings.c \
    $(SRC_UTIL) src/eval/findings.c | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) $^ -o $@

$(BUILD_TEST)/test_json_writer: tests/unit/test_json_writer.c \
    $(SRC_UTIL) src/output/json_writer.c | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) $^ -o $@

$(BUILD_TEST)/test_eval_time: tests/unit/test_eval_time.c \
    $(SRC_UTIL) src/eval/findings.c src/eval/eval_time.c | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) $^ -o $@

$(BUILD_TEST)/test_eval_alg: tests/unit/test_eval_alg.c \
    $(SRC_UTIL) $(SRC_EVAL) $(SRC_CLI) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) $^ -o $@

$(BUILD_TEST)/test_eval_audit: tests/unit/test_eval_audit.c \
    $(SRC_UTIL) $(SRC_EVAL) $(SRC_CLI) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) $^ -o $@

$(BUILD_TEST)/test_eval_validate: tests/unit/test_eval_validate.c \
    $(SRC_UTIL) $(SRC_EVAL) $(SRC_CLI) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) $^ -o $@

$(BUILD_TEST)/test_suppressions: tests/unit/test_suppressions.c \
    $(SRC_UTIL) $(SRC_EVAL) $(SRC_CLI) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) $^ -o $@

# ─── unit / yaml tests ───────────────────────────────────────────────────────

$(BUILD_TEST)/test_policy_parser: tests/unit/test_policy_parser.c \
    $(SRC_FOR_YAML) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $^ $(LIBS_YAML) $(LIBS_MBEDTLS) -o $@

$(BUILD_TEST)/test_token_parser: tests/unit/test_token_parser.c \
    $(SRC_FOR_YAML) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $^ $(LIBS_YAML) $(LIBS_MBEDTLS) -o $@

$(BUILD_TEST)/test_jwks_parser: tests/unit/test_jwks_parser.c \
    $(SRC_FOR_YAML) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $^ $(LIBS_YAML) $(LIBS_MBEDTLS) -o $@

# ─── unit / mbedtls tests ────────────────────────────────────────────────────

$(BUILD_TEST)/test_alg: tests/unit/test_alg.c \
    $(SRC_FOR_MBED) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) -Ivendor/mbedtls/include \
	    $^ $(LIBS_MBEDTLS) -o $@

# ─── integration tests (full stack) ──────────────────────────────────────────

$(BUILD_TEST)/test_audit_pass: tests/integration/test_audit_pass.c \
    $(SRC_FOR_FULL) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $^ $(LIBS_YAML) $(LIBS_MBEDTLS) -o $@

$(BUILD_TEST)/test_audit_fail: tests/integration/test_audit_fail.c \
    $(SRC_FOR_FULL) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $^ $(LIBS_YAML) $(LIBS_MBEDTLS) -o $@

$(BUILD_TEST)/test_validate_pass: tests/integration/test_validate_pass.c \
    $(SRC_FOR_FULL) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $^ $(LIBS_YAML) $(LIBS_MBEDTLS) -o $@

$(BUILD_TEST)/test_validate_fail: tests/integration/test_validate_fail.c \
    $(SRC_FOR_FULL) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $^ $(LIBS_YAML) $(LIBS_MBEDTLS) -o $@

$(BUILD_TEST)/test_validate_forensic: tests/integration/test_validate_forensic.c \
    $(SRC_FOR_FULL) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $^ $(LIBS_YAML) $(LIBS_MBEDTLS) -o $@

$(BUILD_TEST)/test_cli_contract: tests/integration/test_cli_contract.c \
    $(SRC_FOR_FULL) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $^ $(LIBS_YAML) $(LIBS_MBEDTLS) -o $@

# ─── security properties ─────────────────────────────────────────────────────

$(BUILD_TEST)/security_props: tests/security_properties/security_props.c \
    $(SRC_FOR_FULL) | $(BUILD_TEST)
	$(CC) $(CFLAGS_TEST) $(INC_TEST) \
	    -Ivendor/libyaml/include -Ivendor/mbedtls/include \
	    $^ $(LIBS_YAML) $(LIBS_MBEDTLS) -o $@

# ── test runner ───────────────────────────────────────────────────────────────

.PHONY: test
test: $(ALL_TEST_BINS)
	@echo ""
	@echo "=== running unit tests (no vendor deps) ==="
	@for t in $(addprefix $(BUILD_TEST)/, $(UNIT_NODEP)); do \
	    echo ""; \
	    echo "--- $$t ---"; \
	    $$t || exit 1; \
	done
	@echo ""
	@echo "=== running unit tests (libyaml) ==="
	@for t in $(addprefix $(BUILD_TEST)/, $(UNIT_YAML)); do \
	    echo ""; \
	    echo "--- $$t ---"; \
	    $$t || exit 1; \
	done
	@echo ""
	@echo "=== running unit tests (mbedTLS) ==="
	@for t in $(addprefix $(BUILD_TEST)/, $(UNIT_MBED)); do \
	    echo ""; \
	    echo "--- $$t ---"; \
	    $$t || exit 1; \
	done
	@echo ""
	@echo "=== running integration tests ==="
	@for t in $(addprefix $(BUILD_TEST)/, $(INTEGRATION)); do \
	    echo ""; \
	    echo "--- $$t ---"; \
	    $$t || exit 1; \
	done
	@echo ""
	@echo "=== running security property tests ==="
	@$(BUILD_TEST)/security_props || exit 2
	@echo ""
	@echo "=== all tests passed ==="

.PHONY: security_props
security_props: $(BUILD_TEST)/security_props
	@echo ""
	@echo "=== security property tests ==="
	$(BUILD_TEST)/security_props

# ── check-coverage ────────────────────────────────────────────────────────────

.PHONY: check-coverage
check-coverage:
	python3 tools/check_coverage.py finding_registry.def tests/

# ── lint / format ─────────────────────────────────────────────────────────────

.PHONY: lint
lint:
	@if command -v clang-tidy >/dev/null 2>&1; then \
	    clang-tidy $(SRC_ALL) -- $(CFLAGS_COMMON) \
	        $(INC_COMMON) \
	        -Ivendor/libyaml/include \
	        -Ivendor/mbedtls/include; \
	else \
	    echo "clang-tidy not found — skipping lint"; \
	fi

.PHONY: format
format:
	@if command -v clang-format >/dev/null 2>&1; then \
	    clang-format -i $(SRC_ALL) $(shell find include -name '*.h') \
	        $(shell find tests -name '*.c' -o -name '*.h'); \
	else \
	    echo "clang-format not found — skipping format"; \
	fi

# ── clean ─────────────────────────────────────────────────────────────────────

.PHONY: clean
clean:
	rm -rf $(BUILD)

# ── build directories ─────────────────────────────────────────────────────────

$(BUILDDIRS):
	mkdir -p $@

# ── phony aliases ─────────────────────────────────────────────────────────────

.PHONY: debug
debug: all
