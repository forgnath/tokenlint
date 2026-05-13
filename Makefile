# tokenlint Makefile
# Requires: C11 compiler (gcc or clang), GNU Make 3.81+

VERSION     := $(shell cat VERSION)
CC          ?= gcc
AR          ?= ar

# ── directories ─────────────────────────────────────────────────────────────
SRC         := src
INC         := include
VENDOR      := vendor
BUILD       := build
TESTS       := tests

# ── compiler flags ───────────────────────────────────────────────────────────
CFLAGS_COMMON := \
    -std=c11          \
    -Wall             \
    -Wextra           \
    -Wpedantic        \
    -Werror           \
    -Wshadow          \
    -Wdouble-promotion \
    -Wformat=2        \
    -Wundef           \
    -fno-common       \
    -DTL_VERSION=\"$(VERSION)\"

CFLAGS_DEBUG   := $(CFLAGS_COMMON) -O0 -g3
CFLAGS_RELEASE := $(CFLAGS_COMMON) -O2 -DNDEBUG \
                  -fstack-protector-strong -D_FORTIFY_SOURCE=2
CFLAGS_ASAN    := $(CFLAGS_COMMON) -O0 -g3 \
                  -fsanitize=address,undefined -fno-omit-frame-pointer

# ── include paths by layer ───────────────────────────────────────────────────
# parse/: libyaml headers available
# crypto/: mbedTLS headers available
# all others: only include/ (no vendor headers)
INC_PARSE   := -I$(INC) -I$(VENDOR)/libyaml/include
INC_CRYPTO  := -I$(INC) -I$(VENDOR)/mbedtls/include
INC_DEFAULT := -I$(INC)

# ── source files ─────────────────────────────────────────────────────────────
SRCS_UTIL   := $(wildcard $(SRC)/util/*.c)
SRCS_PARSE  := $(wildcard $(SRC)/parse/*.c)
SRCS_CRYPTO := $(wildcard $(SRC)/crypto/*.c)
SRCS_EVAL   := $(wildcard $(SRC)/eval/*.c)
SRCS_OUTPUT := $(wildcard $(SRC)/output/*.c)
SRCS_CLI    := $(wildcard $(SRC)/cli/*.c)
SRCS_VENDOR_YAML   := $(wildcard $(VENDOR)/libyaml/src/*.c)
SRCS_VENDOR_MBEDTLS := $(wildcard $(VENDOR)/mbedtls/library/*.c)

# ── default target: debug build ───────────────────────────────────────────────
.PHONY: all
all: debug

# ── debug ────────────────────────────────────────────────────────────────────
.PHONY: debug
debug: $(BUILD)/debug/tokenlint

$(BUILD)/debug/tokenlint: CFLAGS := $(CFLAGS_DEBUG)
$(BUILD)/debug/tokenlint:
	@mkdir -p $(BUILD)/debug
	@echo "Building debug..."
	# TODO: compile objects and link
	# Placeholder until source files exist

# ── release ──────────────────────────────────────────────────────────────────
.PHONY: release
release: $(BUILD)/release/tokenlint

$(BUILD)/release/tokenlint: CFLAGS := $(CFLAGS_RELEASE)
$(BUILD)/release/tokenlint:
	@mkdir -p $(BUILD)/release
	@echo "Building release..."
	# TODO: compile objects and link

# ── static (Linux + musl) ────────────────────────────────────────────────────
.PHONY: static
static:
	@mkdir -p $(BUILD)/static
	@echo "Building static binary (requires musl-gcc or CC=musl-gcc)..."
	# TODO: compile and link with -static -static-libgcc

# ── asan ─────────────────────────────────────────────────────────────────────
.PHONY: asan
asan: CFLAGS := $(CFLAGS_ASAN)
asan:
	@mkdir -p $(BUILD)/asan
	@echo "Building with sanitizers..."
	# TODO: compile objects and link

# ── test ─────────────────────────────────────────────────────────────────────
.PHONY: test
test: check-coverage
	@mkdir -p $(BUILD)/test
	@echo "Building and running tests..."
	# TODO: build test binaries and run

# ── check-coverage ────────────────────────────────────────────────────────────
# Verify every finding in finding_registry.def has both test functions.
.PHONY: check-coverage
check-coverage:
	@echo "Checking finding test coverage..."
	@python3 tools/check_coverage.py finding_registry.def $(TESTS) || exit 1
	@echo "Coverage check passed."

# ── lint ─────────────────────────────────────────────────────────────────────
.PHONY: lint
lint:
	@command -v clang-tidy >/dev/null 2>&1 || \
	    { echo "clang-tidy not found, skipping"; exit 0; }
	clang-tidy $(SRC)/**/*.c -- $(CFLAGS_COMMON) $(INC_DEFAULT)

# ── format ───────────────────────────────────────────────────────────────────
.PHONY: format
format:
	@command -v clang-format >/dev/null 2>&1 || \
	    { echo "clang-format not found, skipping"; exit 0; }
	clang-format -i $(SRC)/**/*.c $(INC)/*.h

# ── clean ─────────────────────────────────────────────────────────────────────
.PHONY: clean
clean:
	rm -rf $(BUILD)

# ── version ───────────────────────────────────────────────────────────────────
.PHONY: version
version:
	@cat VERSION
