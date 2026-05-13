# Build Contract — tokenlint v1

---

## Language and standard

| Property | Value |
|---|---|
| Language | C |
| Standard | C11 (ISO/IEC 9899:2011) |
| Compiler | GCC 9+ or Clang 10+ |
| macOS | Apple Clang 12+ |

### C11 features used

- `_Static_assert` — struct layout, enum completeness, capacity bounds
- Designated initializers
- Flexible array members (`arena_block_t`)
- `stdint.h` / `stdbool.h` / `stddef.h`

### C11 features explicitly avoided

- `_Atomic` / `threads.h` — no concurrency in v1
- VLAs — stack size unpredictable
- `_Generic` — only if genuinely clarifying
- Complex numbers — not applicable

---

## Compiler flags

### All builds

```makefile
CFLAGS_COMMON = \
    -std=c11          \
    -Wall             \
    -Wextra           \
    -Wpedantic        \
    -Werror           \
    -Wshadow          \
    -Wdouble-promotion \
    -Wformat=2        \
    -Wundef           \
    -fno-common
```

### Release builds

```makefile
CFLAGS_RELEASE = \
    $(CFLAGS_COMMON)       \
    -O2                    \
    -DNDEBUG               \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2
```

### Debug builds

```makefile
CFLAGS_DEBUG = \
    $(CFLAGS_COMMON) \
    -O0              \
    -g3              \
    -fsanitize=address,undefined \
    -fno-omit-frame-pointer
```

---

## Dependencies

### Dependency policy

- No system runtime dependencies in release builds
- All third-party code vendored in tree under `vendor/`
- Third-party APIs must not leak into core evaluation code
- One wrapper layer between each dependency and tokenlint internals

### Vendored dependencies (three only)

#### 1. libyaml

| Property | Value |
|---|---|
| Version | 0.2.5 (pinned exact) |
| License | MIT |
| Location | `vendor/libyaml/` |
| Used by | `src/parse/policy_parser.c` only |
| Purpose | YAML policy file parsing |

No libyaml types visible in any header outside `src/parse/`.

#### 2. mbedTLS

| Property | Value |
|---|---|
| Version | 3.5.x LTS (pinned exact) |
| License | Apache 2.0 |
| Location | `vendor/mbedtls/` |
| Used by | `src/crypto/crypto_backend.c` only |
| Purpose | Signature verification, base64url decode |

Algorithm support:

| Algorithm | mbedTLS feature | Status |
|---|---|---|
| RS256/384/512 | `MBEDTLS_RSA_PKCS_V15` | ✓ supported |
| PS256/384/512 | `MBEDTLS_RSA_PKCS_V21` | ✓ supported |
| ES256 | `MBEDTLS_ECP_DP_SECP256R1` | ✓ supported |
| ES384 | `MBEDTLS_ECP_DP_SECP384R1` | ✓ supported |
| ES512 | `MBEDTLS_ECP_DP_SECP521R1` | ✓ supported |
| EdDSA/Ed25519 | `MBEDTLS_ECP_DP_CURVE25519` | ✓ supported |
| Ed448 | limited in mbedTLS 3.x | recognized; FAIL TL-V002 in v1 |
| HS256/384/512 | `MBEDTLS_MD_SHA256/384/512` | ✓ supported |

No mbedTLS types visible outside `src/crypto/crypto_backend.c`.

#### 3. json_writer (custom)

| Property | Value |
|---|---|
| Location | `src/output/json_writer.c` + `src/output/json_writer.h` |
| Purpose | JSON report generation |
| Dependencies | None |

All string values pass through `jw_escape()` internally. No manual string
interpolation into JSON output. No `sprintf()` into JSON buffers.

`jw_escape()` handles:
- `"` → `\"`
- `\` → `\\`
- Control characters → `\uXXXX`
- Valid UTF-8 passthrough

---

## Build system

| Property | Value |
|---|---|
| Build system | GNU Make |
| Make version | 3.81+ |
| Requirements | C11 compiler + GNU Make only |

No autoconf, cmake, meson, or other build generators in v1.

### Makefile targets

| Target | Output | Description |
|---|---|---|
| `make` | `build/debug/tokenlint` | Debug binary (default) |
| `make release` | `build/release/tokenlint` | Optimized release binary |
| `make static` | `build/static/tokenlint` | Fully static release (Linux, musl) |
| `make test` | — | Build and run full test suite |
| `make clean` | — | Remove all build artifacts |
| `make asan` | `build/asan/tokenlint` | Address + UB sanitizer build |
| `make lint` | — | Run clang-tidy (if available) |
| `make format` | — | Run clang-format (if available) |
| `make check-coverage` | — | Verify finding registry test coverage |
| `make vendor` | — | Manual: update vendored dependencies |

### Version embedding

```makefile
VERSION := $(shell cat VERSION)
CFLAGS  += -DTL_VERSION=\"$(VERSION)\"
```

The `VERSION` file at project root contains the semver string. Available via
`tokenlint --version`.

---

## Target platforms

### Primary (CI-gated, must pass before merge)

| Platform | Compiler | Architecture |
|---|---|---|
| Linux (glibc) | GCC | x86_64 |
| Linux (glibc) | Clang | x86_64 |
| Linux (musl) | GCC | x86_64 |
| Linux (glibc) | GCC | aarch64 |
| macOS | Apple Clang | x86_64 |
| macOS | Apple Clang | aarch64 (M-series) |

### Secondary (best effort, non-blocking)

| Platform | Compiler | Architecture |
|---|---|---|
| Linux (musl) | GCC | aarch64 |
| FreeBSD | Clang | x86_64 |
| OpenBSD | Clang | x86_64 |

### Explicitly not supported in v1

| Platform | Notes |
|---|---|
| Windows native | POSIX assumptions; defer to v2 |
| WASM | Out of scope |
| RISC-V | Out of scope |

WSL is Linux. Treated as Linux for all purposes.

---

## Static binary contract

### Linux (canonical portable artifact)

```bash
# Build with musl-gcc
CC=musl-gcc make static

# Verify
file build/static/tokenlint
# → ELF 64-bit, statically linked

ldd build/static/tokenlint
# → not a dynamic executable
```

Linker flags:
```makefile
LDFLAGS_STATIC = -static -static-libgcc
```

Result: single ELF binary, no dynamic library dependencies, runs on any Linux
kernel ≥ 4.x. Both x86_64 and aarch64 variants produced for release.

### macOS (standalone binary)

Fully static binaries are not supported on macOS (system libraries required by
design). Release contract:

- No third-party dylib dependencies
- Only system libraries permitted: `libSystem.dylib`
- Verify with `otool -L build/release/tokenlint`

```bash
# Universal binary (x86_64 + aarch64)
make release ARCH=universal
lipo -create build/release/tokenlint-x86_64 \
             build/release/tokenlint-arm64 \
     -output build/release/tokenlint
```

Code signing: ad-hoc signed minimum for release:
```bash
codesign --sign - build/release/tokenlint
```

Notarization deferred to v1.1.

---

## Dependency isolation — enforced by Makefile

```makefile
# parse objects: libyaml headers available
$(BUILD)/parse/%.o: src/parse/%.c
	$(CC) $(CFLAGS) -Ivendor/libyaml/include -Iinclude -c $< -o $@

# crypto objects: mbedTLS headers available
$(BUILD)/crypto/%.o: src/crypto/%.c
	$(CC) $(CFLAGS) -Ivendor/mbedtls/include -Iinclude -c $< -o $@

# eval, output, util objects: NO vendor headers
$(BUILD)/eval/%.o: src/eval/%.c
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@

$(BUILD)/output/%.o: src/output/%.c
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@
```

Attempting to `#include <yaml.h>` from `src/eval/` is a compile error.
Attempting to `#include <mbedtls/...>` from `src/eval/` is a compile error.

---

## Deterministic builds

Goal: same source + same toolchain = identical binary.

```makefile
CFLAGS += -ffile-prefix-map=$(PWD)=.   # strip absolute paths from debug info
# No -DBUILD_DATE, no __DATE__, no __TIME__ in source
```

Not guaranteed across different compiler versions or OS versions. Reproducibility
within a toolchain version is the practical goal for v1.

---

## CI pipeline

### Required checks (block merge on failure)

| Stage | Check |
|---|---|
| 1 | `make check-coverage` — finding registry test coverage |
| 2 | `make lint` — clang-tidy clean |
| 3 | `make debug` — GCC + Clang, all primary targets |
| 4 | `make release` — GCC + Clang, all primary targets |
| 5 | `make static` — musl GCC, Linux x86_64 + aarch64 |
| 6 | `make test` — full test suite |
| 7 | `make asan` — sanitizer build + test suite clean |
| 8 | Static binary verification (`ldd` check) |

### Release artifact matrix

| Artifact | Description |
|---|---|
| `tokenlint-linux-x86_64-static` | Fully static Linux binary |
| `tokenlint-linux-aarch64-static` | Fully static Linux ARM64 binary |
| `tokenlint-macos-universal` | Universal macOS binary (x86_64 + aarch64) |
| `sha256sums.txt` | Checksums for all artifacts |

Each artifact checksum signed with project key.

---

## Vendored dependency management

Each vendored dependency has an `UPSTREAM_VERSION` file recording the exact
pinned version:

```
vendor/libyaml/UPSTREAM_VERSION    → 0.2.5
vendor/mbedtls/UPSTREAM_VERSION    → 3.5.2
```

To update a vendored dependency:
1. Download new version
2. Replace files in `vendor/<name>/`
3. Update `UPSTREAM_VERSION`
4. Run full CI
5. Commit as a dedicated PR with explicit review

Vendor updates are never bundled with feature changes.
