/*
 * tests/helpers/test_runner.h
 *
 * Minimal test framework for tokenlint unit tests.
 * ~200 lines. No external dependencies. Fully auditable.
 *
 * Usage:
 *
 *   #include "helpers/test_runner.h"
 *
 *   TEST(my_test) {
 *       int x = 1 + 1;
 *       ASSERT_EQ(x, 2);
 *   }
 *
 *   TEST_MAIN()
 *
 * Runner exits:
 *   0  — all tests passed
 *   1  — any correctness / contract test failed
 *   2  — any SECURITY_PROP test failed  (distinct for CI)
 */

#ifndef TOKENLINT_TEST_RUNNER_H
#define TOKENLINT_TEST_RUNNER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── internal state ─────────────────────────────────────────────────────── */

static int   tl_test_passed       = 0;
static int   tl_test_failed       = 0;
static int   tl_secprop_failed    = 0;
static int   tl_current_is_secprop = 0;
static const char *tl_current_test = NULL;

/* ── colours (suppressed when stdout is not a tty) ──────────────────────── */
#ifdef _WIN32
#  define TL_RED   ""
#  define TL_GREEN ""
#  define TL_RESET ""
#else
#  define TL_RED   "\033[31m"
#  define TL_GREEN "\033[32m"
#  define TL_RESET "\033[0m"
#endif

/* ── assertion primitives ───────────────────────────────────────────────── */

#define TL_FAIL(fmt, ...)                                                    \
    do {                                                                     \
        fprintf(stderr,                                                      \
                TL_RED "  FAIL" TL_RESET " %s  (%s:%d)  " fmt "\n",         \
                tl_current_test, __FILE__, __LINE__, ##__VA_ARGS__);         \
        if (tl_current_is_secprop) tl_secprop_failed++;                     \
        else                       tl_test_failed++;                         \
        return;                                                              \
    } while (0)

#define ASSERT_TRUE(expr)                                                    \
    do {                                                                     \
        if (!(expr)) TL_FAIL("ASSERT_TRUE(%s)", #expr);                     \
    } while (0)

#define ASSERT_FALSE(expr)                                                   \
    do {                                                                     \
        if ((expr)) TL_FAIL("ASSERT_FALSE(%s)", #expr);                     \
    } while (0)

#define ASSERT_NULL(ptr)                                                     \
    do {                                                                     \
        if ((ptr) != NULL) TL_FAIL("ASSERT_NULL(%s)", #ptr);                \
    } while (0)

#define ASSERT_NOT_NULL(ptr)                                                 \
    do {                                                                     \
        if ((ptr) == NULL) TL_FAIL("ASSERT_NOT_NULL(%s)", #ptr);            \
    } while (0)

#define ASSERT_EQ(a, b)                                                      \
    do {                                                                     \
        if ((a) != (b))                                                      \
            TL_FAIL("ASSERT_EQ(%s, %s): %lld != %lld",                      \
                    #a, #b, (long long)(a), (long long)(b));                 \
    } while (0)

#define ASSERT_NE(a, b)                                                      \
    do {                                                                     \
        if ((a) == (b))                                                      \
            TL_FAIL("ASSERT_NE(%s, %s): both %lld",                         \
                    #a, #b, (long long)(a));                                 \
    } while (0)

#define ASSERT_GT(a, b)                                                      \
    do {                                                                     \
        if (!((a) > (b)))                                                    \
            TL_FAIL("ASSERT_GT(%s > %s): %lld <= %lld",                     \
                    #a, #b, (long long)(a), (long long)(b));                 \
    } while (0)

#define ASSERT_GE(a, b)                                                      \
    do {                                                                     \
        if (!((a) >= (b)))                                                   \
            TL_FAIL("ASSERT_GE(%s >= %s): %lld < %lld",                     \
                    #a, #b, (long long)(a), (long long)(b));                 \
    } while (0)

#define ASSERT_STR_EQ(a, b)                                                  \
    do {                                                                     \
        if (strcmp((a), (b)) != 0)                                           \
            TL_FAIL("ASSERT_STR_EQ: \"%s\" != \"%s\"", (a), (b));           \
    } while (0)

/*
 * Memory alignment assertion.
 * Checks that ptr is aligned to `align` bytes.
 */
#define ASSERT_ALIGNED(ptr, align)                                           \
    do {                                                                     \
        uintptr_t _addr = (uintptr_t)(ptr);                                  \
        uintptr_t _aln  = (uintptr_t)(align);                                \
        if (_addr % _aln != 0)                                               \
            TL_FAIL("ASSERT_ALIGNED(%s, %zu): addr %p mod %zu = %zu",       \
                    #ptr, (size_t)_aln,                                      \
                    (void *)(ptr), (size_t)_aln,                             \
                    (size_t)(_addr % _aln));                                 \
    } while (0)

/*
 * Memory is all-zero assertion.
 * Used to verify zero-init on alloc / scrub on reset.
 */
#define ASSERT_ZEROED(ptr, len)                                              \
    do {                                                                     \
        const unsigned char *_p = (const unsigned char *)(ptr);              \
        size_t _n = (size_t)(len);                                           \
        for (size_t _i = 0; _i < _n; _i++) {                                \
            if (_p[_i] != 0)                                                 \
                TL_FAIL("ASSERT_ZEROED(%s, %zu): byte[%zu] = 0x%02x",       \
                        #ptr, _n, _i, _p[_i]);                              \
        }                                                                    \
    } while (0)

/* ── test registration ──────────────────────────────────────────────────── */

/*
 * TEST(name) — correctness / contract test.
 * Exit code 1 on failure.
 */
#define TEST(name)                                                           \
    static void tl_test_body_##name(void);                                   \
    static void tl_run_##name(void) {                                        \
        tl_current_test      = #name;                                        \
        tl_current_is_secprop = 0;                                           \
        fprintf(stdout, "  RUN  %s\n", tl_current_test);                    \
        int _fail_before = tl_test_failed + tl_secprop_failed;              \
        tl_test_body_##name();                                               \
        if ((tl_test_failed + tl_secprop_failed) == _fail_before) {         \
            fprintf(stdout, TL_GREEN "  PASS" TL_RESET " %s\n",             \
                    tl_current_test);                                        \
            tl_test_passed++;                                                \
        }                                                                    \
    }                                                                        \
    static void tl_test_body_##name(void)

/*
 * SECURITY_PROP(name) — security property test.
 * Exit code 2 on failure (distinct from correctness failures).
 */
#define SECURITY_PROP(name)                                                  \
    static void tl_test_body_##name(void);                                   \
    static void tl_run_##name(void) {                                        \
        tl_current_test      = "SECURITY_PROP(" #name ")";                  \
        tl_current_is_secprop = 1;                                           \
        fprintf(stdout, "  RUN  %s\n", tl_current_test);                    \
        int _fail_before = tl_secprop_failed;                                \
        tl_test_body_##name();                                               \
        if (tl_secprop_failed == _fail_before) {                             \
            fprintf(stdout, TL_GREEN "  PASS" TL_RESET " %s\n",             \
                    tl_current_test);                                        \
            tl_test_passed++;                                                \
        }                                                                    \
    }                                                                        \
    static void tl_test_body_##name(void)

/* ── test main ──────────────────────────────────────────────────────────── */

/*
 * TEST_MAIN() — call after all TEST() / SECURITY_PROP() declarations.
 * Pass test runner functions as arguments.
 *
 * Example:
 *   TEST_MAIN(
 *       tl_run_basic_alloc,
 *       tl_run_alignment,
 *   )
 */
#define TEST_MAIN(...)                                                        \
    int main(void) {                                                          \
        typedef void (*test_fn_t)(void);                                      \
        test_fn_t tests[] = { __VA_ARGS__ };                                  \
        size_t count = sizeof(tests) / sizeof(tests[0]);                      \
        fprintf(stdout, "\n=== tokenlint unit tests ===\n\n");                \
        for (size_t i = 0; i < count; i++) tests[i]();                       \
        fprintf(stdout, "\n--- results ---\n");                               \
        fprintf(stdout, "  passed: %d\n", tl_test_passed);                   \
        fprintf(stdout, "  failed: %d\n", tl_test_failed);                   \
        if (tl_secprop_failed > 0)                                            \
            fprintf(stdout, TL_RED "  security property failures: %d\n"       \
                    TL_RESET, tl_secprop_failed);                              \
        if (tl_secprop_failed > 0) return 2;                                  \
        if (tl_test_failed    > 0) return 1;                                  \
        return 0;                                                              \
    }

#endif /* TOKENLINT_TEST_RUNNER_H */
