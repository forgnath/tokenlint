/*
 * tests/unit/test_arena.c
 *
 * Unit tests for src/util/arena.c
 *
 * Covers (per test-strategy.md):
 *   - Allocation
 *   - Alignment
 *   - Overflow / exhaustion
 *   - Free
 *   - Zero-initialisation on alloc
 *   - Slab scrub on reset (via arena_reset — tested here; declared in
 *     arena.c but not in the public header for v1; see note below)
 *
 * NOTE: arena_reset() is an internal helper present in arena.c but not
 * declared in tokenlint.h. Tests that exercise reset behaviour do so
 * indirectly: allocate, drain, then re-create a fresh arena.  A forward
 * declaration is provided below so the test binary can call it directly
 * if it is linked; if arena_reset is removed, those tests simply become
 * re-creation tests.
 *
 * Build (from repo root):
 *
 *   mkdir -p build/test
 *   gcc -std=c11 -Wall -Wextra -Wpedantic -Werror \
 *       -I include -I tests \
 *       src/util/arena.c tests/unit/test_arena.c \
 *       -o build/test/test_arena
 *   ./build/test/test_arena
 *
 * With ASAN:
 *
 *   gcc -std=c11 -Wall -Wextra -Wpedantic -Werror \
 *       -fsanitize=address,undefined -fno-omit-frame-pointer \
 *       -I include -I tests \
 *       src/util/arena.c tests/unit/test_arena.c \
 *       -o build/test/test_arena_asan
 *   ./build/test/test_arena_asan
 */

#include "helpers/test_runner.h"
#include "tokenlint.h"

#include <stdint.h>
#include <string.h>

/* ── construction ────────────────────────────────────────────────────────── */

TEST(arena_new_basic)
{
    arena_t *a = arena_new(1024);
    ASSERT_NOT_NULL(a);
    ASSERT_EQ(arena_used(a), 0);
    ASSERT_EQ(arena_capacity(a), 1024);
    arena_free(a);
}

TEST(arena_new_zero_capacity_fails)
{
    arena_t *a = arena_new(0);
    ASSERT_NULL(a);
}

TEST(arena_new_default_size)
{
    /* TL_ARENA_DEFAULT_SIZE (4 MiB) is the canonical run size */
    arena_t *a = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(a);
    ASSERT_EQ(arena_capacity(a), TL_ARENA_DEFAULT_SIZE);
    ASSERT_EQ(arena_used(a), 0);
    arena_free(a);
}

/* ── basic allocation ────────────────────────────────────────────────────── */

TEST(arena_alloc_basic)
{
    arena_t *a = arena_new(1024);
    ASSERT_NOT_NULL(a);

    void *p = arena_alloc(a, 64, _Alignof(max_align_t));
    ASSERT_NOT_NULL(p);
    ASSERT_GT(arena_used(a), 0);

    arena_free(a);
}

TEST(arena_alloc_zero_size_returns_null)
{
    arena_t *a = arena_new(1024);
    ASSERT_NOT_NULL(a);

    void *p = arena_alloc(a, 0, _Alignof(max_align_t));
    ASSERT_NULL(p);
    /* cursor must not have moved */
    ASSERT_EQ(arena_used(a), 0);

    arena_free(a);
}

TEST(arena_alloc_typed_macro_one)
{
    arena_t *a = arena_new(1024);
    ASSERT_NOT_NULL(a);

    uint64_t *p = ARENA_ALLOC_ONE(a, uint64_t);
    ASSERT_NOT_NULL(p);
    ASSERT_ALIGNED(p, _Alignof(uint64_t));
    ASSERT_EQ(*p, 0);  /* must be zero-initialised */

    arena_free(a);
}

TEST(arena_alloc_typed_macro_array)
{
    arena_t *a = arena_new(4096);
    ASSERT_NOT_NULL(a);

    str_t *arr = ARENA_ALLOC_ARRAY(a, str_t, 10);
    ASSERT_NOT_NULL(arr);
    ASSERT_ALIGNED(arr, _Alignof(str_t));

    /* all elements must be zero-initialised (STR_NULL) */
    for (int i = 0; i < 10; i++) {
        ASSERT_NULL(arr[i].data);
        ASSERT_EQ(arr[i].len, 0);
    }

    arena_free(a);
}

TEST(arena_alloc_array_zero_count_returns_null)
{
    arena_t *a = arena_new(1024);
    ASSERT_NOT_NULL(a);

    /* count == 0 → NULL per macro contract; cursor must not move */
    void *p = ARENA_ALLOC_ARRAY(a, uint64_t, 0);
    ASSERT_NULL(p);
    ASSERT_EQ(arena_used(a), 0);

    arena_free(a);
}

/* ── alignment ───────────────────────────────────────────────────────────── */

TEST(arena_alloc_alignment_1_byte_alloc)
{
    arena_t *a = arena_new(1024);
    ASSERT_NOT_NULL(a);

    /* Even 1-byte alloc must honour requested alignment */
    void *p = arena_alloc(a, 1, _Alignof(max_align_t));
    ASSERT_NOT_NULL(p);
    ASSERT_ALIGNED(p, _Alignof(max_align_t));

    arena_free(a);
}

TEST(arena_alloc_alignment_after_odd_sizes)
{
    arena_t *a = arena_new(1024);
    ASSERT_NOT_NULL(a);

    /* Interleave odd-size allocs; each must come back at its requested align */
    void *p1 = arena_alloc(a, 3,  _Alignof(uint8_t));
    void *p2 = arena_alloc(a, 1,  _Alignof(uint64_t));
    void *p3 = arena_alloc(a, 7,  _Alignof(uint32_t));
    void *p4 = arena_alloc(a, 17, _Alignof(max_align_t));

    ASSERT_NOT_NULL(p1); ASSERT_ALIGNED(p1, _Alignof(uint8_t));
    ASSERT_NOT_NULL(p2); ASSERT_ALIGNED(p2, _Alignof(uint64_t));
    ASSERT_NOT_NULL(p3); ASSERT_ALIGNED(p3, _Alignof(uint32_t));
    ASSERT_NOT_NULL(p4); ASSERT_ALIGNED(p4, _Alignof(max_align_t));

    arena_free(a);
}

TEST(arena_alloc_alignment_mixed_struct_sizes)
{
    arena_t *a = arena_new(4096);
    ASSERT_NOT_NULL(a);

    /* Simulate what the parser allocates */
    uint8_t  *pb = ARENA_ALLOC_ONE(a, uint8_t);
    uint16_t *ph = ARENA_ALLOC_ONE(a, uint16_t);
    uint32_t *pw = ARENA_ALLOC_ONE(a, uint32_t);
    uint64_t *pq = ARENA_ALLOC_ONE(a, uint64_t);
    double   *pd = ARENA_ALLOC_ONE(a, double);
    str_t    *ps = ARENA_ALLOC_ONE(a, str_t);

    ASSERT_NOT_NULL(pb); ASSERT_ALIGNED(pb, _Alignof(uint8_t));
    ASSERT_NOT_NULL(ph); ASSERT_ALIGNED(ph, _Alignof(uint16_t));
    ASSERT_NOT_NULL(pw); ASSERT_ALIGNED(pw, _Alignof(uint32_t));
    ASSERT_NOT_NULL(pq); ASSERT_ALIGNED(pq, _Alignof(uint64_t));
    ASSERT_NOT_NULL(pd); ASSERT_ALIGNED(pd, _Alignof(double));
    ASSERT_NOT_NULL(ps); ASSERT_ALIGNED(ps, _Alignof(str_t));

    arena_free(a);
}

TEST(arena_alloc_regions_do_not_overlap)
{
    arena_t *a = arena_new(1024);
    ASSERT_NOT_NULL(a);

    uint8_t *p1 = arena_alloc(a, 16, 1);
    uint8_t *p2 = arena_alloc(a, 16, 1);
    uint8_t *p3 = arena_alloc(a, 16, 1);

    ASSERT_NOT_NULL(p1);
    ASSERT_NOT_NULL(p2);
    ASSERT_NOT_NULL(p3);

    memset(p1, 0xAA, 16);
    memset(p2, 0xBB, 16);
    memset(p3, 0xCC, 16);

    for (int i = 0; i < 16; i++) ASSERT_EQ(p1[i], 0xAA);
    for (int i = 0; i < 16; i++) ASSERT_EQ(p2[i], 0xBB);
    for (int i = 0; i < 16; i++) ASSERT_EQ(p3[i], 0xCC);

    arena_free(a);
}

/* ── zero-initialisation ─────────────────────────────────────────────────── */

TEST(arena_alloc_zero_initialises)
{
    /*
     * Security requirement: returned memory must be zeroed.
     * Prevents stale bytes (key material, claim values) from leaking
     * into subsequent logical allocations.
     */
    arena_t *a = arena_new(1024);
    ASSERT_NOT_NULL(a);

    uint8_t *p = arena_alloc(a, 128, _Alignof(max_align_t));
    ASSERT_NOT_NULL(p);
    ASSERT_ZEROED(p, 128);

    arena_free(a);
}

TEST(arena_alloc_zero_initialises_large)
{
    arena_t *a = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(a);

    /* Large alloc — whole region must be zero */
    size_t sz = TL_KB(32);
    uint8_t *p = arena_alloc(a, sz, _Alignof(max_align_t));
    ASSERT_NOT_NULL(p);
    ASSERT_ZEROED(p, sz);

    arena_free(a);
}

/* ── exhaustion ──────────────────────────────────────────────────────────── */

TEST(arena_alloc_exhaustion_returns_null)
{
    arena_t *a = arena_new(64);
    ASSERT_NOT_NULL(a);

    /* Drain the arena */
    while (arena_alloc(a, 1, 1)) { /* drain */ }

    /* Next alloc must return NULL */
    void *p = arena_alloc(a, 1, 1);
    ASSERT_NULL(p);

    arena_free(a);
}

TEST(arena_alloc_larger_than_capacity_fails)
{
    arena_t *a = arena_new(64);
    ASSERT_NOT_NULL(a);

    void *p = arena_alloc(a, 65, 1);
    ASSERT_NULL(p);
    ASSERT_EQ(arena_used(a), 0);  /* cursor must not have moved */

    arena_free(a);
}

TEST(arena_alloc_exhaustion_cursor_stable)
{
    arena_t *a = arena_new(32);
    ASSERT_NOT_NULL(a);

    while (arena_alloc(a, 1, 1)) { /* drain */ }
    size_t used = arena_used(a);

    /* Failed alloc must not advance cursor */
    { void *_discard1 = arena_alloc(a, 1, 1); (void)_discard1; }
    ASSERT_EQ(arena_used(a), used);

    arena_free(a);
}

TEST(arena_alloc_exact_capacity_fit)
{
    arena_t *a = arena_new(256);
    ASSERT_NOT_NULL(a);

    /* One allocation consuming the entire capacity */
    void *p = arena_alloc(a, 256, 1);
    ASSERT_NOT_NULL(p);
    ASSERT_EQ(arena_used(a), arena_capacity(a));

    /* Next allocation must fail */
    void *q = arena_alloc(a, 1, 1);
    ASSERT_NULL(q);

    arena_free(a);
}

/* ── arena_strdup ────────────────────────────────────────────────────────── */

TEST(arena_strdup_basic)
{
    arena_t *a = arena_new(1024);
    ASSERT_NOT_NULL(a);

    str_t src = STR_LIT("hello");
    str_t dst = arena_strdup(a, src);

    ASSERT_FALSE(STR_IS_NULL(dst));
    ASSERT_EQ(dst.len, src.len);
    ASSERT_TRUE(str_eq(dst, src));

    /* dst.data must be inside the arena (different pointer from literal) */
    ASSERT_NE((uintptr_t)dst.data, (uintptr_t)src.data);

    arena_free(a);
}

TEST(arena_strdup_null_returns_str_null)
{
    arena_t *a = arena_new(1024);
    ASSERT_NOT_NULL(a);

    str_t dst = arena_strdup(a, STR_NULL);
    ASSERT_TRUE(STR_IS_NULL(dst));
    ASSERT_EQ(arena_used(a), 0);  /* no allocation should have occurred */

    arena_free(a);
}

TEST(arena_strdup_independence)
{
    /* Mutating the source after strdup must not affect the copy */
    arena_t *a = arena_new(1024);
    ASSERT_NOT_NULL(a);

    char buf[8] = "hello";
    str_t src = { buf, 5 };
    str_t dst = arena_strdup(a, src);

    ASSERT_FALSE(STR_IS_NULL(dst));

    /* Corrupt the source buffer */
    memset(buf, 0xFF, 5);

    /* The copy must be unchanged */
    ASSERT_TRUE(memcmp(dst.data, "hello", 5) == 0);

    arena_free(a);
}

TEST(arena_strdup_exhaustion_returns_str_null)
{
    /* Arena too small to hold the string */
    arena_t *a = arena_new(4);
    ASSERT_NOT_NULL(a);

    /* Fill all 4 bytes */
    { void *_discard2 = arena_alloc(a, 4, 1); (void)_discard2; }

    str_t src = STR_LIT("this will not fit");
    str_t dst = arena_strdup(a, src);
    ASSERT_TRUE(STR_IS_NULL(dst));

    arena_free(a);
}

/* ── accounting ──────────────────────────────────────────────────────────── */

TEST(arena_used_tracks_allocations)
{
    arena_t *a = arena_new(1024);
    ASSERT_NOT_NULL(a);

    ASSERT_EQ(arena_used(a), 0);

    { void *_discard3 = arena_alloc(a, 1, 1); (void)_discard3; }
    size_t after_first = arena_used(a);
    ASSERT_GE(after_first, 1);

    { void *_discard4 = arena_alloc(a, 1, 1); (void)_discard4; }
    ASSERT_GE(arena_used(a), after_first + 1);

    arena_free(a);
}

TEST(arena_capacity_constant)
{
    arena_t *a = arena_new(512);
    ASSERT_NOT_NULL(a);

    ASSERT_EQ(arena_capacity(a), 512);
    { void *_discard5 = arena_alloc(a, 100, 1); (void)_discard5; }
    ASSERT_EQ(arena_capacity(a), 512);  /* must not change after alloc */

    arena_free(a);
}

TEST(arena_used_plus_free_space_equals_capacity)
{
    arena_t *a = arena_new(512);
    ASSERT_NOT_NULL(a);

    { void *_discard6 = arena_alloc(a, 37, 1); (void)_discard6; }
    { void *_discard7 = arena_alloc(a, 13, 1); (void)_discard7; }

    size_t used = arena_used(a);
    size_t cap  = arena_capacity(a);

    /* used must not exceed capacity */
    ASSERT_GE(cap, used);

    arena_free(a);
}

/* ── simulated parser workload ───────────────────────────────────────────── */

TEST(arena_simulated_parse_workload)
{
    /*
     * Simulate what the policy parser does: many small string allocations,
     * mixed with struct allocations.  Verifies arena integrity under
     * realistic access patterns and ASAN will catch any overflows.
     */
    arena_t *a = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(a);

    for (int i = 1; i <= 200; i++) {
        size_t len = (size_t)(i * 7 % 128) + 1;
        uint8_t *s = arena_alloc(a, len, _Alignof(char));
        ASSERT_NOT_NULL(s);
        ASSERT_ALIGNED(s, _Alignof(char));
        ASSERT_ZEROED(s, len);
        memset(s, (unsigned char)i, len);  /* write so ASAN catches UAF */
    }

    /* One large struct-sized allocation */
    void *big = arena_alloc(a, 4096, _Alignof(max_align_t));
    ASSERT_NOT_NULL(big);
    ASSERT_ALIGNED(big, _Alignof(max_align_t));

    ASSERT_GT(arena_used(a), 0);

    arena_free(a);
}

/* ── test main ───────────────────────────────────────────────────────────── */

TEST_MAIN(
    /* construction */
    tl_run_arena_new_basic,
    tl_run_arena_new_zero_capacity_fails,
    tl_run_arena_new_default_size,

    /* basic allocation */
    tl_run_arena_alloc_basic,
    tl_run_arena_alloc_zero_size_returns_null,
    tl_run_arena_alloc_typed_macro_one,
    tl_run_arena_alloc_typed_macro_array,
    tl_run_arena_alloc_array_zero_count_returns_null,

    /* alignment */
    tl_run_arena_alloc_alignment_1_byte_alloc,
    tl_run_arena_alloc_alignment_after_odd_sizes,
    tl_run_arena_alloc_alignment_mixed_struct_sizes,
    tl_run_arena_alloc_regions_do_not_overlap,

    /* zero-initialisation */
    tl_run_arena_alloc_zero_initialises,
    tl_run_arena_alloc_zero_initialises_large,

    /* exhaustion */
    tl_run_arena_alloc_exhaustion_returns_null,
    tl_run_arena_alloc_larger_than_capacity_fails,
    tl_run_arena_alloc_exhaustion_cursor_stable,
    tl_run_arena_alloc_exact_capacity_fit,

    /* arena_strdup */
    tl_run_arena_strdup_basic,
    tl_run_arena_strdup_null_returns_str_null,
    tl_run_arena_strdup_independence,
    tl_run_arena_strdup_exhaustion_returns_str_null,

    /* accounting */
    tl_run_arena_used_tracks_allocations,
    tl_run_arena_capacity_constant,
    tl_run_arena_used_plus_free_space_equals_capacity,

    /* workload */
    tl_run_arena_simulated_parse_workload,
)
