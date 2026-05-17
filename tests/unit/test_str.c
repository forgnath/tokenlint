/*
 * tests/unit/test_str.c
 *
 * Unit tests for src/util/str.c
 *
 * Coverage:
 *   str_slice            — 5 tests
 *   str_has_suffix       — 4 tests
 *   str_find_byte        — 4 tests
 *   str_find_byte_from   — 3 tests
 *   str_contains         — 2 tests
 *   str_split_first      — 5 tests
 *   str_split_last       — 4 tests
 *   str_trim_left        — 3 tests
 *   str_trim_right       — 3 tests
 *   str_trim             — 3 tests
 *   str_to_u64           — 7 tests
 *   str_to_i64           — 8 tests
 *   SECURITY_PROP tests  — 4 tests
 *
 * Total: 55 tests
 *
 * Build:
 *   cc -std=c11 -Wall -Wextra -Wpedantic -Werror \
 *      -I include \
 *      src/util/arena.c src/util/str.c \
 *      tests/unit/test_str.c -o build/test_str
 */

#include "helpers/test_runner.h"
#include "tokenlint.h"

/* Forward-declare functions implemented in str.c (no str.h yet) */
str_t    str_slice(str_t s, size_t start, size_t length);
int      str_has_suffix(str_t s, str_t suffix);
size_t   str_find_byte(str_t s, char c);
size_t   str_find_byte_from(str_t s, char c, size_t offset);
int      str_contains(str_t s, char c);
int      str_split_first(str_t s, char delim, str_t *head, str_t *tail);
int      str_split_last(str_t s, char delim, str_t *head, str_t *tail);
str_t    str_trim_left(str_t s);
str_t    str_trim_right(str_t s);
str_t    str_trim(str_t s);
int      str_to_u64(str_t s, uint64_t *out);
int      str_to_i64(str_t s, int64_t *out);


/* =========================================================================
 * str_slice
 * ========================================================================= */

TEST(slice_basic) {
    str_t s = STR_LIT("hello");
    str_t r = str_slice(s, 1, 3);
    ASSERT_EQ(r.len, 3u);
    ASSERT_TRUE(memcmp(r.data, "ell", 3) == 0);
}

TEST(slice_from_zero) {
    str_t s = STR_LIT("abcde");
    str_t r = str_slice(s, 0, 3);
    ASSERT_EQ(r.len, 3u);
    ASSERT_TRUE(memcmp(r.data, "abc", 3) == 0);
}

TEST(slice_clamps_to_end) {
    str_t s = STR_LIT("hello");
    str_t r = str_slice(s, 3, 100);
    ASSERT_EQ(r.len, 2u);
    ASSERT_TRUE(memcmp(r.data, "lo", 2) == 0);
}

TEST(slice_start_at_end_returns_null) {
    str_t s = STR_LIT("hello");
    str_t r = str_slice(s, 5, 1);
    ASSERT_TRUE(STR_IS_NULL(r));
}

TEST(slice_start_beyond_len_returns_null) {
    str_t s = STR_LIT("hi");
    str_t r = str_slice(s, 99, 1);
    ASSERT_TRUE(STR_IS_NULL(r));
}


/* =========================================================================
 * str_has_suffix
 * ========================================================================= */

TEST(suffix_matches) {
    str_t s      = STR_LIT("payments-api.yaml");
    str_t suffix = STR_LIT(".yaml");
    ASSERT_TRUE(str_has_suffix(s, suffix));
}

TEST(suffix_no_match) {
    str_t s      = STR_LIT("payments-api.json");
    str_t suffix = STR_LIT(".yaml");
    ASSERT_FALSE(str_has_suffix(s, suffix));
}

TEST(suffix_empty_always_matches) {
    str_t s      = STR_LIT("anything");
    str_t suffix = STR_LIT("");
    ASSERT_TRUE(str_has_suffix(s, suffix));
}

TEST(suffix_longer_than_s_no_match) {
    str_t s      = STR_LIT("ab");
    str_t suffix = STR_LIT("xyzab");
    ASSERT_FALSE(str_has_suffix(s, suffix));
}


/* =========================================================================
 * str_find_byte
 * ========================================================================= */

TEST(find_byte_found) {
    str_t s = STR_LIT("iss.example.com");
    ASSERT_EQ(str_find_byte(s, '.'), 3u);
}

TEST(find_byte_not_found) {
    str_t s = STR_LIT("no-dots-here");
    /* hyphen is not a dot */
    ASSERT_EQ(str_find_byte(s, '.'), (size_t)-1);
}

TEST(find_byte_first_char) {
    str_t s = STR_LIT(".leading");
    ASSERT_EQ(str_find_byte(s, '.'), 0u);
}

TEST(find_byte_last_char) {
    str_t s = STR_LIT("trailing.");
    ASSERT_EQ(str_find_byte(s, '.'), 8u);
}


/* =========================================================================
 * str_find_byte_from
 * ========================================================================= */

TEST(find_byte_from_skips_offset) {
    str_t s = STR_LIT("a.b.c");
    /* skip past first dot at index 1 */
    ASSERT_EQ(str_find_byte_from(s, '.', 2), 3u);
}

TEST(find_byte_from_not_found_after_offset) {
    str_t s = STR_LIT("a.b");
    /* start past the only dot */
    ASSERT_EQ(str_find_byte_from(s, '.', 2), (size_t)-1);
}

TEST(find_byte_from_offset_zero_same_as_find) {
    str_t s = STR_LIT("x.y");
    ASSERT_EQ(str_find_byte_from(s, '.', 0), str_find_byte(s, '.'));
}


/* =========================================================================
 * str_contains
 * ========================================================================= */

TEST(contains_true) {
    str_t s = STR_LIT("Bearer token");
    ASSERT_TRUE(str_contains(s, ' '));
}

TEST(contains_false) {
    str_t s = STR_LIT("nowhitespace");
    ASSERT_FALSE(str_contains(s, ' '));
}


/* =========================================================================
 * str_split_first
 * ========================================================================= */

TEST(split_first_basic) {
    str_t s = STR_LIT("header.payload.sig");
    str_t head, tail;
    int found = str_split_first(s, '.', &head, &tail);
    ASSERT_TRUE(found);
    ASSERT_EQ(head.len, 6u);
    ASSERT_TRUE(memcmp(head.data, "header", 6) == 0);
    ASSERT_EQ(tail.len, 11u);
    ASSERT_TRUE(memcmp(tail.data, "payload.sig", 11) == 0);
}

TEST(split_first_not_found) {
    str_t s = STR_LIT("nodot");
    str_t head, tail;
    int found = str_split_first(s, '.', &head, &tail);
    ASSERT_FALSE(found);
    ASSERT_TRUE(str_eq(head, s));
    ASSERT_TRUE(STR_IS_NULL(tail));
}

TEST(split_first_delim_at_start) {
    str_t s = STR_LIT(".rest");
    str_t head, tail;
    int found = str_split_first(s, '.', &head, &tail);
    ASSERT_TRUE(found);
    ASSERT_EQ(head.len, 0u);
    ASSERT_EQ(tail.len, 4u);
}

TEST(split_first_delim_at_end) {
    str_t s = STR_LIT("before.");
    str_t head, tail;
    int found = str_split_first(s, '.', &head, &tail);
    ASSERT_TRUE(found);
    ASSERT_EQ(head.len, 6u);
    ASSERT_EQ(tail.len, 0u);
}

TEST(split_first_single_char) {
    str_t s = STR_LIT(".");
    str_t head, tail;
    int found = str_split_first(s, '.', &head, &tail);
    ASSERT_TRUE(found);
    ASSERT_EQ(head.len, 0u);
    ASSERT_EQ(tail.len, 0u);
}


/* =========================================================================
 * str_split_last
 * ========================================================================= */

TEST(split_last_basic) {
    str_t s = STR_LIT("header.payload.sig");
    str_t head, tail;
    int found = str_split_last(s, '.', &head, &tail);
    ASSERT_TRUE(found);
    ASSERT_EQ(head.len, 14u);
    ASSERT_TRUE(memcmp(head.data, "header.payload", 14) == 0);
    ASSERT_EQ(tail.len, 3u);
    ASSERT_TRUE(memcmp(tail.data, "sig", 3) == 0);
}

TEST(split_last_not_found) {
    str_t s = STR_LIT("nodot");
    str_t head, tail;
    int found = str_split_last(s, '.', &head, &tail);
    ASSERT_FALSE(found);
    ASSERT_TRUE(str_eq(head, s));
    ASSERT_TRUE(STR_IS_NULL(tail));
}

TEST(split_last_single_delim_agrees_with_first) {
    str_t s = STR_LIT("a.b");
    str_t hf, tf, hl, tl;
    str_split_first(s, '.', &hf, &tf);
    str_split_last(s, '.', &hl, &tl);
    ASSERT_TRUE(str_eq(hf, hl));
    ASSERT_TRUE(str_eq(tf, tl));
}

TEST(split_last_delim_at_start) {
    str_t s = STR_LIT(".only");
    str_t head, tail;
    int found = str_split_last(s, '.', &head, &tail);
    ASSERT_TRUE(found);
    ASSERT_EQ(head.len, 0u);
    ASSERT_EQ(tail.len, 4u);
}


/* =========================================================================
 * str_trim_left
 * ========================================================================= */

TEST(trim_left_spaces) {
    str_t s = STR_LIT("   hello");
    str_t r = str_trim_left(s);
    ASSERT_EQ(r.len, 5u);
    ASSERT_TRUE(memcmp(r.data, "hello", 5) == 0);
}

TEST(trim_left_no_whitespace) {
    str_t s = STR_LIT("hello");
    str_t r = str_trim_left(s);
    ASSERT_EQ(r.len, 5u);
}

TEST(trim_left_all_whitespace) {
    str_t s = STR_LIT("   \t\n");
    str_t r = str_trim_left(s);
    ASSERT_EQ(r.len, 0u);
}


/* =========================================================================
 * str_trim_right
 * ========================================================================= */

TEST(trim_right_spaces) {
    str_t s = STR_LIT("hello   ");
    str_t r = str_trim_right(s);
    ASSERT_EQ(r.len, 5u);
    ASSERT_TRUE(memcmp(r.data, "hello", 5) == 0);
}

TEST(trim_right_no_whitespace) {
    str_t s = STR_LIT("hello");
    str_t r = str_trim_right(s);
    ASSERT_EQ(r.len, 5u);
}

TEST(trim_right_all_whitespace) {
    str_t s = STR_LIT("\t\t  ");
    str_t r = str_trim_right(s);
    ASSERT_EQ(r.len, 0u);
}


/* =========================================================================
 * str_trim (both sides)
 * ========================================================================= */

TEST(trim_both_sides) {
    str_t s = STR_LIT("  hello world  ");
    str_t r = str_trim(s);
    ASSERT_EQ(r.len, 11u);
    ASSERT_TRUE(memcmp(r.data, "hello world", 11) == 0);
}

TEST(trim_internal_whitespace_untouched) {
    str_t s = STR_LIT("  a  b  ");
    str_t r = str_trim(s);
    ASSERT_EQ(r.len, 4u);
    ASSERT_TRUE(memcmp(r.data, "a  b", 4) == 0);
}

TEST(trim_already_clean) {
    str_t s = STR_LIT("clean");
    str_t r = str_trim(s);
    ASSERT_EQ(r.len, 5u);
    ASSERT_TRUE(memcmp(r.data, "clean", 5) == 0);
}


/* =========================================================================
 * str_to_u64
 * ========================================================================= */

TEST(u64_basic) {
    uint64_t v = 0;
    ASSERT_TRUE(str_to_u64(STR_LIT("42"), &v));
    ASSERT_EQ(v, 42u);
}

TEST(u64_zero) {
    uint64_t v = 1;
    ASSERT_TRUE(str_to_u64(STR_LIT("0"), &v));
    ASSERT_EQ(v, 0u);
}

TEST(u64_max) {
    uint64_t v = 0;
    /* UINT64_MAX = 18446744073709551615 */
    ASSERT_TRUE(str_to_u64(STR_LIT("18446744073709551615"), &v));
    ASSERT_EQ(v, UINT64_MAX);
}

TEST(u64_overflow_rejected) {
    uint64_t v = 99;
    /* one more than UINT64_MAX */
    ASSERT_FALSE(str_to_u64(STR_LIT("18446744073709551616"), &v));
    ASSERT_EQ(v, 99u); /* out not modified */
}

TEST(u64_non_digit_rejected) {
    uint64_t v = 0;
    ASSERT_FALSE(str_to_u64(STR_LIT("12x4"), &v));
}

TEST(u64_empty_rejected) {
    uint64_t v = 0;
    ASSERT_FALSE(str_to_u64(STR_LIT(""), &v));
}

TEST(u64_leading_whitespace_rejected) {
    uint64_t v = 0;
    ASSERT_FALSE(str_to_u64(STR_LIT(" 42"), &v));
}


/* =========================================================================
 * str_to_i64
 * ========================================================================= */

TEST(i64_positive) {
    int64_t v = 0;
    ASSERT_TRUE(str_to_i64(STR_LIT("1234567890"), &v));
    ASSERT_EQ(v, 1234567890LL);
}

TEST(i64_negative) {
    int64_t v = 0;
    ASSERT_TRUE(str_to_i64(STR_LIT("-42"), &v));
    ASSERT_EQ(v, -42LL);
}

TEST(i64_zero) {
    int64_t v = 1;
    ASSERT_TRUE(str_to_i64(STR_LIT("0"), &v));
    ASSERT_EQ(v, 0LL);
}

TEST(i64_min) {
    int64_t v = 0;
    /* INT64_MIN = -9223372036854775808 */
    ASSERT_TRUE(str_to_i64(STR_LIT("-9223372036854775808"), &v));
    ASSERT_EQ(v, INT64_MIN);
}

TEST(i64_max) {
    int64_t v = 0;
    ASSERT_TRUE(str_to_i64(STR_LIT("9223372036854775807"), &v));
    ASSERT_EQ(v, INT64_MAX);
}

TEST(i64_overflow_positive) {
    int64_t v = 99;
    ASSERT_FALSE(str_to_i64(STR_LIT("9223372036854775808"), &v));
    ASSERT_EQ(v, 99LL);
}

TEST(i64_overflow_negative) {
    int64_t v = 99;
    ASSERT_FALSE(str_to_i64(STR_LIT("-9223372036854775809"), &v));
    ASSERT_EQ(v, 99LL);
}

TEST(i64_bare_minus_rejected) {
    int64_t v = 0;
    ASSERT_FALSE(str_to_i64(STR_LIT("-"), &v));
}


/* =========================================================================
 * Security properties
 *
 * These use SECURITY_PROP() so CI exits 2 (not 1) on failure.
 * They verify invariants the evaluator depends on for safety.
 * ========================================================================= */

/*
 * str_t from a literal must never report a len that would allow
 * reading past the literal's actual bytes.
 */
SECURITY_PROP(str_lit_len_matches_literal) {
    str_t s = STR_LIT("RS256");
    ASSERT_EQ(s.len, 5u);
    str_t s2 = STR_LIT("");
    ASSERT_EQ(s2.len, 0u);
}

/*
 * str_slice must never return a pointer or length that reaches beyond
 * the original string's bounds.
 */
SECURITY_PROP(slice_never_exceeds_source_bounds) {
    str_t s = STR_LIT("abcde");
    str_t r = str_slice(s, 0, 999);
    /* r must end at or before s ends */
    ASSERT_TRUE(r.len <= s.len);
    if (r.data != NULL) {
        ASSERT_TRUE(r.data >= s.data);
        ASSERT_TRUE(r.data + r.len <= s.data + s.len);
    }
}

/*
 * Integer parsers must not modify *out on failure.
 * Callers rely on this: they initialise *out to a safe sentinel before
 * calling, and must not see it corrupted on parse error.
 */
SECURITY_PROP(parse_failure_leaves_out_unmodified) {
    uint64_t u = 0xDEADBEEFu;
    str_to_u64(STR_LIT("bad"), &u);
    ASSERT_EQ(u, 0xDEADBEEFu);

    int64_t i = -1LL;
    str_to_i64(STR_LIT("--0"), &i);
    ASSERT_EQ(i, -1LL);
}

/*
 * str_split_first must not produce head or tail pointers that reach
 * outside the source string.
 */
SECURITY_PROP(split_pointers_within_source) {
    str_t s = STR_LIT("eyJ.payload.sig");
    str_t head, tail;
    str_split_first(s, '.', &head, &tail);
    /* head starts at s.data */
    ASSERT_TRUE(head.data == s.data);
    ASSERT_TRUE(head.len <= s.len);
    /* tail starts inside s and ends at s's end */
    ASSERT_TRUE(tail.data >= s.data);
    ASSERT_TRUE(tail.data + tail.len <= s.data + s.len);
}


/* =========================================================================
 * TEST_MAIN
 * ========================================================================= */

TEST_MAIN(
    /* str_slice */
    tl_run_slice_basic,
    tl_run_slice_from_zero,
    tl_run_slice_clamps_to_end,
    tl_run_slice_start_at_end_returns_null,
    tl_run_slice_start_beyond_len_returns_null,

    /* str_has_suffix */
    tl_run_suffix_matches,
    tl_run_suffix_no_match,
    tl_run_suffix_empty_always_matches,
    tl_run_suffix_longer_than_s_no_match,

    /* str_find_byte */
    tl_run_find_byte_found,
    tl_run_find_byte_not_found,
    tl_run_find_byte_first_char,
    tl_run_find_byte_last_char,

    /* str_find_byte_from */
    tl_run_find_byte_from_skips_offset,
    tl_run_find_byte_from_not_found_after_offset,
    tl_run_find_byte_from_offset_zero_same_as_find,

    /* str_contains */
    tl_run_contains_true,
    tl_run_contains_false,

    /* str_split_first */
    tl_run_split_first_basic,
    tl_run_split_first_not_found,
    tl_run_split_first_delim_at_start,
    tl_run_split_first_delim_at_end,
    tl_run_split_first_single_char,

    /* str_split_last */
    tl_run_split_last_basic,
    tl_run_split_last_not_found,
    tl_run_split_last_single_delim_agrees_with_first,
    tl_run_split_last_delim_at_start,

    /* str_trim_left */
    tl_run_trim_left_spaces,
    tl_run_trim_left_no_whitespace,
    tl_run_trim_left_all_whitespace,

    /* str_trim_right */
    tl_run_trim_right_spaces,
    tl_run_trim_right_no_whitespace,
    tl_run_trim_right_all_whitespace,

    /* str_trim */
    tl_run_trim_both_sides,
    tl_run_trim_internal_whitespace_untouched,
    tl_run_trim_already_clean,

    /* str_to_u64 */
    tl_run_u64_basic,
    tl_run_u64_zero,
    tl_run_u64_max,
    tl_run_u64_overflow_rejected,
    tl_run_u64_non_digit_rejected,
    tl_run_u64_empty_rejected,
    tl_run_u64_leading_whitespace_rejected,

    /* str_to_i64 */
    tl_run_i64_positive,
    tl_run_i64_negative,
    tl_run_i64_zero,
    tl_run_i64_min,
    tl_run_i64_max,
    tl_run_i64_overflow_positive,
    tl_run_i64_overflow_negative,
    tl_run_i64_bare_minus_rejected,

    /* security properties */
    tl_run_str_lit_len_matches_literal,
    tl_run_slice_never_exceeds_source_bounds,
    tl_run_parse_failure_leaves_out_unmodified,
    tl_run_split_pointers_within_source,
)
