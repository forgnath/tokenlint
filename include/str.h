/*
 * include/str.h
 *
 * Public declarations for src/util/str.c.
 *
 * Declares the 12 str_t utility functions that supplement the static-inline
 * helpers already defined in tokenlint.h (str_eq, str_has_prefix, str_blank,
 * str_from_cstr).  Do NOT declare those here — they live in tokenlint.h.
 *
 * arena_strdup() is declared in tokenlint.h and implemented in arena.c;
 * it is NOT repeated here.
 *
 * Dependency: tokenlint.h (for str_t, TL_PURE, TL_NONNULL)
 * Include order: #include "tokenlint.h" before this header.
 *
 * C11 required.
 */

#ifndef TOKENLINT_STR_H
#define TOKENLINT_STR_H

#include "tokenlint.h"

#include <stddef.h>    /* size_t    */
#include <stdint.h>    /* uint64_t, int64_t */

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * Slicing and suffix
 * ========================================================================= */

/*
 * str_slice — return the sub-string s[start .. start+length).
 *
 * If start >= s.len, returns STR_NULL.
 * If start+length > s.len, clamps to the end of s.
 * No allocation — returned str_t shares s.data.
 */
TL_PURE
str_t str_slice(str_t s, size_t start, size_t length);

/*
 * str_has_suffix — returns 1 if s ends with suffix, 0 otherwise.
 * Empty suffix always matches.  Null s never matches a non-empty suffix.
 */
TL_PURE
int str_has_suffix(str_t s, str_t suffix);


/* =========================================================================
 * Search
 * ========================================================================= */

/*
 * str_find_byte — return the index of the first occurrence of byte c in s,
 * or (size_t)-1 if not found.
 */
TL_PURE
size_t str_find_byte(str_t s, char c);

/*
 * str_find_byte_from — like str_find_byte but starts searching at offset.
 * Returns (size_t)-1 if not found at or after offset.
 */
TL_PURE
size_t str_find_byte_from(str_t s, char c, size_t offset);

/*
 * str_contains — returns 1 if s contains byte c, 0 otherwise.
 */
TL_PURE
int str_contains(str_t s, char c);


/* =========================================================================
 * Splitting
 * ========================================================================= */

/*
 * str_split_first — split s on the first occurrence of delimiter delim.
 *
 * On success (delim found):
 *   *head receives the bytes before delim
 *   *tail receives the bytes after delim (may be empty)
 *   returns 1
 *
 * On failure (delim not found):
 *   *head receives s unchanged
 *   *tail receives STR_NULL
 *   returns 0
 *
 * Neither head nor tail include the delimiter byte.
 * No allocation — both share s.data.
 */
TL_NONNULL(3, 4)
int str_split_first(str_t s, char delim, str_t *head, str_t *tail);

/*
 * str_split_last — split s on the last occurrence of delimiter delim.
 * Same semantics as str_split_first but anchored to the rightmost delim.
 */
TL_NONNULL(3, 4)
int str_split_last(str_t s, char delim, str_t *head, str_t *tail);


/* =========================================================================
 * Whitespace trimming
 * ========================================================================= */

/*
 * str_trim_left — return s with leading ASCII whitespace removed.
 * No allocation.  Returns a sub-view of s.data.
 */
TL_PURE
str_t str_trim_left(str_t s);

/*
 * str_trim_right — return s with trailing ASCII whitespace removed.
 * No allocation.
 */
TL_PURE
str_t str_trim_right(str_t s);

/*
 * str_trim — return s with both leading and trailing ASCII whitespace removed.
 */
TL_PURE
str_t str_trim(str_t s);


/* =========================================================================
 * Integer parsing
 *
 * No atoi(). No strtol(). No NUL-terminated assumptions.
 * Leading/trailing whitespace is NOT accepted — caller trims if needed.
 * *out is written only on success (return value 1).
 * ========================================================================= */

/*
 * str_to_u64 — parse s as a base-10 unsigned 64-bit integer.
 * Returns 1 on success, 0 on parse error, overflow, or out == NULL.
 */
int str_to_u64(str_t s, uint64_t *out);

/*
 * str_to_i64 — parse s as a base-10 signed 64-bit integer.
 * Optional leading '-'; no leading '+' accepted.
 * Returns 1 on success, 0 on parse error, overflow, or out == NULL.
 */
int str_to_i64(str_t s, int64_t *out);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKENLINT_STR_H */
