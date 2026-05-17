/*
 * src/util/str.c
 *
 * str_t utility functions for tokenlint.
 *
 * Everything here operates on str_t values that already live in an arena.
 * No allocation. No strlen(). No NUL-terminated assumptions.
 *
 * Functions declared static inline in tokenlint.h (str_eq, str_has_prefix,
 * str_blank, str_from_cstr) are NOT repeated here.
 *
 * arena_strdup() is implemented in src/util/arena.c, not here.
 */

#include "tokenlint.h"

#include <stdint.h>   /* uint64_t, int64_t, UINT64_MAX */
#include <stddef.h>   /* size_t                        */


/* =========================================================================
 * Slicing and suffix
 * ========================================================================= */

/*
 * str_slice — return the sub-string s[start .. start+length).
 *
 * If start >= s.len, returns STR_NULL.
 * If start+length > s.len, clamps to the end of s.
 * The returned str_t shares s.data — no copy, no allocation.
 */
str_t str_slice(str_t s, size_t start, size_t length) {
    if (start >= s.len) return STR_NULL;
    size_t avail = s.len - start;
    if (length > avail) length = avail;
    str_t r;
    r.data = s.data + start;
    r.len  = length;
    return r;
}

/*
 * str_has_suffix — returns 1 if s ends with suffix, 0 otherwise.
 * Empty suffix always matches.  Null s never matches a non-empty suffix.
 */
int str_has_suffix(str_t s, str_t suffix) {
    if (suffix.len == 0) return 1;
    if (s.len < suffix.len) return 0;
    size_t offset = s.len - suffix.len;
    return memcmp(s.data + offset, suffix.data, suffix.len) == 0;
}


/* =========================================================================
 * Search
 * ========================================================================= */

/*
 * str_find_byte — return the index of the first occurrence of byte c in s,
 * or (size_t)-1 if not found.
 */
size_t str_find_byte(str_t s, char c) {
    for (size_t i = 0; i < s.len; i++) {
        if (s.data[i] == c) return i;
    }
    return (size_t)-1;
}

/*
 * str_find_byte_from — like str_find_byte but starts searching at offset.
 * Returns (size_t)-1 if not found at or after offset.
 */
size_t str_find_byte_from(str_t s, char c, size_t offset) {
    for (size_t i = offset; i < s.len; i++) {
        if (s.data[i] == c) return i;
    }
    return (size_t)-1;
}

/*
 * str_contains — returns 1 if s contains byte c, 0 otherwise.
 */
int str_contains(str_t s, char c) {
    return str_find_byte(s, c) != (size_t)-1;
}


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
 * Neither head nor tail include the delimiter byte itself.
 * No allocation — both share s.data.
 */
int str_split_first(str_t s, char delim, str_t *head, str_t *tail) {
    size_t pos = str_find_byte(s, delim);
    if (pos == (size_t)-1) {
        *head = s;
        *tail = STR_NULL;
        return 0;
    }
    head->data = s.data;
    head->len  = pos;
    tail->data = s.data + pos + 1;
    tail->len  = s.len - pos - 1;
    return 1;
}

/*
 * str_split_last — split s on the last occurrence of delimiter delim.
 * Same semantics as str_split_first but anchored to the rightmost delim.
 */
int str_split_last(str_t s, char delim, str_t *head, str_t *tail) {
    /* scan right-to-left */
    for (size_t i = s.len; i-- > 0; ) {
        if (s.data[i] == delim) {
            head->data = s.data;
            head->len  = i;
            tail->data = s.data + i + 1;
            tail->len  = s.len - i - 1;
            return 1;
        }
    }
    *head = s;
    *tail = STR_NULL;
    return 0;
}


/* =========================================================================
 * Whitespace trimming
 * ========================================================================= */

/* Internal: is byte ASCII whitespace? */
static int is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/*
 * str_trim_left — return s with leading ASCII whitespace removed.
 * No allocation. Returns a sub-view of s.data.
 */
str_t str_trim_left(str_t s) {
    size_t i = 0;
    while (i < s.len && is_ws(s.data[i])) i++;
    return str_slice(s, i, s.len - i);
}

/*
 * str_trim_right — return s with trailing ASCII whitespace removed.
 * No allocation.
 */
str_t str_trim_right(str_t s) {
    size_t n = s.len;
    while (n > 0 && is_ws(s.data[n - 1])) n--;
    str_t r;
    r.data = s.data;
    r.len  = n;
    return r;
}

/*
 * str_trim — return s with both leading and trailing ASCII whitespace removed.
 */
str_t str_trim(str_t s) {
    return str_trim_right(str_trim_left(s));
}


/* =========================================================================
 * Integer parsing
 *
 * No atoi(). No strtol(). No NUL-terminated assumptions.
 * All parsing operates directly on str_t bytes.
 *
 * Parsing rules:
 *   - Leading/trailing whitespace is NOT accepted (caller must trim if needed)
 *   - Empty string → error
 *   - Non-digit characters → error (no sign for u64; sign allowed for i64)
 *   - Overflow → error; *out is not modified on error
 * ========================================================================= */

/*
 * str_to_u64 — parse s as a base-10 unsigned 64-bit integer.
 * Returns 1 on success, 0 on parse error or overflow.
 * *out is written only on success.
 */
int str_to_u64(str_t s, uint64_t *out) {
    if (s.len == 0 || out == NULL) return 0;

    uint64_t val = 0;
    for (size_t i = 0; i < s.len; i++) {
        char c = s.data[i];
        if (c < '0' || c > '9') return 0;
        uint64_t digit = (uint64_t)(c - '0');
        /* overflow check: val * 10 + digit > UINT64_MAX */
        if (val > (UINT64_MAX - digit) / 10) return 0;
        val = val * 10 + digit;
    }
    *out = val;
    return 1;
}

/*
 * str_to_i64 — parse s as a base-10 signed 64-bit integer.
 * Optional leading '-'; no leading '+' accepted.
 * Returns 1 on success, 0 on parse error or overflow.
 * *out is written only on success.
 */
int str_to_i64(str_t s, int64_t *out) {
    if (s.len == 0 || out == NULL) return 0;

    int negative = 0;
    size_t start = 0;

    if (s.data[0] == '-') {
        negative = 1;
        start    = 1;
        if (s.len == 1) return 0; /* bare '-' is not a number */
    }

    /* Parse the absolute value into u64 first to handle INT64_MIN cleanly */
    uint64_t uval = 0;
    for (size_t i = start; i < s.len; i++) {
        char c = s.data[i];
        if (c < '0' || c > '9') return 0;
        uint64_t digit = (uint64_t)(c - '0');
        if (uval > (UINT64_MAX - digit) / 10) return 0;
        uval = uval * 10 + digit;
    }

    if (negative) {
        /* INT64_MIN = -9223372036854775808; as u64 = 9223372036854775808 */
        if (uval > (uint64_t)INT64_MAX + 1u) return 0;
        *out = (uval == (uint64_t)INT64_MAX + 1u)
               ? INT64_MIN
               : -(int64_t)uval;
    } else {
        if (uval > (uint64_t)INT64_MAX) return 0;
        *out = (int64_t)uval;
    }
    return 1;
}
