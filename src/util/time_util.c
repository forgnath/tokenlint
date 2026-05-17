/*
 * src/util/time_util.c
 *
 * Time utilities for tokenlint v1.
 *
 * Implements --at flag parsing, system-clock resolution, and ISO 8601 Z
 * formatting.  All arithmetic is in int64_t Unix epoch seconds.
 *
 * No vendor headers.  No arena allocation (time values are plain integers).
 * No strlen() except at the parse boundary where the input is a str_t.
 *
 * Parsing design:
 *   - "now"          -> system clock, labelled cli_at_now
 *   - ISO 8601       -> civil_to_epoch() (no mktime, no tz dependency)
 *   - unsigned int   -> str_to_u64() from str.h (no atoi, no strtol)
 *
 * civil_to_epoch() uses the algorithm from Howard Hinnant's date library
 * (public domain): https://howardhinnant.github.io/date_algorithms.html
 */

#include "tokenlint.h"
#include "str.h"
#include "time_util.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>   /* memcpy (not used; included for consistency) */
#include <time.h>     /* time(), gmtime_r(), strftime()              */


/* =========================================================================
 * Internal helpers
 * ========================================================================= */

/*
 * at_error — construct TL_ERR_AT_FLAG with a literal message and the raw
 * at_str as context (for the error envelope).
 */
static tl_error_t at_error(const char *msg, str_t context) {
    return tl_error(TL_ERR_AT_FLAG, msg, context);
}

/*
 * parse_two_digits — parse exactly two ASCII decimal digits from p[0..1].
 * Returns value [0..99] or -1 on failure.
 * No NUL check — caller guarantees at least 2 bytes remain.
 */
static int parse_two_digits(const char *p) {
    if (p[0] < '0' || p[0] > '9') return -1;
    if (p[1] < '0' || p[1] > '9') return -1;
    return (p[0] - '0') * 10 + (p[1] - '0');
}

/*
 * parse_four_digits — parse exactly four ASCII decimal digits from p[0..3].
 * Returns value [0..9999] or -1 on failure.
 */
static int parse_four_digits(const char *p) {
    for (int i = 0; i < 4; i++)
        if (p[i] < '0' || p[i] > '9') return -1;
    return  (p[0] - '0') * 1000
          + (p[1] - '0') * 100
          + (p[2] - '0') * 10
          + (p[3] - '0');
}

/*
 * is_leap_year — 1 if year is a Gregorian leap year, else 0.
 */
static int is_leap_year(int y) {
    return (y % 4 == 0) && ((y % 100 != 0) || (y % 400 == 0));
}

/* Days in each month for a non-leap year (index 1..12) */
static const int days_in_month[13] = {
    0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

/*
 * civil_to_epoch — convert a broken-down UTC date/time to Unix epoch seconds.
 *
 * Uses Hinnant's algorithm (shift epoch to 0000-03-01; integer-only arithmetic).
 * Sets *ok = 1 on success, 0 on invalid input.
 * Returns -1 with *ok = 0 on failure (so callers can treat -1 as sentinel).
 *
 * Valid ranges enforced:
 *   mon  [1..12]
 *   day  [1..days_in_month[mon]] (leap-year aware)
 *   hour [0..23]
 *   min  [0..59]
 *   sec  [0..60]  (60 permitted for leap second; no special handling)
 */
static int64_t civil_to_epoch(int year, int mon, int day,
                               int hour, int min, int sec,
                               int *ok)
{
    *ok = 0;

    if (mon < 1 || mon > 12) return -1;
    if (day < 1)              return -1;
    {
        int dim = days_in_month[mon];
        if (mon == 2 && is_leap_year(year)) dim = 29;
        if (day > dim) return -1;
    }
    if (hour < 0 || hour > 23) return -1;
    if (min  < 0 || min  > 59) return -1;
    if (sec  < 0 || sec  > 60) return -1;

    /* Shift months so Mar=0, ..., Feb=11 (eliminates leap-day special case) */
    int y = year;
    int m = mon;
    int d = day;
    if (m <= 2) { y--; m += 9; } else { m -= 3; }

    /* Hinnant's formula for days since 1970-01-01 */
    int64_t era  = (int64_t)(y >= 0 ? y : y - 399) / 400;
    int     yoe  = (int)(y - era * 400);                   /* [0, 399]    */
    int     doy  = (153 * m + 2) / 5 + d - 1;             /* [0, 365]    */
    int     doe  = yoe * 365 + yoe / 4 - yoe / 100 + doy; /* [0, 146096] */
    int64_t days = era * 146097 + (int64_t)doe - 719468;   /* epoch days  */

    int64_t result = days  * 86400LL
                   + (int64_t)hour * 3600LL
                   + (int64_t)min  * 60LL
                   + (int64_t)sec;
    *ok = 1;
    return result;
}

/*
 * parse_iso8601 — parse an ISO 8601 datetime with mandatory timezone.
 *
 * Accepted:
 *   len==20: "YYYY-MM-DDTHH:MM:SSZ"
 *   len==25: "YYYY-MM-DDTHH:MM:SS+HH:MM" or "YYYY-MM-DDTHH:MM:SS-HH:MM"
 *
 * Any other length or structure returns 0 (rejected).
 * "YYYY-MM-DDTHH:MM:SS" (len==19, no timezone) is rejected.
 *
 * On success: *epoch_out = UTC epoch seconds, returns 1.
 * On failure: returns 0.
 */
static int parse_iso8601(const char *s, size_t len, int64_t *epoch_out) {
    /* Minimum viable: "YYYY-MM-DDTHH:MM:SSZ" = 20 chars */
    if (len < 20) return 0;

    /* Validate fixed separators at known positions */
    if (s[4] != '-' || s[7] != '-' || s[10] != 'T' ||
        s[13] != ':' || s[16] != ':') return 0;

    int year = parse_four_digits(s + 0);
    int mon  = parse_two_digits (s + 5);
    int day  = parse_two_digits (s + 8);
    int hour = parse_two_digits (s + 11);
    int min  = parse_two_digits (s + 14);
    int sec  = parse_two_digits (s + 17);

    if (year < 0 || mon < 0 || day < 0 ||
        hour < 0 || min < 0 || sec < 0) return 0;

    /* Timezone starts at position 19 */
    int64_t offset_secs = 0;

    if (len == 20 && s[19] == 'Z') {
        /* "...Z" — UTC */
        offset_secs = 0;

    } else if (len == 25 && (s[19] == '+' || s[19] == '-')) {
        /* "...+HH:MM" or "...-HH:MM" */
        if (s[22] != ':') return 0;
        int oh = parse_two_digits(s + 20);
        int om = parse_two_digits(s + 23);
        if (oh < 0 || om < 0)    return 0;
        if (oh > 23 || om > 59)  return 0;
        offset_secs = (int64_t)oh * 3600 + (int64_t)om * 60;
        if (s[19] == '-') offset_secs = -offset_secs;

    } else {
        /*
         * len==19 with no timezone char, or any other unrecognized suffix.
         * Both are rejected — the caller reports "missing timezone".
         */
        return 0;
    }

    int ok;
    int64_t epoch = civil_to_epoch(year, mon, day, hour, min, sec, &ok);
    if (!ok) return 0;

    /* Convert from local timezone to UTC by subtracting the offset */
    epoch -= offset_secs;

    *epoch_out = epoch;
    return 1;
}


/* =========================================================================
 * Public API
 * ========================================================================= */

/*
 * tl_parse_at_flag — parse the --at flag value into a tl_reference_time_t.
 *
 * Parse order:
 *   1. "now"        — system clock, source = cli_at_now
 *   2. ISO 8601     — detected by '-' at position 4
 *   3. Unsigned int — all-digit string via str_to_u64()
 */
tl_error_t tl_parse_at_flag(str_t at_str, tl_reference_time_t *out) {
    if (str_blank(at_str)) {
        return at_error("--at value is empty", at_str);
    }

    /* ── "now" ── */
    if (str_eq(at_str, STR_LIT("now"))) {
        tl_error_t err = tl_resolve_reference_time(out);
        if (!tl_ok(err)) return err;
        out->source = TL_TIME_SRC_CLI_AT_NOW;
        return TL_OK;
    }

    /* ── Reject explicit negative integer literals ── */
    if (at_str.data[0] == '-') {
        return at_error("--at value must not be negative", at_str);
    }

    /* ── ISO 8601 ── (heuristic: '-' at position 4) */
    if (at_str.len >= 10 &&
        at_str.data[4] == '-' && at_str.data[7] == '-') {

        int64_t epoch;
        if (!parse_iso8601(at_str.data, at_str.len, &epoch)) {
            return at_error(
                "--at ISO 8601 value is malformed or missing timezone "
                "(expected Z or +HH:MM suffix)",
                at_str);
        }
        if (epoch < 0) {
            return at_error(
                "--at timestamp resolves before Unix epoch (1970-01-01T00:00:00Z)",
                at_str);
        }
        out->value  = epoch;
        out->source = TL_TIME_SRC_CLI_AT;
        return TL_OK;
    }

    /* ── Unsigned decimal integer ── */
    uint64_t uval;
    if (!str_to_u64(at_str, &uval)) {
        return at_error(
            "--at value is not a valid Unix timestamp or ISO 8601 datetime",
            at_str);
    }
    if (uval > (uint64_t)INT64_MAX) {
        return at_error("--at Unix timestamp overflows int64", at_str);
    }

    out->value  = (int64_t)uval;
    out->source = TL_TIME_SRC_CLI_AT;
    return TL_OK;
}

/*
 * tl_resolve_reference_time — read the system clock.
 *
 * Sets source = TL_TIME_SRC_SYSTEM_CLOCK.
 * Returns TL_ERR_INTERNAL if time() fails (should not happen on any
 * supported platform).
 */
tl_error_t tl_resolve_reference_time(tl_reference_time_t *out) {
    time_t t = time(NULL);
    if (t == (time_t)-1) {
        return tl_error_internal("system clock unavailable");
    }
    out->value  = (int64_t)t;
    out->source = TL_TIME_SRC_SYSTEM_CLOCK;
    return TL_OK;
}

/*
 * tl_format_iso8601z — format epoch_secs as "YYYY-MM-DDTHH:MM:SSZ\0".
 *
 * Uses gmtime_r() (POSIX) or gmtime_s() (Windows) to avoid tz dependency.
 * buf must be at least TL_ISO8601Z_BUF_LEN (21) bytes.
 * Returns 0 on success, -1 on failure.
 */
int tl_format_iso8601z(int64_t epoch_secs, char *buf, size_t buf_len) {
    if (buf_len < TL_ISO8601Z_BUF_LEN) return -1;

    time_t t = (time_t)epoch_secs;
    struct tm tm_utc;

#if defined(_WIN32)
    if (gmtime_s(&tm_utc, &t) != 0) return -1;
#else
    if (gmtime_r(&t, &tm_utc) == NULL) return -1;
#endif

    /* strftime writes "YYYY-MM-DDTHH:MM:SS" (19 chars) */
    size_t n = strftime(buf, buf_len, "%Y-%m-%dT%H:%M:%S", &tm_utc);
    if (n == 0) return -1;
    /* Append 'Z' and NUL — must fit */
    if (n + 2 > buf_len) return -1;

    buf[n]     = 'Z';
    buf[n + 1] = '\0';
    return 0;
}

/*
 * tl_time_source_str — string literal for JSON "source" field.
 */
const char *tl_time_source_str(tl_time_source_t source) {
    switch (source) {
        case TL_TIME_SRC_SYSTEM_CLOCK: return "system_clock";
        case TL_TIME_SRC_CLI_AT:       return "cli_at";
        case TL_TIME_SRC_CLI_AT_NOW:   return "cli_at_now";
        default:                       return "unknown";
    }
}
