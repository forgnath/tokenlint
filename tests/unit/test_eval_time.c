/*
 * tests/unit/test_eval_time.c
 *
 * Unit tests for src/util/time_util.c
 *
 * Coverage:
 *   tl_parse_at_flag     -- all accepted and rejected formats per time-contract.md
 *   tl_resolve_reference_time
 *   tl_format_iso8601z
 *   tl_time_source_str
 *
 * 28 TEST + 4 SECURITY_PROP = 32 total
 *
 * Exit codes (from test_runner.h):
 *   0 -- all passed
 *   1 -- correctness failure
 *   2 -- SECURITY_PROP failure
 */

#include "helpers/test_runner.h"
#include "tokenlint.h"
#include "str.h"
#include "time_util.h"

#include <stdint.h>
#include <string.h>
#include <time.h>


/* =========================================================================
 * Test helpers
 * ========================================================================= */

/* Parse and return the result (unchecked error — use only when expecting OK) */
static tl_reference_time_t parse_ok(const char *lit) {
    tl_reference_time_t r;
    r.value  = -1;
    r.source = TL_TIME_SRC_SYSTEM_CLOCK;
    tl_error_t err = tl_parse_at_flag(str_from_cstr(lit), &r);
    TL_UNUSED(err);
    return r;
}

/* Returns 1 if parsing lit produces a non-OK error */
static int parse_fails(const char *lit) {
    tl_reference_time_t r;
    r.value  = 0;
    r.source = TL_TIME_SRC_SYSTEM_CLOCK;
    tl_error_t err = tl_parse_at_flag(str_from_cstr(lit), &r);
    return !tl_ok(err);
}

/* Returns the error kind from parsing lit */
static int parse_err_kind(const char *lit) {
    tl_reference_time_t r;
    r.value  = 0;
    r.source = TL_TIME_SRC_SYSTEM_CLOCK;
    tl_error_t err = tl_parse_at_flag(str_from_cstr(lit), &r);
    return (int)err.kind;
}


/* =========================================================================
 * tl_parse_at_flag -- "now"
 * ========================================================================= */

TEST(parse_at_now_source) {
    tl_reference_time_t r;
    tl_error_t err = tl_parse_at_flag(STR_LIT("now"), &r);
    ASSERT_TRUE(tl_ok(err));
    ASSERT_EQ((int)r.source, (int)TL_TIME_SRC_CLI_AT_NOW);
}

TEST(parse_at_now_value_positive) {
    tl_reference_time_t r;
    tl_error_t err = tl_parse_at_flag(STR_LIT("now"), &r);
    ASSERT_TRUE(tl_ok(err));
    /* Should be a plausible post-2020 timestamp */
    ASSERT_GT(r.value, 1577836800LL);
}


/* =========================================================================
 * tl_parse_at_flag -- Unix epoch integers
 * ========================================================================= */

TEST(parse_at_unix_zero) {
    tl_reference_time_t r = parse_ok("0");
    ASSERT_EQ(r.value, 0LL);
    ASSERT_EQ((int)r.source, (int)TL_TIME_SRC_CLI_AT);
}

TEST(parse_at_unix_one) {
    tl_reference_time_t r = parse_ok("1");
    ASSERT_EQ(r.value, 1LL);
}

TEST(parse_at_unix_known_epoch) {
    /* 2026-04-30T12:00:00Z = 1777550400 (verified via python3 datetime) */
    tl_reference_time_t r = parse_ok("1777550400");
    ASSERT_EQ(r.value, 1777550400LL);
    ASSERT_EQ((int)r.source, (int)TL_TIME_SRC_CLI_AT);
}

TEST(parse_at_unix_large) {
    /* ~year 2100 */
    tl_reference_time_t r = parse_ok("4102444800");
    ASSERT_EQ(r.value, 4102444800LL);
}


/* =========================================================================
 * tl_parse_at_flag -- ISO 8601 with Z suffix
 * ========================================================================= */

TEST(parse_at_iso_z_basic) {
    /* 2026-04-30T12:00:00Z */
    tl_reference_time_t r = parse_ok("2026-04-30T12:00:00Z");
    ASSERT_EQ(r.value, 1777550400LL);
    ASSERT_EQ((int)r.source, (int)TL_TIME_SRC_CLI_AT);
}

TEST(parse_at_iso_z_epoch) {
    /* 1970-01-01T00:00:00Z = 0 */
    tl_reference_time_t r = parse_ok("1970-01-01T00:00:00Z");
    ASSERT_EQ(r.value, 0LL);
}

TEST(parse_at_iso_z_midnight) {
    /* 2024-01-01T00:00:00Z = 1704067200 */
    tl_reference_time_t r = parse_ok("2024-01-01T00:00:00Z");
    ASSERT_EQ(r.value, 1704067200LL);
}

TEST(parse_at_iso_z_end_of_day) {
    /* 2024-01-01T23:59:59Z = 1704153599 */
    tl_reference_time_t r = parse_ok("2024-01-01T23:59:59Z");
    ASSERT_EQ(r.value, 1704153599LL);
}

TEST(parse_at_iso_leap_day) {
    /* 2024-02-29T00:00:00Z = 1709164800 (2024 is a leap year) */
    tl_reference_time_t r = parse_ok("2024-02-29T00:00:00Z");
    ASSERT_EQ(r.value, 1709164800LL);
}


/* =========================================================================
 * tl_parse_at_flag -- ISO 8601 with numeric timezone offset
 * ========================================================================= */

TEST(parse_at_iso_negative_offset) {
    /* 2026-04-30T08:00:00-04:00 = 2026-04-30T12:00:00Z = 1777550400 */
    tl_reference_time_t r = parse_ok("2026-04-30T08:00:00-04:00");
    ASSERT_EQ(r.value, 1777550400LL);
}

TEST(parse_at_iso_positive_offset) {
    /* 2026-04-30T15:30:00+03:30 = 2026-04-30T12:00:00Z = 1777550400 */
    tl_reference_time_t r = parse_ok("2026-04-30T15:30:00+03:30");
    ASSERT_EQ(r.value, 1777550400LL);
}

TEST(parse_at_iso_plus_zero_offset) {
    /* +00:00 is equivalent to Z */
    tl_reference_time_t r = parse_ok("2026-04-30T12:00:00+00:00");
    ASSERT_EQ(r.value, 1777550400LL);
}


/* =========================================================================
 * tl_parse_at_flag -- rejected formats (time-contract.md TL-I001)
 * ========================================================================= */

TEST(parse_at_reject_no_timezone) {
    /* time-contract: ISO 8601 without timezone -> FAIL TL-I001 */
    ASSERT_TRUE(parse_fails("2026-04-30T12:00:00"));
    ASSERT_EQ(parse_err_kind("2026-04-30T12:00:00"), (int)TL_ERR_AT_FLAG);
}

TEST(parse_at_reject_negative_integer) {
    ASSERT_TRUE(parse_fails("-1"));
    ASSERT_EQ(parse_err_kind("-1"), (int)TL_ERR_AT_FLAG);
}

TEST(parse_at_reject_negative_large) {
    ASSERT_TRUE(parse_fails("-9999999999"));
    ASSERT_EQ(parse_err_kind("-9999999999"), (int)TL_ERR_AT_FLAG);
}

TEST(parse_at_reject_empty_string) {
    ASSERT_TRUE(parse_fails(""));
}

TEST(parse_at_reject_str_null) {
    tl_reference_time_t r;
    r.value = 0;
    r.source = TL_TIME_SRC_SYSTEM_CLOCK;
    tl_error_t err = tl_parse_at_flag(STR_NULL, &r);
    ASSERT_FALSE(tl_ok(err));
    ASSERT_EQ((int)err.kind, (int)TL_ERR_AT_FLAG);
}

TEST(parse_at_reject_garbage) {
    ASSERT_TRUE(parse_fails("yesterday"));
    ASSERT_TRUE(parse_fails("last-week"));
    ASSERT_TRUE(parse_fails("abc"));
    ASSERT_TRUE(parse_fails("12abc"));
}

TEST(parse_at_reject_partial_iso) {
    ASSERT_TRUE(parse_fails("2026-04"));
    ASSERT_TRUE(parse_fails("2026-04-30"));
}

TEST(parse_at_reject_invalid_month) {
    ASSERT_TRUE(parse_fails("2026-13-01T00:00:00Z"));
    ASSERT_TRUE(parse_fails("2026-00-01T00:00:00Z"));
}

TEST(parse_at_reject_invalid_day) {
    /* 2026 is not a leap year: Feb 29 invalid */
    ASSERT_TRUE(parse_fails("2026-02-29T00:00:00Z"));
    /* April has 30 days */
    ASSERT_TRUE(parse_fails("2026-04-31T00:00:00Z"));
}

TEST(parse_at_reject_invalid_hour) {
    ASSERT_TRUE(parse_fails("2026-04-30T25:00:00Z"));
    ASSERT_TRUE(parse_fails("2026-04-30T24:00:00Z"));
}


/* =========================================================================
 * tl_resolve_reference_time
 * ========================================================================= */

TEST(resolve_reference_time_ok) {
    tl_reference_time_t r;
    tl_error_t err = tl_resolve_reference_time(&r);
    ASSERT_TRUE(tl_ok(err));
    ASSERT_EQ((int)r.source, (int)TL_TIME_SRC_SYSTEM_CLOCK);
    /* Must be a plausible post-2020 timestamp */
    ASSERT_GT(r.value, 1577836800LL);
}

TEST(resolve_reference_time_not_cli_at) {
    tl_reference_time_t r;
    tl_error_t err = tl_resolve_reference_time(&r);
    ASSERT_TRUE(tl_ok(err));
    ASSERT_NE((int)r.source, (int)TL_TIME_SRC_CLI_AT);
    ASSERT_NE((int)r.source, (int)TL_TIME_SRC_CLI_AT_NOW);
}


/* =========================================================================
 * tl_format_iso8601z
 * ========================================================================= */

TEST(format_iso8601z_known_value) {
    char buf[TL_ISO8601Z_BUF_LEN];
    int rc = tl_format_iso8601z(1777550400LL, buf, sizeof(buf));
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(buf, "2026-04-30T12:00:00Z");
}

TEST(format_iso8601z_epoch) {
    char buf[TL_ISO8601Z_BUF_LEN];
    int rc = tl_format_iso8601z(0LL, buf, sizeof(buf));
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(buf, "1970-01-01T00:00:00Z");
}

TEST(format_iso8601z_buf_too_small) {
    char buf[10];
    int rc = tl_format_iso8601z(1777550400LL, buf, sizeof(buf));
    ASSERT_EQ(rc, -1);
}

TEST(format_iso8601z_exact_length) {
    char buf[TL_ISO8601Z_BUF_LEN];
    int rc = tl_format_iso8601z(1777550400LL, buf, sizeof(buf));
    ASSERT_EQ(rc, 0);
    ASSERT_EQ((int)strlen(buf), 20);
}

TEST(format_iso8601z_z_suffix) {
    char buf[TL_ISO8601Z_BUF_LEN];
    tl_format_iso8601z(1777550400LL, buf, sizeof(buf));
    ASSERT_EQ((int)buf[19], (int)'Z');
    ASSERT_EQ((int)buf[20], (int)'\0');
}

TEST(format_iso8601z_midnight) {
    char buf[TL_ISO8601Z_BUF_LEN];
    int rc = tl_format_iso8601z(1704067200LL, buf, sizeof(buf));
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(buf, "2024-01-01T00:00:00Z");
}


/* =========================================================================
 * tl_time_source_str
 * ========================================================================= */

TEST(time_source_str_system_clock) {
    ASSERT_STR_EQ(tl_time_source_str(TL_TIME_SRC_SYSTEM_CLOCK), "system_clock");
}

TEST(time_source_str_cli_at) {
    ASSERT_STR_EQ(tl_time_source_str(TL_TIME_SRC_CLI_AT), "cli_at");
}

TEST(time_source_str_cli_at_now) {
    ASSERT_STR_EQ(tl_time_source_str(TL_TIME_SRC_CLI_AT_NOW), "cli_at_now");
}


/* =========================================================================
 * SECURITY_PROP — time-contract critical invariants
 * ========================================================================= */

/*
 * SECURITY_PROP: ISO 8601 without timezone must ALWAYS be rejected.
 *
 * Accepting "2026-04-30T12:00:00" silently as UTC would introduce a
 * class of timezone-confusion bugs.  The time-contract.md is explicit:
 * ambiguous timezone is a hard failure.
 */
SECURITY_PROP(iso8601_no_tz_always_rejected) {
    const char *cases[] = {
        "2026-04-30T12:00:00",
        "2000-01-01T00:00:00",
        "1999-12-31T23:59:59",
        "2038-01-19T03:14:07",
        "1970-01-01T00:00:00",
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        tl_reference_time_t r;
        r.value = 0;
        r.source = TL_TIME_SRC_SYSTEM_CLOCK;
        tl_error_t err = tl_parse_at_flag(str_from_cstr(cases[i]), &r);
        ASSERT_FALSE(tl_ok(err));
        ASSERT_EQ((int)err.kind, (int)TL_ERR_AT_FLAG);
    }
}

/*
 * SECURITY_PROP: Negative integer timestamps must ALWAYS be rejected.
 *
 * Accepting negative values would cause exp/nbf comparisons to behave
 * incorrectly — pre-1970 reference_time would make all tokens appear valid.
 */
SECURITY_PROP(negative_timestamp_always_rejected) {
    const char *cases[] = {
        "-1",
        "-100",
        "-9223372036854775808",
        "-0",   /* leading '-' before zero */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        ASSERT_TRUE(parse_fails(cases[i]));
        ASSERT_EQ(parse_err_kind(cases[i]), (int)TL_ERR_AT_FLAG);
    }
}

/*
 * SECURITY_PROP: Parse-then-format round-trip must be stable.
 *
 * Ensures the civil_to_epoch algorithm and tl_format_iso8601z are
 * consistent — critical for reproducible forensic output.
 */
SECURITY_PROP(parse_format_roundtrip) {
    struct { const char *iso; int64_t epoch; } cases[] = {
        { "2026-04-30T12:00:00Z", 1777550400LL },
        { "1970-01-01T00:00:00Z", 0LL           },
        { "2024-01-01T00:00:00Z", 1704067200LL  },
        { "2024-01-01T23:59:59Z", 1704153599LL  },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        tl_reference_time_t r = parse_ok(cases[i].iso);
        ASSERT_EQ(r.value, cases[i].epoch);

        char buf[TL_ISO8601Z_BUF_LEN];
        int rc = tl_format_iso8601z(r.value, buf, sizeof(buf));
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(buf, cases[i].iso);
    }
}

/*
 * SECURITY_PROP: "--at now" must produce source=cli_at_now, NOT system_clock.
 *
 * The JSON output contract requires distinct source strings.  Misidentifying
 * the source corrupts the audit trail used for forensic reproduction.
 */
SECURITY_PROP(now_source_is_cli_at_now_not_system_clock) {
    tl_reference_time_t r;
    tl_error_t err = tl_parse_at_flag(STR_LIT("now"), &r);
    ASSERT_TRUE(tl_ok(err));
    ASSERT_EQ((int)r.source, (int)TL_TIME_SRC_CLI_AT_NOW);
    ASSERT_NE((int)r.source, (int)TL_TIME_SRC_SYSTEM_CLOCK);
    ASSERT_NE((int)r.source, (int)TL_TIME_SRC_CLI_AT);
}


/* =========================================================================
 * TEST_MAIN
 * ========================================================================= */

TEST_MAIN(
    /* "now" */
    tl_run_parse_at_now_source,
    tl_run_parse_at_now_value_positive,

    /* Unix integers */
    tl_run_parse_at_unix_zero,
    tl_run_parse_at_unix_one,
    tl_run_parse_at_unix_known_epoch,
    tl_run_parse_at_unix_large,

    /* ISO 8601 Z */
    tl_run_parse_at_iso_z_basic,
    tl_run_parse_at_iso_z_epoch,
    tl_run_parse_at_iso_z_midnight,
    tl_run_parse_at_iso_z_end_of_day,
    tl_run_parse_at_iso_leap_day,

    /* ISO 8601 offset */
    tl_run_parse_at_iso_negative_offset,
    tl_run_parse_at_iso_positive_offset,
    tl_run_parse_at_iso_plus_zero_offset,

    /* Rejected */
    tl_run_parse_at_reject_no_timezone,
    tl_run_parse_at_reject_negative_integer,
    tl_run_parse_at_reject_negative_large,
    tl_run_parse_at_reject_empty_string,
    tl_run_parse_at_reject_str_null,
    tl_run_parse_at_reject_garbage,
    tl_run_parse_at_reject_partial_iso,
    tl_run_parse_at_reject_invalid_month,
    tl_run_parse_at_reject_invalid_day,
    tl_run_parse_at_reject_invalid_hour,

    /* resolve */
    tl_run_resolve_reference_time_ok,
    tl_run_resolve_reference_time_not_cli_at,

    /* format */
    tl_run_format_iso8601z_known_value,
    tl_run_format_iso8601z_epoch,
    tl_run_format_iso8601z_buf_too_small,
    tl_run_format_iso8601z_exact_length,
    tl_run_format_iso8601z_z_suffix,
    tl_run_format_iso8601z_midnight,

    /* source_str */
    tl_run_time_source_str_system_clock,
    tl_run_time_source_str_cli_at,
    tl_run_time_source_str_cli_at_now,

    /* SECURITY_PROP */
    tl_run_iso8601_no_tz_always_rejected,
    tl_run_negative_timestamp_always_rejected,
    tl_run_parse_format_roundtrip,
    tl_run_now_source_is_cli_at_now_not_system_clock,
)
