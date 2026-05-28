/*
 * tests/unit/test_json_writer.c
 *
 * Unit tests for src/output/json_writer.c.
 *
 * Strategy: write to a temporary FILE* (tmpfile()), read back the output,
 * compare to expected JSON strings.
 */

#include "helpers/test_runner.h"
#include "json_writer.h"
#include "tokenlint.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* =========================================================================
 * Helper: capture jw output into a heap buffer
 * ========================================================================= */

static char *capture(void (*fn)(jw_t *w, void *arg), void *arg)
{
    FILE *f = tmpfile();
    if (!f) return NULL;

    jw_t w;
    jw_init(&w, f);
    fn(&w, arg);
    jw_finish(&w);

    long len = ftell(f);
    if (len < 0) { fclose(f); return NULL; }

    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(f); return NULL; }

    rewind(f);
    size_t n = fread(buf, 1, (size_t)len, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}


/* =========================================================================
 * Tests
 * ========================================================================= */

static void write_empty_object(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_object_end(w);
}

TEST(empty_object) {
    char *out = capture(write_empty_object, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_STR_EQ(out, "{}\n");
    free(out);
}

/* --- */

static void write_empty_array(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_array_begin(w);
    jw_array_end(w);
}

TEST(empty_array) {
    char *out = capture(write_empty_array, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_STR_EQ(out, "[]\n");
    free(out);
}

/* --- */

static void write_string_value(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_key(w, "name");
    jw_string(w, "tokenlint");
    jw_object_end(w);
}

TEST(string_value) {
    char *out = capture(write_string_value, NULL);
    ASSERT_NOT_NULL(out);
    /* Must contain key and value */
    ASSERT_TRUE(strstr(out, "\"name\"") != NULL);
    ASSERT_TRUE(strstr(out, "\"tokenlint\"") != NULL);
    free(out);
}

/* --- */

static void write_int_value(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_key(w, "count");
    jw_int(w, 42);
    jw_object_end(w);
}

TEST(int_value) {
    char *out = capture(write_int_value, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(strstr(out, "\"count\"") != NULL);
    ASSERT_TRUE(strstr(out, "42") != NULL);
    free(out);
}

/* --- */

static void write_negative_int(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_key(w, "x");
    jw_int(w, -9999);
    jw_object_end(w);
}

TEST(negative_int) {
    char *out = capture(write_negative_int, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(strstr(out, "-9999") != NULL);
    free(out);
}

/* --- */

static void write_bool_values(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_key(w, "t"); jw_bool(w, 1);
    jw_key(w, "f"); jw_bool(w, 0);
    jw_object_end(w);
}

TEST(bool_values) {
    char *out = capture(write_bool_values, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(strstr(out, "true") != NULL);
    ASSERT_TRUE(strstr(out, "false") != NULL);
    free(out);
}

/* --- */

static void write_null_value(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_key(w, "x"); jw_null(w);
    jw_object_end(w);
}

TEST(null_value) {
    char *out = capture(write_null_value, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(strstr(out, "null") != NULL);
    free(out);
}

/* --- */

static void write_null_string(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_key(w, "x"); jw_string(w, NULL);
    jw_object_end(w);
}

TEST(null_string_writes_null) {
    char *out = capture(write_null_string, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(strstr(out, "null") != NULL);
    free(out);
}

/* --- */

static void write_escape_special(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_key(w, "msg");
    jw_string(w, "say \"hello\"\\world");
    jw_object_end(w);
}

TEST(escape_quotes_and_backslash) {
    char *out = capture(write_escape_special, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(strstr(out, "\\\"hello\\\"") != NULL);
    ASSERT_TRUE(strstr(out, "\\\\world") != NULL);
    free(out);
}

/* --- */

static void write_escape_control(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_key(w, "tab");
    jw_string(w, "a\tb");
    jw_key(w, "newline");
    jw_string(w, "c\nd");
    jw_object_end(w);
}

TEST(escape_control_chars) {
    char *out = capture(write_escape_control, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(strstr(out, "\\t") != NULL);
    ASSERT_TRUE(strstr(out, "\\n") != NULL);
    free(out);
}

/* --- */

static void write_array_of_strings(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_array_begin(w);
    jw_string(w, "a");
    jw_string(w, "b");
    jw_string(w, "c");
    jw_array_end(w);
}

TEST(array_of_strings) {
    char *out = capture(write_array_of_strings, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(strstr(out, "\"a\"") != NULL);
    ASSERT_TRUE(strstr(out, "\"b\"") != NULL);
    ASSERT_TRUE(strstr(out, "\"c\"") != NULL);
    /* Exactly 2 commas for 3 elements */
    int commas = 0;
    for (char *p = out; *p; p++) if (*p == ',') commas++;
    ASSERT_EQ(commas, 2);
    free(out);
}

/* --- */

static void write_nested_object(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_key(w, "tool");
    jw_object_begin(w);
    jw_key(w, "name"); jw_string(w, "tokenlint");
    jw_key(w, "version"); jw_string(w, "0.1.0");
    jw_object_end(w);
    jw_key(w, "active"); jw_bool(w, 1);
    jw_object_end(w);
}

TEST(nested_object) {
    char *out = capture(write_nested_object, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(strstr(out, "\"tool\"") != NULL);
    ASSERT_TRUE(strstr(out, "\"tokenlint\"") != NULL);
    ASSERT_TRUE(strstr(out, "\"0.1.0\"") != NULL);
    ASSERT_TRUE(strstr(out, "\"active\"") != NULL);
    ASSERT_TRUE(strstr(out, "true") != NULL);
    free(out);
}

/* --- */

static void write_multiple_keys(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_key(w, "a"); jw_int(w, 1);
    jw_key(w, "b"); jw_int(w, 2);
    jw_key(w, "c"); jw_int(w, 3);
    jw_object_end(w);
}

TEST(multiple_keys_comma_count) {
    char *out = capture(write_multiple_keys, NULL);
    ASSERT_NOT_NULL(out);
    /* 3 keys → 2 commas between them */
    int commas = 0;
    for (char *p = out; *p; p++) if (*p == ',') commas++;
    ASSERT_EQ(commas, 2);
    free(out);
}

/* --- */

static void write_str_t(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_key(w, "s");
    str_t s = STR_LIT("hello");
    jw_str(w, s);
    jw_key(w, "n");
    jw_str(w, STR_NULL);
    jw_object_end(w);
}

TEST(str_t_value) {
    char *out = capture(write_str_t, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(strstr(out, "\"hello\"") != NULL);
    /* STR_NULL → null */
    ASSERT_TRUE(strstr(out, "null") != NULL);
    free(out);
}

/* --- */

static void write_array_in_object(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_key(w, "items");
    jw_array_begin(w);
    jw_string(w, "x");
    jw_string(w, "y");
    jw_array_end(w);
    jw_key(w, "done"); jw_bool(w, 1);
    jw_object_end(w);
}

TEST(array_in_object) {
    char *out = capture(write_array_in_object, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(strstr(out, "\"items\"") != NULL);
    ASSERT_TRUE(strstr(out, "\"x\"") != NULL);
    ASSERT_TRUE(strstr(out, "\"y\"") != NULL);
    ASSERT_TRUE(strstr(out, "\"done\"") != NULL);
    free(out);
}

/* --- */

static void write_string_n(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    jw_object_begin(w);
    jw_key(w, "x");
    /* "hello world" — only write first 5 chars */
    jw_string_n(w, "hello world", 5);
    jw_object_end(w);
}

TEST(string_n_length_limited) {
    char *out = capture(write_string_n, NULL);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(strstr(out, "\"hello\"") != NULL);
    /* "world" must not appear */
    ASSERT_TRUE(strstr(out, "world") == NULL);
    free(out);
}

/* --- security property: output never contains raw control bytes --- */

static void write_all_controls(jw_t *w, void *arg)
{
    TL_UNUSED(arg);
    /* Build a string with all 32 ASCII control chars */
    char controls[32];
    for (int i = 0; i < 32; i++) controls[i] = (char)i;
    jw_array_begin(w);
    jw_string_n(w, controls, 32);
    jw_array_end(w);
}

SECURITY_PROP(no_raw_control_bytes_in_output) {
    char *out = capture(write_all_controls, NULL);
    ASSERT_NOT_NULL(out);
    /* Skip the final newline jw_finish() emits, which is fine. */
    /* The JSON string value must not contain raw control chars */
    int found_raw = 0;
    int in_string = 0;
    for (char *p = out; *p; p++) {
        if (*p == '"' && (p == out || *(p-1) != '\\')) {
            in_string = !in_string;
            continue;
        }
        if (in_string) {
            unsigned char c = (unsigned char)*p;
            /* Escaped sequences start with \, skip the escape char */
            if (c == '\\') { p++; continue; } /* skip next */
            if (c < 0x20) found_raw = 1;
        }
    }
    ASSERT_FALSE(found_raw);
    free(out);
}


TEST_MAIN(
    tl_run_empty_object,
    tl_run_empty_array,
    tl_run_string_value,
    tl_run_int_value,
    tl_run_negative_int,
    tl_run_bool_values,
    tl_run_null_value,
    tl_run_null_string_writes_null,
    tl_run_escape_quotes_and_backslash,
    tl_run_escape_control_chars,
    tl_run_array_of_strings,
    tl_run_nested_object,
    tl_run_multiple_keys_comma_count,
    tl_run_str_t_value,
    tl_run_array_in_object,
    tl_run_string_n_length_limited,
    tl_run_no_raw_control_bytes_in_output,
)
