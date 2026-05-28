/*
 * src/output/json_writer.c
 *
 * Low-level JSON emitter for tokenlint.
 *
 * State machine:
 *   need_comma — a comma must precede the next sibling value
 *   after_key  — we just emitted "key": so next value goes on same line
 *   first_item — we are at depth 0 and haven't written anything yet
 *                (suppresses leading newline for the top-level value)
 *
 * Indent: 2 spaces per depth level.
 * All strings pass through jw_escape_string (escapes \, ", and U+0000–001F).
 */

#include "tokenlint.h"
#include "json_writer.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>


/* =========================================================================
 * Internal helpers
 * ========================================================================= */

static void write_indent(jw_t *w)
{
    for (int i = 0; i < w->depth; i++) {
        fputs("  ", w->fp);
    }
}

/*
 * pre_value — emit separator before a value.
 *
 * Cases:
 *   after_key == 1   : value follows "key": on same line; no newline, no indent
 *   first_item == 1  : very first value at depth 0; no leading newline
 *   need_comma == 1  : sibling value; emit "," then newline+indent
 *   otherwise        : first element of container; emit newline+indent
 */
static void pre_value(jw_t *w)
{
    if (w->after_key) {
        w->after_key = 0;
        /* value follows key on same line — no prefix */
        return;
    }

    if (w->first_item) {
        w->first_item = 0;
        /* top-level first value: no leading newline */
        return;
    }

    if (w->need_comma) {
        fputc(',', w->fp);
    }
    fputc('\n', w->fp);
    write_indent(w);
    w->need_comma = 1;
}

static void jw_escape_string(jw_t *w, const char *data, size_t len)
{
    fputc('"', w->fp);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        switch (c) {
            case '"':  fputs("\\\"", w->fp); break;
            case '\\': fputs("\\\\", w->fp); break;
            case '\b': fputs("\\b",  w->fp); break;
            case '\f': fputs("\\f",  w->fp); break;
            case '\n': fputs("\\n",  w->fp); break;
            case '\r': fputs("\\r",  w->fp); break;
            case '\t': fputs("\\t",  w->fp); break;
            default:
                if (c < 0x20) {
                    fprintf(w->fp, "\\u%04x", (unsigned)c);
                } else {
                    fputc((char)c, w->fp);
                }
                break;
        }
    }
    fputc('"', w->fp);
}


/* =========================================================================
 * Public API
 * ========================================================================= */

void jw_init(jw_t *w, FILE *fp)
{
    w->fp         = fp;
    w->depth      = 0;
    w->need_comma = 0;
    w->after_key  = 0;
    w->first_item = 1;  /* suppress leading newline for top-level value */
}

void jw_finish(jw_t *w)
{
    fputc('\n', w->fp);
    fflush(w->fp);
}

/* --- containers ---------------------------------------------------------- */

void jw_object_begin(jw_t *w)
{
    pre_value(w);
    fputc('{', w->fp);
    w->depth++;
    w->need_comma = 0;
}

void jw_object_end(jw_t *w)
{
    w->depth--;
    if (w->need_comma) {
        /* at least one member was written */
        fputc('\n', w->fp);
        write_indent(w);
    }
    fputc('}', w->fp);
    w->need_comma = 1;
    w->after_key  = 0;
}

void jw_array_begin(jw_t *w)
{
    pre_value(w);
    fputc('[', w->fp);
    w->depth++;
    w->need_comma = 0;
}

void jw_array_end(jw_t *w)
{
    w->depth--;
    if (w->need_comma) {
        fputc('\n', w->fp);
        write_indent(w);
    }
    fputc(']', w->fp);
    w->need_comma = 1;
    w->after_key  = 0;
}

/* --- object key ---------------------------------------------------------- */

void jw_key(jw_t *w, const char *key)
{
    /* Key acts like a value for separator purposes, then sets after_key */
    if (w->need_comma) {
        fputc(',', w->fp);
    }
    fputc('\n', w->fp);
    write_indent(w);
    jw_escape_string(w, key, strlen(key));
    fputc(':', w->fp);
    fputc(' ', w->fp);
    w->need_comma = 0;
    w->after_key  = 1;
}

/* --- scalar values ------------------------------------------------------- */

void jw_string(jw_t *w, const char *s)
{
    pre_value(w);
    if (s == NULL) {
        fputs("null", w->fp);
    } else {
        jw_escape_string(w, s, strlen(s));
    }
    w->need_comma = 1;
}

void jw_string_n(jw_t *w, const char *data, size_t len)
{
    pre_value(w);
    jw_escape_string(w, data, len);
    w->need_comma = 1;
}

void jw_str(jw_t *w, str_t s)
{
    pre_value(w);
    if (STR_IS_NULL(s)) {
        fputs("null", w->fp);
    } else {
        jw_escape_string(w, s.data, s.len);
    }
    w->need_comma = 1;
}

void jw_int(jw_t *w, int64_t v)
{
    pre_value(w);
    fprintf(w->fp, "%" PRId64, v);
    w->need_comma = 1;
}

void jw_uint(jw_t *w, uint64_t v)
{
    pre_value(w);
    fprintf(w->fp, "%" PRIu64, v);
    w->need_comma = 1;
}

void jw_bool(jw_t *w, int v)
{
    pre_value(w);
    fputs(v ? "true" : "false", w->fp);
    w->need_comma = 1;
}

void jw_null(jw_t *w)
{
    pre_value(w);
    fputs("null", w->fp);
    w->need_comma = 1;
}
