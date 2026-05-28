/*
 * include/json_writer.h
 *
 * Low-level JSON writer for tokenlint.
 *
 * jw_t is a stateful writer that emits pretty-printed JSON to a FILE*.
 * Two-space indent per nesting level. Correct comma placement.
 * All string values are escaped through jw_escape_string().
 *
 * Usage:
 *   jw_t w;
 *   jw_init(&w, stdout);
 *   jw_object_begin(&w);
 *     jw_key(&w, "version"); jw_string(&w, "0.1.0");
 *     jw_key(&w, "count");   jw_int(&w, 3);
 *   jw_object_end(&w);
 *   jw_finish(&w);
 *
 * Dependencies: tokenlint.h (str_t), <stdio.h>
 * C11 required.
 */

#ifndef TOKENLINT_JSON_WRITER_H
#define TOKENLINT_JSON_WRITER_H

#include "tokenlint.h"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * jw_t — JSON writer state
 * ========================================================================= */

typedef struct {
    FILE *fp;
    int   depth;
    int   need_comma;  /* 1 if a comma must precede the next sibling value */
    int   after_key;   /* 1 if we just wrote a key — value follows inline  */
    int   first_item;  /* 1 if no value written yet (suppresses leading \n) */
} jw_t;


/* =========================================================================
 * Lifecycle
 * ========================================================================= */

/* jw_init — initialise a writer pointing at fp.  fp must remain open. */
void jw_init(jw_t *w, FILE *fp);

/* jw_finish — write trailing newline and flush.  Call once at end. */
void jw_finish(jw_t *w);


/* =========================================================================
 * Container operations
 * ========================================================================= */

void jw_object_begin(jw_t *w);
void jw_object_end(jw_t *w);
void jw_array_begin(jw_t *w);
void jw_array_end(jw_t *w);


/* =========================================================================
 * Object key
 *
 * Call jw_key() immediately before a value when inside an object.
 * ========================================================================= */

void jw_key(jw_t *w, const char *key);


/* =========================================================================
 * Scalar values
 * ========================================================================= */

/* jw_string — write a NUL-terminated string value. NULL writes JSON null. */
void jw_string(jw_t *w, const char *s);

/* jw_string_n — write a length-bounded string value. */
void jw_string_n(jw_t *w, const char *data, size_t len);

/* jw_str — write a str_t value. STR_NULL writes JSON null. */
void jw_str(jw_t *w, str_t s);

/* jw_int — write a signed 64-bit integer. */
void jw_int(jw_t *w, int64_t v);

/* jw_uint — write an unsigned 64-bit integer. */
void jw_uint(jw_t *w, uint64_t v);

/* jw_bool — write true or false. */
void jw_bool(jw_t *w, int v);

/* jw_null — write null. */
void jw_null(jw_t *w);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKENLINT_JSON_WRITER_H */
