/*
 * include/tokenlint.h
 *
 * Foundational primitives for tokenlint v1.
 *
 * This header defines three types that everything else depends on:
 *
 *   str_t       — bounded string; no strlen() anywhere in evaluation code
 *   arena_t     — bump-pointer allocator; one arena per run, free once at exit
 *   tl_error_t  — halt condition (distinct from finding_t, which is data)
 *
 * Include order: this header has no dependencies on other tokenlint headers.
 * All other include/ headers may depend on this one.
 *
 * No vendor headers are included here. This header must remain safe to include
 * from any translation unit, including eval/ (which has no vendor include paths).
 *
 * C11 required. _Static_assert and <stdint.h> used throughout.
 */

#ifndef TOKENLINT_H
#define TOKENLINT_H

#include <stddef.h>   /* size_t                  */
#include <stdint.h>   /* uint8_t, int64_t, ...   */
#include <string.h>   /* memcmp()                */

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * Versioning
 * ========================================================================= */

#define TL_VERSION_MAJOR  0
#define TL_VERSION_MINOR  1
#define TL_VERSION_PATCH  0

/* Convenience: single integer for compile-time comparisons */
#define TL_VERSION \
    ((TL_VERSION_MAJOR) * 10000 + (TL_VERSION_MINOR) * 100 + (TL_VERSION_PATCH))


/* =========================================================================
 * Compiler portability
 * ========================================================================= */

#if defined(__GNUC__) || defined(__clang__)
#  define TL_NODISCARD   __attribute__((warn_unused_result))
#  define TL_NONNULL(...)  __attribute__((nonnull(__VA_ARGS__)))
#  define TL_PURE        __attribute__((pure))
#  define TL_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define TL_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#  define TL_NODISCARD
#  define TL_NONNULL(...)
#  define TL_PURE
#  define TL_LIKELY(x)   (x)
#  define TL_UNLIKELY(x) (x)
#endif

/* Silence unused-parameter warnings on stub implementations */
#define TL_UNUSED(x) ((void)(x))


/* =========================================================================
 * str_t — length-carrying string
 *
 * All strings in tokenlint are str_t. Raw char* only appears at I/O
 * boundaries (CLI argument ingestion, YAML parser output, JWT base64 input).
 * Once a string crosses the parse boundary it is a str_t for life.
 *
 * Invariants:
 *   - data points into an arena; it is never independently freed
 *   - if data == NULL then len MUST be 0 (STR_NULL)
 *   - data is NOT guaranteed to be NUL-terminated; never pass to printf("%s")
 *     without explicit length control (%.*s / (int)len / data)
 *
 * No strlen() in evaluation code. Ever.
 * ========================================================================= */

typedef struct {
    const char *data;   /* points into arena; not owned, not NUL-terminated */
    size_t      len;
} str_t;

/* Construct a null/empty str_t */
#define STR_NULL       ((str_t){ NULL, 0 })
#define STR_IS_NULL(s) ((s).data == NULL)
#define STR_IS_EMPTY(s) ((s).len == 0)

/*
 * STR_LIT — construct a str_t from a C string literal at compile time.
 * Safe only for true literals (not runtime char* variables).
 */
#define STR_LIT(literal) \
    ((str_t){ (literal), sizeof(literal) - 1 })

/*
 * STR_FROM_CSTR — construct a str_t from a runtime NUL-terminated string.
 * Calls strlen(); use only at parse/I/O boundaries, never in eval code.
 */
static inline str_t str_from_cstr(const char *s) {
    if (s == NULL) return STR_NULL;
    str_t r;
    r.data = s;
    r.len  = strlen(s);
    return r;
}

/* Equality — returns 1 if equal, 0 otherwise */
static inline TL_PURE int str_eq(str_t a, str_t b) {
    return a.len == b.len &&
           (a.len == 0 || memcmp(a.data, b.data, a.len) == 0);
}

/* Prefix test — returns 1 if s starts with prefix */
static inline TL_PURE int str_has_prefix(str_t s, str_t prefix) {
    return s.len >= prefix.len &&
           (prefix.len == 0 || memcmp(s.data, prefix.data, prefix.len) == 0);
}

/* True if s contains no characters (either null or zero-length) */
static inline TL_PURE int str_blank(str_t s) {
    return s.data == NULL || s.len == 0;
}

/* _Static_assert: str_t must not grow unexpectedly */
_Static_assert(sizeof(str_t) == sizeof(const char *) + sizeof(size_t),
    "str_t layout unexpected; check padding");


/* =========================================================================
 * arena_t — bump-pointer arena allocator
 *
 * All memory for a single tokenlint run is allocated from one arena.
 * Freeing the arena frees everything. No per-allocation free. No ownership
 * tracking. No destructor chains.
 *
 * Usage:
 *
 *   arena_t *a = arena_new(TL_ARENA_DEFAULT_SIZE);
 *   if (!a) { ... handle OOM at startup ... }
 *
 *   void *p = arena_alloc(a, 64, 8);  // 64 bytes, 8-byte aligned
 *   str_t *strings = arena_alloc(a, sizeof(str_t) * n, _Alignof(str_t));
 *
 *   arena_free(a);  // end of run — frees everything in one call
 *
 * arena_alloc() returns NULL only on overflow (arena exhausted).
 * Callers must check and propagate TL_ERR_INTERNAL on NULL return.
 *
 * Alignment: all sizes must be powers of two; behaviour is undefined otherwise.
 * ========================================================================= */

/* Recommended default: 4 MiB covers all known v1 workloads with headroom */
#define TL_ARENA_DEFAULT_SIZE  (4u * 1024u * 1024u)

/* Maximum single allocation (sanity guard; not a hard architectural limit) */
#define TL_ARENA_ALLOC_MAX     (TL_ARENA_DEFAULT_SIZE / 2u)

/* Opaque handle. Implementation in src/util/arena.c */
typedef struct tl_arena tl_arena_t;

/* arena_t is the public alias; tl_arena_t is the internal-prefixed form.
 * Both refer to the same opaque struct. Use arena_t in all interface code. */
typedef tl_arena_t arena_t;

/*
 * arena_new — create a new arena with capacity bytes of backing storage.
 * Returns NULL if the system cannot satisfy the allocation.
 * Must be called exactly once per run before any arena_alloc() calls.
 */
TL_NODISCARD
arena_t *arena_new(size_t capacity);

/*
 * arena_alloc — allocate size bytes aligned to align bytes from the arena.
 * align must be a power of two and >= 1.
 * Returns NULL if the arena is exhausted; caller must handle this.
 *
 * Memory is zero-initialized.
 */
TL_NODISCARD TL_NONNULL(1)
void *arena_alloc(arena_t *arena, size_t size, size_t align);

/*
 * arena_strdup — copy a str_t's bytes into the arena, returning a new str_t
 * whose data pointer lives in the arena.  The source data need not survive
 * this call.  Returns STR_NULL on arena exhaustion.
 */
TL_NODISCARD TL_NONNULL(1)
str_t arena_strdup(arena_t *arena, str_t s);

/*
 * arena_free — release all memory owned by the arena and the arena itself.
 * arena is invalid after this call; callers must not use it again.
 */
TL_NONNULL(1)
void arena_free(arena_t *arena);

/*
 * arena_used — bytes consumed so far (diagnostic / test helper).
 */
TL_PURE TL_NONNULL(1)
size_t arena_used(const arena_t *arena);

/*
 * arena_capacity — total bytes available (diagnostic / test helper).
 */
TL_PURE TL_NONNULL(1)
size_t arena_capacity(const arena_t *arena);

/*
 * Typed allocation helpers — prefer these over raw arena_alloc().
 *
 * ARENA_ALLOC_ONE(arena, type)
 *   → allocates sizeof(type) bytes, aligned to _Alignof(type)
 *   → returns (type *) or NULL
 *
 * ARENA_ALLOC_ARRAY(arena, type, count)
 *   → allocates sizeof(type) * count bytes, aligned to _Alignof(type)
 *   → returns (type *) or NULL
 *   → count == 0 returns NULL (not an error; callers must not dereference)
 */
#define ARENA_ALLOC_ONE(arena, type) \
    ((type *)arena_alloc((arena), sizeof(type), _Alignof(type)))

#define ARENA_ALLOC_ARRAY(arena, type, count) \
    ((count) == 0 ? NULL \
                  : (type *)arena_alloc((arena), \
                                        sizeof(type) * (size_t)(count), \
                                        _Alignof(type)))


/* =========================================================================
 * tl_error_t — halt condition
 *
 * A tl_error_t signals that the tool must stop. It is NOT a finding.
 *
 * Distinction:
 *   finding_t  — data produced by evaluation; collected, reported, output
 *   tl_error_t — halt condition; print and exit immediately
 *
 * Examples of errors (not findings):
 *   - Policy file not found or unreadable           → TL_ERR_IO
 *   - JWKS file has malformed JSON                  → TL_ERR_JWKS
 *   - --at flag value cannot be parsed              → TL_ERR_AT_FLAG
 *   - Arena exhausted                               → TL_ERR_INTERNAL
 *   - policy_t unexpectedly large (static_assert)   → compile-time, not runtime
 *
 * The happy path returns TL_OK from every function in the call chain.
 * Any non-OK error propagates up to main(), which emits the error envelope
 * and exits with code 3 (tool error).
 * ========================================================================= */

typedef enum {
    TL_ERR_NONE     = 0,  /* no error; operation succeeded          */
    TL_ERR_SCHEMA   = 1,  /* policy file fails schema validation    */
    TL_ERR_JWKS     = 2,  /* JWKS file unreadable or structurally   */
                          /*   invalid (not a finding-level error)  */
    TL_ERR_TOKEN    = 3,  /* token is structurally unparseable      */
                          /*   before we can even emit TL-V000      */
    TL_ERR_AT_FLAG  = 4,  /* --at value malformed                   */
    TL_ERR_IO       = 5,  /* file not found, unreadable, etc.       */
    TL_ERR_INTERNAL = 6   /* arena OOM, invariant violation, etc.   */
} tl_err_kind_t;

typedef struct {
    tl_err_kind_t kind;
    str_t         message;  /* human-readable; may be empty          */
    str_t         context;  /* e.g. filename, flag value; may be empty */
} tl_error_t;

/* The zero value — no error */
#define TL_OK ((tl_error_t){ TL_ERR_NONE, STR_NULL, STR_NULL })

/* Predicate — true if error is non-fatal (i.e. kind == TL_ERR_NONE) */
static inline int tl_ok(tl_error_t e) {
    return e.kind == TL_ERR_NONE;
}

/*
 * tl_error — construct a tl_error_t with a string literal message.
 * Intended for call sites that have a compile-time error string.
 *
 * Example:
 *   return tl_error(TL_ERR_IO, "policy file not found", path_str);
 */
static inline tl_error_t tl_error(tl_err_kind_t kind,
                                   const char   *message_lit,
                                   str_t         context) {
    tl_error_t e;
    e.kind    = kind;
    e.message = str_from_cstr(message_lit);
    e.context = context;
    return e;
}

/*
 * tl_error_str — construct a tl_error_t with a runtime str_t message.
 * Used when the message itself was built in the arena.
 */
static inline tl_error_t tl_error_str(tl_err_kind_t kind,
                                       str_t         message,
                                       str_t         context) {
    tl_error_t e;
    e.kind    = kind;
    e.message = message;
    e.context = context;
    return e;
}

/*
 * tl_error_internal — convenience for TL_ERR_INTERNAL with a literal message.
 * Typically arena OOM or an invariant violation.
 */
static inline tl_error_t tl_error_internal(const char *message_lit) {
    return tl_error(TL_ERR_INTERNAL, message_lit, STR_NULL);
}

/* _Static_assert: tl_err_kind_t fits in the expected range */
_Static_assert(TL_ERR_INTERNAL <= 127,
    "tl_err_kind_t values should fit in a signed byte for output encoding");


/* =========================================================================
 * Utility macros
 * ========================================================================= */

/*
 * TL_PROPAGATE — propagate a tl_error_t up the call stack if non-OK.
 * Use at the end of a statement that returns tl_error_t.
 *
 * Example:
 *   TL_PROPAGATE(policy_parse(arena, path, findings, &policy));
 */
#define TL_PROPAGATE(expr)                  \
    do {                                    \
        tl_error_t _tl_err = (expr);        \
        if (TL_UNLIKELY(!tl_ok(_tl_err)))   \
            return _tl_err;                 \
    } while (0)

/*
 * TL_RETURN_IF_NULL — return TL_ERR_INTERNAL if a pointer is NULL.
 * Typical use: arena allocation result check.
 *
 * Example:
 *   policy_t *p = ARENA_ALLOC_ONE(arena, policy_t);
 *   TL_RETURN_IF_NULL(p, "arena exhausted allocating policy_t");
 */
#define TL_RETURN_IF_NULL(ptr, msg_lit)                             \
    do {                                                            \
        if (TL_UNLIKELY((ptr) == NULL))                            \
            return tl_error_internal(msg_lit);                      \
    } while (0)

/*
 * TL_MB / TL_KB — size helpers for arena_new() call sites.
 */
#define TL_KB(n) ((size_t)(n) * 1024u)
#define TL_MB(n) ((size_t)(n) * 1024u * 1024u)


/* =========================================================================
 * Compile-time self-checks
 * ========================================================================= */

/* Platform requirements */
_Static_assert(sizeof(int)      >= 4, "int must be at least 32 bits");
_Static_assert(sizeof(size_t)   >= 4, "size_t must be at least 32 bits");
_Static_assert(sizeof(int64_t)  == 8, "int64_t must be 64 bits (time math)");
_Static_assert(sizeof(uint8_t)  == 1, "uint8_t must be 8 bits");

/* TL_ARENA_DEFAULT_SIZE must be a power of two */
_Static_assert((TL_ARENA_DEFAULT_SIZE & (TL_ARENA_DEFAULT_SIZE - 1u)) == 0u,
    "TL_ARENA_DEFAULT_SIZE must be a power of two");


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TOKENLINT_H */
