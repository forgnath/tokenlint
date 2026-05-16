/*
 * src/util/arena.c
 *
 * Bump-pointer arena allocator.
 *
 * Design:
 *   - Single malloc() at arena_new(); single free() at arena_free().
 *   - arena_alloc() advances a cursor with caller-specified alignment.
 *   - arena_reset() rewinds the cursor to zero without releasing memory.
 *   - Overflow is explicit: arena_alloc() returns NULL on exhaustion.
 *     Callers must check and propagate TL_ERR_INTERNAL on NULL return.
 *   - No thread safety. One arena per run; no shared state.
 *
 * Layout in memory (single malloc block):
 *
 *   [ struct tl_arena header | padding to max_align_t | user slab ... ]
 *
 * arena_free() is one free(arena) — the header and slab are co-located.
 *
 * Security:
 *   - arena_alloc() zero-initialises every returned region.
 *   - arena_reset() scrubs the used portion before rewinding.
 *   - arena_free() scrubs the used portion before freeing.
 *   Sensitive data (key material, claim values) must not persist in freed
 *   or reused memory regions.
 */

#include "tokenlint.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── internal struct ────────────────────────────────────────────────────── */

/*
 * The public header forward-declares this as 'struct tl_arena' (opaque).
 * We define the body here — no other translation unit sees the internals.
 */
struct tl_arena {
    size_t capacity;  /* bytes available for user allocations              */
    size_t used;      /* bytes consumed so far (bump cursor position)      */
    /*
     * The user slab follows immediately in memory after this header,
     * padded to _Alignof(max_align_t).  See arena_base() below.
     */
};

/* ── helpers ────────────────────────────────────────────────────────────── */

/*
 * Round x up to the next multiple of align.
 * align must be a power of two.
 */
static inline size_t round_up(size_t x, size_t align)
{
    return (x + (align - 1u)) & ~(align - 1u);
}

/*
 * Pointer to the first byte of user-accessible slab memory.
 * The slab starts right after the header, aligned to max_align_t so the
 * very first allocation is correctly aligned regardless of its type.
 */
static inline unsigned char *arena_base(arena_t *a)
{
    return (unsigned char *)a + round_up(sizeof(struct tl_arena),
                                         _Alignof(max_align_t));
}

/* ── public API ─────────────────────────────────────────────────────────── */

/*
 * arena_new — create a new arena with `capacity` bytes of backing storage.
 *
 * Returns NULL if the system cannot satisfy the allocation.
 * The total malloc size is header (padded) + capacity.
 */
arena_t *arena_new(size_t capacity)
{
    if (capacity == 0) {
        return NULL;
    }

    size_t header_size = round_up(sizeof(struct tl_arena),
                                  _Alignof(max_align_t));

    /* Overflow guard before adding */
    if (capacity > SIZE_MAX - header_size) {
        return NULL;
    }

    arena_t *a = malloc(header_size + capacity);
    if (!a) {
        return NULL;
    }

    a->capacity = capacity;
    a->used     = 0;

    return a;
}

/*
 * arena_alloc — allocate `size` bytes aligned to `align` bytes.
 *
 * align must be a power of two and >= 1.
 * Returns NULL if the arena is exhausted or size is 0.
 * Memory is zero-initialised.
 *
 * Callers must check for NULL and return TL_ERR_INTERNAL on failure.
 * Prefer the ARENA_ALLOC_ONE / ARENA_ALLOC_ARRAY macros from tokenlint.h.
 */
void *arena_alloc(arena_t *a, size_t size, size_t align)
{
    if (size == 0) {
        return NULL;
    }

    /* align must be at least 1; treat 0 as 1 defensively */
    if (align == 0) {
        align = 1;
    }

    /*
     * Advance cursor to satisfy requested alignment, then check whether
     * size bytes fit in the remaining capacity.
     */
    size_t cursor_aligned = round_up(a->used, align);

    /* Overflow guard: round_up can wrap if used is near SIZE_MAX */
    if (cursor_aligned < a->used) {
        return NULL;
    }

    /* Check size fits after alignment padding */
    if (size > a->capacity - cursor_aligned) {
        return NULL;
    }

    void *ptr = arena_base(a) + cursor_aligned;
    a->used   = cursor_aligned + size;

    /* Zero-initialise: no stale bytes visible to the caller */
    memset(ptr, 0, size);

    return ptr;
}

/*
 * arena_strdup — copy a str_t's bytes into the arena.
 *
 * Returns a new str_t whose data pointer lives in the arena.
 * The source data need not survive this call.
 * Returns STR_NULL on arena exhaustion or if s is null/empty.
 *
 * Note: the copy is NOT NUL-terminated (str_t invariant).
 */
str_t arena_strdup(arena_t *a, str_t s)
{
    if (STR_IS_NULL(s) || s.len == 0) {
        return STR_NULL;
    }

    char *buf = arena_alloc(a, s.len, _Alignof(char));
    if (!buf) {
        return STR_NULL;
    }

    memcpy(buf, s.data, s.len);

    str_t result;
    result.data = buf;
    result.len  = s.len;
    return result;
}

/*
 * arena_free — release all memory owned by the arena.
 *
 * Scrubs used slab bytes before freeing to prevent sensitive data from
 * persisting in freed heap blocks.
 *
 * Declared TL_NONNULL(1) in the header — do not pass NULL.
 */
void arena_free(arena_t *a)
{
    memset(arena_base(a), 0, a->used);
    free(a);
}

/*
 * arena_used — bytes consumed so far (diagnostic / test helper).
 *
 * Declared TL_NONNULL(1) in the header — do not pass NULL.
 */
size_t arena_used(const arena_t *a)
{
    return a->used;
}

/*
 * arena_capacity — total bytes available (diagnostic / test helper).
 *
 * Declared TL_NONNULL(1) in the header — do not pass NULL.
 */
size_t arena_capacity(const arena_t *a)
{
    return a->capacity;
}
