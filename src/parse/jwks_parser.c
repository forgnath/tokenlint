/*
 * src/parse/jwks_parser.c
 *
 * JWKS JSON → jwks_t.
 *
 * Loads and validates a JWKS file, producing a frozen jwks_t.
 * This is the only file that reads JWKS JSON (hand-rolled parser — no
 * additional JSON library dependency).
 *
 * After this file, all evaluation code works exclusively against jwks_t.
 * Key material bytes are stored opaquely for the crypto backend.
 *
 * Structural validation per jwks-contract.md:
 *   Missing `keys` array → TL_ERR_JWKS
 *   Empty keyset         → TL_ERR_JWKS
 *   Malformed key entry  → TL_ERR_JWKS
 *   File unreadable      → TL_ERR_JWKS
 *
 * Key normalization:
 *   kty  → kty_t enum
 *   crv  → crv_t enum
 *   use  → key_use_t enum
 *   alg  → alg_id_t (ALG_NONE_ALG if absent)
 *   kid  → str_t (STR_NULL if absent)
 *   key_ops → key_ops_verify int (1 if contains "verify", 0 otherwise)
 *   Key material fields (n, e, x, y, d, k) stored as raw base64url str_t
 *   for the crypto backend to decode on demand.
 */

#define _POSIX_C_SOURCE 200809L

#include "tokenlint.h"
#include "str.h"
#include "alg.h"
#include "jwks.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ── minimal JSON extractor (shared logic from token_parser, duplicated here
 *    to keep the two parse files self-contained) ──────────────────────────── */

static size_t jws(const char *s, size_t i, size_t n) {
    while (i < n && (s[i]==' '||s[i]=='\t'||s[i]=='\r'||s[i]=='\n')) i++;
    return i;
}

static size_t jstr(const char *s, size_t i, size_t n,
                    char *buf, size_t cap, size_t *lenout) {
    if (i >= n || s[i] != '"') return (size_t)-1;
    i++;
    size_t out = 0;
    while (i < n && s[i] != '"') {
        char ch;
        if (s[i] == '\\') {
            i++;
            if (i >= n) return (size_t)-1;
            switch (s[i]) {
                case '"': ch='"'; break; case '\\': ch='\\'; break;
                case '/': ch='/'; break; case 'n':  ch='\n'; break;
                case 'r': ch='\r'; break; case 't':  ch='\t'; break;
                default:  ch=s[i]; break;
            }
        } else { ch = s[i]; }
        if (buf && out+1 < cap) buf[out] = ch;
        out++; i++;
    }
    if (i >= n) return (size_t)-1;
    if (buf && out < cap) buf[out] = '\0';
    if (lenout) *lenout = out;
    return i+1;
}

static size_t jskip(const char *s, size_t i, size_t n) {
    i = jws(s, i, n);
    if (i >= n) return (size_t)-1;
    if (s[i] == '"') { char t[4096]; return jstr(s,i,n,t,sizeof t,NULL); }
    if (s[i] == '{' || s[i] == '[') {
        char open=s[i], close=(s[i]=='{')?'}':']';
        int depth=1; i++;
        while (i < n && depth > 0) {
            if (s[i]==open) depth++;
            else if (s[i]==close) depth--;
            else if (s[i]=='"') {
                char t[4096]; size_t ni=jstr(s,i,n,t,sizeof t,NULL);
                if (ni==(size_t)-1) return (size_t)-1;
                i=ni; continue;
            }
            i++;
        }
        return i;
    }
    while (i<n && s[i]!=',' && s[i]!='}' && s[i]!=']' &&
           s[i]!=' '&& s[i]!='\t'&&s[i]!='\r'&&s[i]!='\n') i++;
    return i;
}

/* Get a string field from a JSON object starting at json[0].
 * Returns 1 on success. */
static int jget_str(const char *json, size_t jlen, const char *key,
                     char *vbuf, size_t vcap, size_t *vlen) {
    size_t klen = strlen(key);
    size_t i = jws(json, 0, jlen);
    if (i >= jlen || json[i] != '{') return 0;
    i++;
    while (i < jlen) {
        i = jws(json, i, jlen);
        if (i >= jlen || json[i] == '}') break;
        if (json[i] == ',') { i++; continue; }
        char kbuf[256]; size_t kl=0;
        size_t ni = jstr(json, i, jlen, kbuf, sizeof kbuf, &kl);
        if (ni == (size_t)-1) return 0;
        i = ni;
        i = jws(json, i, jlen);
        if (i >= jlen || json[i] != ':') return 0;
        i++;
        i = jws(json, i, jlen);
        if (kl == klen && memcmp(kbuf, key, kl) == 0) {
            if (i >= jlen || json[i] != '"') return 0;
            ni = jstr(json, i, jlen, vbuf, vcap, vlen);
            return ni != (size_t)-1 ? 1 : 0;
        }
        size_t sk = jskip(json, i, jlen);
        if (sk == (size_t)-1) return 0;
        i = sk;
    }
    return 0;
}

/* Find the "keys" array in the top-level JSON object.
 * Returns pointer to '[' and sets *arr_len to the length of the array content. */
static const char *find_keys_array(const char *json, size_t jlen,
                                    size_t *arr_start_out, size_t *arr_end_out) {
    size_t i = jws(json, 0, jlen);
    if (i >= jlen || json[i] != '{') return NULL;
    i++;
    while (i < jlen) {
        i = jws(json, i, jlen);
        if (i >= jlen || json[i] == '}') break;
        if (json[i] == ',') { i++; continue; }
        char kbuf[64]; size_t kl=0;
        size_t ni = jstr(json, i, jlen, kbuf, sizeof kbuf, &kl);
        if (ni == (size_t)-1) return NULL;
        i = ni;
        i = jws(json, i, jlen);
        if (i >= jlen || json[i] != ':') return NULL;
        i++;
        i = jws(json, i, jlen);
        if (kl == 4 && memcmp(kbuf, "keys", 4) == 0) {
            if (i >= jlen || json[i] != '[') return NULL;
            *arr_start_out = i;
            size_t end = jskip(json, i, jlen);
            if (end == (size_t)-1) return NULL;
            *arr_end_out = end;
            return json + i;
        }
        size_t sk = jskip(json, i, jlen);
        if (sk == (size_t)-1) return NULL;
        i = sk;
    }
    return NULL;
}

/* ── enum parsers ────────────────────────────────────────────────────────── */

static kty_t kty_from_str(const char *s) {
    if (!s) return KTY_UNKNOWN;
    if (strcmp(s, "RSA") == 0) return KTY_RSA;
    if (strcmp(s, "EC")  == 0) return KTY_EC;
    if (strcmp(s, "OKP") == 0) return KTY_OKP;
    if (strcmp(s, "oct") == 0) return KTY_OCT;
    return KTY_UNKNOWN;
}

static crv_t crv_from_str(const char *s) {
    if (!s) return CRV_UNSET;
    if (strcmp(s, "P-256")   == 0) return CRV_P256;
    if (strcmp(s, "P-384")   == 0) return CRV_P384;
    if (strcmp(s, "P-521")   == 0) return CRV_P521;
    if (strcmp(s, "Ed25519") == 0) return CRV_ED25519;
    if (strcmp(s, "Ed448")   == 0) return CRV_ED448;
    return CRV_UNSET;
}

static key_use_t use_from_str(const char *s) {
    if (!s) return KEY_USE_UNSET;
    if (strcmp(s, "sig") == 0) return KEY_USE_SIG;
    if (strcmp(s, "enc") == 0) return KEY_USE_ENC;
    return KEY_USE_UNSET;
}

static alg_id_t key_alg_from_str(const char *s) {
    if (!s) return ALG_NONE_ALG;
    static const struct { const char *name; alg_id_t id; } map[] = {
        {"RS256",ALG_RS256},{"RS384",ALG_RS384},{"RS512",ALG_RS512},
        {"PS256",ALG_PS256},{"PS384",ALG_PS384},{"PS512",ALG_PS512},
        {"ES256",ALG_ES256},{"ES384",ALG_ES384},{"ES512",ALG_ES512},
        {"EdDSA",ALG_ECDSA_EDDSA},
        {"HS256",ALG_HS256},{"HS384",ALG_HS384},{"HS512",ALG_HS512},
    };
    for (size_t i = 0; i < sizeof(map)/sizeof(map[0]); i++)
        if (strcmp(map[i].name, s) == 0) return map[i].id;
    return ALG_NONE_ALG;
}

/* Parse key_ops array — look for "verify". */
static int parse_key_ops(const char *json, size_t jlen) {
    /* key_ops is an array of strings */
    size_t i = jws(json, 0, jlen);
    if (i >= jlen || json[i] != '[') return 0;
    i++;
    while (i < jlen && json[i] != ']') {
        i = jws(json, i, jlen);
        if (i >= jlen || json[i] == ']') break;
        if (json[i] == ',') { i++; continue; }
        char vbuf[64]; size_t vlen = 0;
        size_t ni = jstr(json, i, jlen, vbuf, sizeof vbuf, &vlen);
        if (ni == (size_t)-1) break;
        if (vlen == 6 && memcmp(vbuf, "verify", 6) == 0) return 1;
        i = ni;
    }
    return 0;
}

/* Find key_ops array in a key entry JSON object and check for "verify". */
static int key_ops_has_verify(const char *key_json, size_t klen) {
    /* Walk the key object and find key_ops */
    size_t i = jws(key_json, 0, klen);
    if (i >= klen || key_json[i] != '{') return 0;
    i++;
    while (i < klen) {
        i = jws(key_json, i, klen);
        if (i >= klen || key_json[i] == '}') break;
        if (key_json[i] == ',') { i++; continue; }
        char kbuf[64]; size_t kl = 0;
        size_t ni = jstr(key_json, i, klen, kbuf, sizeof kbuf, &kl);
        if (ni == (size_t)-1) return 0;
        i = ni;
        i = jws(key_json, i, klen);
        if (i >= klen || key_json[i] != ':') return 0;
        i++;
        i = jws(key_json, i, klen);
        if (kl == 7 && memcmp(kbuf, "key_ops", 7) == 0) {
            /* Found key_ops — check its value */
            if (i >= klen || key_json[i] != '[') return 0;
            size_t arr_end = jskip(key_json, i, klen);
            if (arr_end == (size_t)-1) return 0;
            return parse_key_ops(key_json + i, arr_end - i);
        }
        size_t sk = jskip(key_json, i, klen);
        if (sk == (size_t)-1) return 0;
        i = sk;
    }
    return 0; /* key_ops absent → 0 (no restriction) */
}

/* ── parse a single key entry ────────────────────────────────────────────── */

static int parse_key_entry(arena_t *arena,
                             const char *key_json, size_t klen,
                             jwks_key_t *out)
{
    memset(out, 0, sizeof *out);

    char vbuf[2048]; size_t vlen = 0;

    /* kty — required */
    if (!jget_str(key_json, klen, "kty", vbuf, sizeof vbuf, &vlen))
        return 0; /* malformed entry */
    out->kty = kty_from_str(vbuf);

    /* crv — optional */
    if (jget_str(key_json, klen, "crv", vbuf, sizeof vbuf, &vlen))
        out->crv = crv_from_str(vbuf);

    /* use — optional */
    if (jget_str(key_json, klen, "use", vbuf, sizeof vbuf, &vlen))
        out->use = use_from_str(vbuf);

    /* alg — optional (key constraint) */
    if (jget_str(key_json, klen, "alg", vbuf, sizeof vbuf, &vlen))
        out->declared_alg = key_alg_from_str(vbuf);

    /* kid — optional */
    if (jget_str(key_json, klen, "kid", vbuf, sizeof vbuf, &vlen))
        out->kid = arena_strdup(arena, (str_t){ vbuf, vlen });

    /* key_ops — pre-resolved */
    out->key_ops_verify = key_ops_has_verify(key_json, klen);

    /* Key material fields — stored as arena str_t (raw base64url) */
    /* These are passed to the crypto backend; we just copy the bytes */
    static const char * const MAT_FIELDS[] = {
        "n","e","d","p","q","dp","dq","qi",  /* RSA */
        "x","y",                              /* EC/OKP */
        "k",                                  /* oct */
    };
    size_t total_mat = 0;
    for (size_t fi = 0; fi < sizeof(MAT_FIELDS)/sizeof(MAT_FIELDS[0]); fi++) {
        if (jget_str(key_json, klen, MAT_FIELDS[fi], vbuf, sizeof vbuf, &vlen))
            total_mat += vlen;
    }

    /* Store key material as a small struct in the arena.
     * For the crypto backend, we store the full key entry JSON so it can
     * use mbedTLS to import the key directly. */
    char *mat = (char *)arena_alloc(arena, klen + 1, 1);
    if (!mat) return 0;
    memcpy(mat, key_json, klen);
    mat[klen] = '\0';
    out->key_material     = (const uint8_t *)mat;
    out->key_material_len = klen;

    TL_UNUSED(total_mat);
    return 1;
}

/* ── jwks_load ───────────────────────────────────────────────────────────── */

tl_error_t jwks_load(arena_t       *arena,
                      const char    *path,
                      finding_set_t *fs,
                      jwks_t       **out)
{
    TL_UNUSED(fs); /* findings reserved for future structural warnings */

    /* ── Read file ── */
    FILE *f = fopen(path, "r");
    if (!f)
        return tl_error(TL_ERR_JWKS, "JWKS file not found or unreadable",
                         str_from_cstr(path));

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f);
        return tl_error(TL_ERR_JWKS, "JWKS fseek failed", str_from_cstr(path)); }
    long fsz = ftell(f);
    if (fsz < 0 || fsz > (long)TL_ARENA_ALLOC_MAX) {
        fclose(f);
        return tl_error(TL_ERR_JWKS, "JWKS file too large", str_from_cstr(path));
    }
    rewind(f);

    char *buf = (char *)arena_alloc(arena, (size_t)fsz + 1, 1);
    if (!buf) { fclose(f); return tl_error_internal("arena OOM for JWKS file"); }

    size_t nread = fread(buf, 1, (size_t)fsz, f);
    fclose(f);
    buf[nread] = '\0';

    /* ── Find "keys" array ── */
    size_t arr_start = 0, arr_end = 0;
    const char *arr = find_keys_array(buf, nread, &arr_start, &arr_end);
    if (!arr)
        return tl_error(TL_ERR_JWKS, "JWKS missing 'keys' array",
                         str_from_cstr(path));

    const char *keys_json = buf + arr_start;
    size_t keys_len = arr_end - arr_start;

    /* ── Count key entries ── */
    size_t key_count = 0;
    {
        size_t i = 1; /* skip '[' */
        while (i < keys_len && keys_json[i] != ']') {
            i = jws(keys_json, i, keys_len);
            if (i >= keys_len || keys_json[i] == ']') break;
            if (keys_json[i] == ',') { i++; continue; }
            if (keys_json[i] != '{')
                return tl_error(TL_ERR_JWKS, "JWKS key entry is not an object",
                                 str_from_cstr(path));
            size_t sk = jskip(keys_json, i, keys_len);
            if (sk == (size_t)-1)
                return tl_error(TL_ERR_JWKS, "JWKS malformed key entry",
                                 str_from_cstr(path));
            i = sk;
            key_count++;
        }
    }

    if (key_count == 0)
        return tl_error(TL_ERR_JWKS, "JWKS 'keys' array is empty",
                         str_from_cstr(path));

    /* ── Allocate jwks_t and key array ── */
    jwks_t *jwks = ARENA_ALLOC_ONE(arena, jwks_t);
    TL_RETURN_IF_NULL(jwks, "arena OOM for jwks_t");

    jwks->keys = ARENA_ALLOC_ARRAY(arena, jwks_key_t, key_count);
    TL_RETURN_IF_NULL(jwks->keys, "arena OOM for jwks keys");

    /* ── Parse each key entry ── */
    {
        size_t i = 1; /* skip '[' */
        while (i < keys_len && keys_json[i] != ']') {
            i = jws(keys_json, i, keys_len);
            if (i >= keys_len || keys_json[i] == ']') break;
            if (keys_json[i] == ',') { i++; continue; }

            /* Find the end of this entry */
            size_t entry_start = i;
            size_t entry_end   = jskip(keys_json, i, keys_len);
            if (entry_end == (size_t)-1)
                return tl_error(TL_ERR_JWKS, "JWKS malformed key entry",
                                 str_from_cstr(path));

            const char *entry_json = keys_json + entry_start;
            size_t entry_len       = entry_end - entry_start;

            if (!parse_key_entry(arena, entry_json, entry_len,
                                   &jwks->keys[jwks->count]))
                return tl_error(TL_ERR_JWKS, "JWKS key entry missing required field",
                                 str_from_cstr(path));

            jwks->count++;
            i = entry_end;
        }
    }

    *out = jwks;
    return TL_OK;
}
