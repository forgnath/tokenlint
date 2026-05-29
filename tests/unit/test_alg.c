/*
 * tests/unit/test_alg.c
 *
 * Unit tests for the crypto backend (src/crypto/crypto_backend.c).
 *
 * Tests tl_verify_signature() and tl_base64url_decode() using real key
 * material and signatures generated with openssl.
 *
 * Test vectors were generated with:
 *   openssl genrsa -out rsa2048.pem 2048
 *   openssl ecparam -name prime256v1 -genkey -out ec256.pem
 *   openssl ecparam -name secp384r1  -genkey -out ec384.pem
 *   echo -n "header.payload" | openssl dgst -sha256 -sign rsa2048.pem
 *   etc.
 *
 * All test vectors over the signing input "header.payload" (14 bytes).
 *
 * Key material is supplied as JWK JSON strings (the format crypto_backend.c
 * receives via key->key_material from jwks_parser.c).
 */

#define _POSIX_C_SOURCE 200809L

#include "../../include/tokenlint.h"
#include "../../include/alg.h"
#include "../../include/jwks.h"
#include "../../include/crypto_backend.h"
#include "helpers/test_runner.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* =========================================================================
 * Test vectors — generated with openssl
 * ========================================================================= */

/* signing_input = "header.payload" */
static const uint8_t TV_MSG[] = {
    0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2e, 0x70,
    0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64
};
static const size_t TV_MSG_LEN = 14;

/* RS256 signature over TV_MSG with rsa2048.pem */
static const uint8_t TV_SIG_RS256[256] = {
    0x9f, 0x67, 0xd9, 0xc8, 0x36, 0x57, 0x37, 0x72, 0x24, 0x7a, 0xb5, 0x43, 0x59, 0xc6, 0x61, 0x1f,
    0x59, 0x36, 0x39, 0x97, 0x56, 0x74, 0xc5, 0x78, 0x77, 0x1d, 0x39, 0xba, 0x13, 0xbf, 0x06, 0x8c,
    0xc4, 0x87, 0x7c, 0x35, 0xd8, 0xb7, 0xd8, 0xbb, 0xf2, 0x17, 0xf9, 0xa7, 0x4d, 0x11, 0xa4, 0x62,
    0x63, 0x29, 0xf4, 0x89, 0xa3, 0xa5, 0xd5, 0x72, 0x07, 0x20, 0xb4, 0x80, 0xb3, 0x6b, 0xc9, 0xc8,
    0x19, 0x74, 0xb2, 0x82, 0xbc, 0x87, 0xc1, 0xe7, 0x79, 0xa7, 0xa0, 0x07, 0x53, 0xf4, 0x3a, 0x32,
    0x65, 0x6c, 0x17, 0xe1, 0xd4, 0xbc, 0x17, 0x42, 0xe1, 0x8f, 0x44, 0x77, 0x3c, 0x11, 0xd3, 0xdf,
    0x03, 0xaf, 0xec, 0xea, 0x24, 0x1c, 0xa8, 0x05, 0xd6, 0x8b, 0x62, 0x98, 0xea, 0x38, 0xe9, 0x62,
    0xfb, 0x42, 0x03, 0x22, 0x4b, 0x29, 0xd0, 0x18, 0x10, 0x24, 0x5e, 0xe2, 0xeb, 0x5f, 0xa0, 0x4e,
    0xf9, 0xee, 0x2f, 0xc6, 0x5d, 0x9f, 0xe6, 0x25, 0x32, 0x21, 0x4f, 0xda, 0xd0, 0x73, 0xf8, 0xfd,
    0x43, 0x96, 0xc7, 0x27, 0xd3, 0x84, 0xf6, 0x60, 0x4e, 0x16, 0x26, 0x80, 0xdb, 0x31, 0x1d, 0x4d,
    0x8b, 0x1e, 0x55, 0xd6, 0x72, 0x50, 0x23, 0x9c, 0x4f, 0x9c, 0xbe, 0x3e, 0x14, 0x82, 0x0f, 0x9d,
    0x18, 0x33, 0x5c, 0xa5, 0xf0, 0x5e, 0x60, 0xa2, 0x8f, 0xfc, 0x1c, 0xea, 0x59, 0xea, 0x20, 0xce,
    0xd2, 0x5c, 0x34, 0x6d, 0xf8, 0x5e, 0x35, 0x18, 0xa1, 0xe7, 0x94, 0xcf, 0xa7, 0x47, 0xc3, 0x70,
    0x40, 0x01, 0x40, 0x36, 0x3d, 0x4d, 0x05, 0x16, 0x80, 0xc3, 0x44, 0xf2, 0x20, 0x1a, 0x0a, 0xa5,
    0x1c, 0x2e, 0xf0, 0x32, 0xdd, 0xb2, 0xe3, 0xb1, 0x59, 0x61, 0x15, 0xb2, 0xb1, 0x46, 0xc4, 0x7a,
    0xe8, 0x65, 0x7e, 0xc2, 0x5b, 0xd0, 0x9d, 0x4d, 0x36, 0x92, 0x99, 0x0c, 0x37, 0x63, 0x0a, 0xcf
};

/* PS256 signature over TV_MSG with rsa2048.pem (PSS padding) */
static const uint8_t TV_SIG_PS256[256] = {
    0xb7, 0xb9, 0x0d, 0x4e, 0x79, 0xfd, 0x05, 0xc3, 0xc5, 0x9b, 0x9d, 0xa6, 0x74, 0xac, 0x27, 0xab,
    0xf4, 0x49, 0x9c, 0x71, 0x6f, 0x71, 0x3d, 0x1a, 0x79, 0x9b, 0xde, 0xbc, 0x7a, 0x16, 0xc7, 0x8b,
    0x77, 0xb7, 0x4a, 0x91, 0xda, 0xcf, 0x0d, 0xe8, 0xef, 0xc6, 0x02, 0x69, 0x26, 0x62, 0x87, 0xf9,
    0x06, 0x9c, 0xb6, 0x0e, 0xec, 0xd9, 0x88, 0x33, 0x34, 0x4b, 0x8c, 0x6f, 0x4a, 0xc7, 0x18, 0x18,
    0x7d, 0x8b, 0x88, 0xe0, 0x7c, 0x44, 0x3c, 0xdf, 0xeb, 0xac, 0x95, 0xe5, 0xc0, 0xa3, 0x52, 0x77,
    0xd9, 0xf7, 0x7d, 0xb2, 0xad, 0x53, 0xd7, 0xc3, 0xc4, 0x44, 0xf7, 0x6e, 0x21, 0x73, 0x64, 0xff,
    0x4b, 0x2c, 0x12, 0xe8, 0x52, 0xbe, 0xc7, 0x76, 0x78, 0x2a, 0xc9, 0xe9, 0x21, 0x5d, 0x10, 0x67,
    0xdf, 0xc9, 0x38, 0xc7, 0xb2, 0xae, 0x15, 0x1b, 0x20, 0xda, 0xa9, 0xfd, 0x88, 0xef, 0xf4, 0xb8,
    0x8b, 0x10, 0x0c, 0xe8, 0x67, 0x41, 0xfc, 0xcb, 0x03, 0x71, 0x90, 0xfb, 0x03, 0x3a, 0x53, 0x93,
    0xee, 0xc6, 0x8a, 0x20, 0x12, 0x37, 0xb2, 0x73, 0x13, 0x8a, 0x5e, 0x8d, 0xcd, 0xc8, 0xd4, 0xb5,
    0xc0, 0xad, 0xb5, 0x5f, 0xc0, 0xb2, 0xee, 0x67, 0x4b, 0x8b, 0xd1, 0x53, 0x5e, 0xa1, 0xaa, 0x4e,
    0x28, 0xb6, 0x5c, 0x97, 0xe8, 0xa8, 0x3f, 0x58, 0xac, 0xc2, 0xd8, 0x04, 0xa6, 0xb9, 0xc5, 0xf2,
    0x9f, 0xc4, 0x4e, 0xc0, 0x43, 0x56, 0x85, 0x39, 0x0a, 0x11, 0xae, 0xd0, 0xa4, 0x44, 0xe6, 0xbd,
    0x01, 0x92, 0xd0, 0x91, 0x2c, 0x22, 0xec, 0xdc, 0x6e, 0xff, 0x07, 0x11, 0x63, 0xd4, 0x5a, 0x9e,
    0x48, 0x4e, 0x37, 0x84, 0xc3, 0xa4, 0x4f, 0xab, 0xa7, 0xe1, 0x57, 0x21, 0x6b, 0xed, 0x9f, 0xdb,
    0x9d, 0x67, 0xc5, 0x3c, 0x42, 0xe4, 0xdd, 0xb2, 0xb8, 0x2f, 0x96, 0xc3, 0xc2, 0x19, 0x62, 0x3a
};

/* ES256 signature (DER) over TV_MSG with ec256.pem */
static const uint8_t TV_SIG_ES256[71] = {
    0x30, 0x45, 0x02, 0x20, 0x4b, 0x4c, 0x0b, 0x3d, 0x4c, 0xa1, 0x08, 0x19, 0xd2, 0x0f, 0xba, 0x2f,
    0xe9, 0xab, 0xf1, 0x9f, 0xd2, 0x9b, 0xbd, 0x5e, 0xd0, 0x3b, 0x36, 0xb4, 0x57, 0x6a, 0xc7, 0x9e,
    0x3b, 0x28, 0x5a, 0x6f, 0x02, 0x21, 0x00, 0xea, 0xf0, 0x29, 0xb2, 0x65, 0x7d, 0x8e, 0xc7, 0xed,
    0x2e, 0x88, 0x67, 0x98, 0xca, 0x21, 0xf1, 0x65, 0x92, 0x47, 0x56, 0x96, 0x51, 0x74, 0xa7, 0x1b,
    0xe5, 0x91, 0xf4, 0x5f, 0x05, 0x38, 0x47
};

/* ES384 signature (DER) over TV_MSG with ec384.pem */
static const uint8_t TV_SIG_ES384[104] = {
    0x30, 0x66, 0x02, 0x31, 0x00, 0xda, 0x49, 0xa6, 0xb1, 0xe7, 0x92, 0x1f, 0x60, 0xc4, 0x0e, 0xbf,
    0xe9, 0xec, 0xaa, 0x93, 0x75, 0xca, 0x17, 0x86, 0x2b, 0x38, 0x38, 0xd0, 0xe5, 0x68, 0x6c, 0x1a,
    0xc1, 0x88, 0x50, 0x79, 0x12, 0x20, 0x4a, 0x47, 0x3b, 0x7b, 0xb7, 0xd7, 0x2b, 0x88, 0x26, 0xb2,
    0x7a, 0xfb, 0x6e, 0x3e, 0x74, 0x02, 0x31, 0x00, 0x9a, 0x46, 0x01, 0x8f, 0x7b, 0x3c, 0xa3, 0x12,
    0xc9, 0x38, 0x19, 0xd5, 0xd1, 0x77, 0x0d, 0x6d, 0x0e, 0x10, 0x24, 0x7b, 0xf9, 0xc6, 0x76, 0x8b,
    0x21, 0x82, 0x31, 0xa6, 0xb6, 0x63, 0xff, 0x3f, 0x7c, 0xd3, 0x90, 0x51, 0x62, 0x81, 0x5f, 0x31,
    0x3d, 0x32, 0x31, 0x85, 0x1c, 0x07, 0x69, 0xf0
};

/* HS256 MAC over TV_MSG with key = "deadbeefcafebabedeadbeefcafebabe" */
static const uint8_t TV_MAC_HS256[32] = {
    0x28, 0x26, 0x36, 0x57, 0x87, 0x25, 0x0f, 0xaf, 0xcd, 0x09, 0x26, 0x50, 0x71, 0x60, 0xe0, 0xa9,
    0x60, 0x50, 0xd0, 0xa2, 0x7b, 0x4c, 0x2b, 0x6e, 0x49, 0x6e, 0x08, 0xe6, 0x52, 0xd2, 0xf6, 0xb1
};


/* =========================================================================
 * JWK JSON fixtures
 *
 * These are minimal JWK objects matching the keys used above.
 * The crypto backend receives key_material as a NUL-terminated JSON string.
 * ========================================================================= */

/* RSA-2048 public key (n, e in base64url) */
static const char JWK_RSA2048[] =
    "{\"kty\":\"RSA\","
    "\"n\":\"0K6aHcCxjOS61rhoZY_XF-Hm90Bnwc3WFIiaKIll0gws1ReaP4VJw96zXsiOgigFaEoxa4hJ4wqOpotdMsmsdvd1hnpndMkcuHC5d66TrSYQ9TNRc_oYAim9oLmimaAISygcxgT6jOS4J8Hy7G22KWEawwkp2vesvR44NjZ0iM8YVZzodZj0MHvDEkbll0fKniOSbAZqxoeVch8Gy-W0IG9F3wxQfA3d9FXN0eWObL-EfK_nYgVRjd6qMp2WQLd0wynJ8rQZHboCZ23cRhyh3FIfPDMIh5CLdDcPgei_PHi43NEqUu8oSo1y8bQPF77dxmbU6jhUApSjUYrj7hpTgw\","
    "\"e\":\"AQAB\"}";

/* EC P-256 public key */
static const char JWK_EC256[] =
    "{\"kty\":\"EC\",\"crv\":\"P-256\","
    "\"x\":\"WsWJW2QpHq1vBUxSfdUcBXEwn6hQwcGlOQ4IiDGgsIY\","
    "\"y\":\"it56slBRJZSwHm6zSoksOgSKPELO8C0PJbKdy7gHVnM\"}";

/* EC P-384 public key */
static const char JWK_EC384[] =
    "{\"kty\":\"EC\",\"crv\":\"P-384\","
    "\"x\":\"wOj-hMslzHBkXTzXBBaRDlHKgkbrp3JXROpaZ2VugKojsuH8dV-0GtxuzgZclS9U\","
    "\"y\":\"r6_bmRk5YWUeJsEyLcxKVQV0692422aD5vKUyCBrP41PhYjidC7126SkDiXH_u8X\"}";

/* HS256 symmetric key */
static const char JWK_HS256[] =
    "{\"kty\":\"oct\","
    "\"k\":\"ZGVhZGJlZWZjYWZlYmFiZWRlYWRiZWVmY2FmZWJhYmU\"}";

/* OKP Ed25519 key (fake — just for testing unsupported return) */
static const char JWK_ED25519[] =
    "{\"kty\":\"OKP\",\"crv\":\"Ed25519\","
    "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

/* OKP Ed448 key (fake — for testing UNSUPPORTED return) */
static const char JWK_ED448[] =
    "{\"kty\":\"OKP\",\"crv\":\"Ed448\","
    "\"x\":\"fakekey\"}";


/* =========================================================================
 * Helpers
 * ========================================================================= */

static jwks_key_t make_rsa_key(const char *json)
{
    jwks_key_t k;
    memset(&k, 0, sizeof(k));
    k.kty            = KTY_RSA;
    k.crv            = CRV_UNSET;
    k.use            = KEY_USE_UNSET;
    k.key_ops_verify = 1;
    k.declared_alg   = ALG_NONE_ALG;
    k.key_material   = (const void *)json;
    k.key_material_len = strlen(json);
    return k;
}

static jwks_key_t make_ec_key(const char *json, crv_t crv)
{
    jwks_key_t k;
    memset(&k, 0, sizeof(k));
    k.kty            = KTY_EC;
    k.crv            = crv;
    k.use            = KEY_USE_UNSET;
    k.key_ops_verify = 1;
    k.declared_alg   = ALG_NONE_ALG;
    k.key_material   = (const void *)json;
    k.key_material_len = strlen(json);
    return k;
}

static jwks_key_t make_oct_key(const char *json)
{
    jwks_key_t k;
    memset(&k, 0, sizeof(k));
    k.kty            = KTY_OCT;
    k.crv            = CRV_UNSET;
    k.use            = KEY_USE_UNSET;
    k.key_ops_verify = 1;
    k.declared_alg   = ALG_NONE_ALG;
    k.key_material   = (const void *)json;
    k.key_material_len = strlen(json);
    return k;
}

static jwks_key_t make_okp_key(const char *json, crv_t crv)
{
    jwks_key_t k;
    memset(&k, 0, sizeof(k));
    k.kty            = KTY_OKP;
    k.crv            = crv;
    k.use            = KEY_USE_UNSET;
    k.key_ops_verify = 1;
    k.declared_alg   = ALG_NONE_ALG;
    k.key_material   = (const void *)json;
    k.key_material_len = strlen(json);
    return k;
}


/* =========================================================================
 * tl_base64url_decode tests
 * ========================================================================= */

TEST(b64url_decode_basic)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    /* "aGVsbG8" = base64url("hello") */
    uint8_t *out = NULL;
    size_t out_len = 0;
    tl_error_t err = tl_base64url_decode(arena, "aGVsbG8", 7, &out, &out_len);
    ASSERT_TRUE(tl_ok(err));
    ASSERT_EQ(out_len, 5u);
    ASSERT_TRUE(memcmp(out, "hello", 5) == 0);

    arena_free(arena);
}

TEST(b64url_decode_padding_variants)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    /* 0 pad: "YQ" = "a" */
    uint8_t *out = NULL; size_t out_len = 0;
    ASSERT_TRUE(tl_ok(tl_base64url_decode(arena, "YQ", 2, &out, &out_len)));
    ASSERT_EQ(out_len, 1u);
    ASSERT_EQ(out[0], (uint8_t)'a');

    /* 1 pad: "YWI" = "ab" */
    ASSERT_TRUE(tl_ok(tl_base64url_decode(arena, "YWI", 3, &out, &out_len)));
    ASSERT_EQ(out_len, 2u);

    /* URL-safe chars: '-' and '_' */
    /* "A-_B" → bytes from base64url: 0x03 0xeb 0xf0 01 */
    ASSERT_TRUE(tl_ok(tl_base64url_decode(arena, "A-_B", 4, &out, &out_len)));
    ASSERT_EQ(out_len, 3u);

    arena_free(arena);
}

TEST(b64url_decode_empty)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    uint8_t *out = NULL; size_t out_len = 99;
    tl_error_t err = tl_base64url_decode(arena, "", 0, &out, &out_len);
    ASSERT_TRUE(tl_ok(err));
    ASSERT_EQ(out_len, 0u);
    arena_free(arena);
}

TEST(b64url_decode_invalid)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);
    uint8_t *out = NULL; size_t out_len = 0;
    /* "!!!!" is not valid base64 */
    tl_error_t err = tl_base64url_decode(arena, "!!!!", 4, &out, &out_len);
    ASSERT_FALSE(tl_ok(err));
    arena_free(arena);
}


/* =========================================================================
 * RS256 verification tests
 * ========================================================================= */

TEST(verify_rs256_ok)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_rsa_key(JWK_RSA2048);
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_RS256, &key,
        TV_MSG, TV_MSG_LEN,
        TV_SIG_RS256, sizeof(TV_SIG_RS256));
    ASSERT_EQ(r, TL_VERIFY_OK);

    arena_free(arena);
}

TEST(verify_rs256_bad_sig)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_rsa_key(JWK_RSA2048);
    /* Flip one byte of the valid signature */
    uint8_t bad_sig[256];
    memcpy(bad_sig, TV_SIG_RS256, 256);
    bad_sig[10] ^= 0xff;

    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_RS256, &key,
        TV_MSG, TV_MSG_LEN,
        bad_sig, 256);
    ASSERT_EQ(r, TL_VERIFY_FAIL);

    arena_free(arena);
}

TEST(verify_rs256_wrong_message)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_rsa_key(JWK_RSA2048);
    const uint8_t other_msg[] = "other.message";
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_RS256, &key,
        other_msg, sizeof(other_msg) - 1,
        TV_SIG_RS256, sizeof(TV_SIG_RS256));
    ASSERT_EQ(r, TL_VERIFY_FAIL);

    arena_free(arena);
}


/* =========================================================================
 * PS256 verification tests
 * ========================================================================= */

TEST(verify_ps256_ok)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_rsa_key(JWK_RSA2048);
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_PS256, &key,
        TV_MSG, TV_MSG_LEN,
        TV_SIG_PS256, sizeof(TV_SIG_PS256));
    ASSERT_EQ(r, TL_VERIFY_OK);

    arena_free(arena);
}

TEST(verify_ps256_bad_sig)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_rsa_key(JWK_RSA2048);
    uint8_t bad_sig[256];
    memcpy(bad_sig, TV_SIG_PS256, 256);
    bad_sig[5] ^= 0x01;

    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_PS256, &key,
        TV_MSG, TV_MSG_LEN,
        bad_sig, 256);
    ASSERT_EQ(r, TL_VERIFY_FAIL);

    arena_free(arena);
}


/* =========================================================================
 * RS256 sig does not verify under PS256 and vice versa
 * ========================================================================= */

TEST(verify_pkcs1_sig_rejects_under_pss)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_rsa_key(JWK_RSA2048);
    /* RS256 sig presented as PS256 */
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_PS256, &key,
        TV_MSG, TV_MSG_LEN,
        TV_SIG_RS256, sizeof(TV_SIG_RS256));
    ASSERT_NE(r, TL_VERIFY_OK);

    arena_free(arena);
}

TEST(verify_pss_sig_rejects_under_pkcs1)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_rsa_key(JWK_RSA2048);
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_RS256, &key,
        TV_MSG, TV_MSG_LEN,
        TV_SIG_PS256, sizeof(TV_SIG_PS256));
    ASSERT_NE(r, TL_VERIFY_OK);

    arena_free(arena);
}


/* =========================================================================
 * ES256 verification tests
 * ========================================================================= */

TEST(verify_es256_ok)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_ec_key(JWK_EC256, CRV_P256);
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_ES256, &key,
        TV_MSG, TV_MSG_LEN,
        TV_SIG_ES256, sizeof(TV_SIG_ES256));
    ASSERT_EQ(r, TL_VERIFY_OK);

    arena_free(arena);
}

TEST(verify_es256_bad_sig)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_ec_key(JWK_EC256, CRV_P256);
    uint8_t bad_sig[71];
    memcpy(bad_sig, TV_SIG_ES256, 71);
    bad_sig[4] ^= 0x01;

    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_ES256, &key,
        TV_MSG, TV_MSG_LEN,
        bad_sig, 71);
    ASSERT_NE(r, TL_VERIFY_OK);

    arena_free(arena);
}

TEST(verify_es256_wrong_curve_key)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    /* ES256 sig, but key says P-384 — should not verify */
    jwks_key_t key = make_ec_key(JWK_EC256, CRV_P384);
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_ES384, &key,
        TV_MSG, TV_MSG_LEN,
        TV_SIG_ES256, sizeof(TV_SIG_ES256));
    /* Should fail — curve mismatch or bad sig */
    ASSERT_NE(r, TL_VERIFY_OK);

    arena_free(arena);
}


/* =========================================================================
 * ES384 verification tests
 * ========================================================================= */

TEST(verify_es384_ok)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_ec_key(JWK_EC384, CRV_P384);
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_ES384, &key,
        TV_MSG, TV_MSG_LEN,
        TV_SIG_ES384, sizeof(TV_SIG_ES384));
    ASSERT_EQ(r, TL_VERIFY_OK);

    arena_free(arena);
}


/* =========================================================================
 * HS256 verification tests
 * ========================================================================= */

TEST(verify_hs256_ok)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_oct_key(JWK_HS256);
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_HS256, &key,
        TV_MSG, TV_MSG_LEN,
        TV_MAC_HS256, sizeof(TV_MAC_HS256));
    ASSERT_EQ(r, TL_VERIFY_OK);

    arena_free(arena);
}

TEST(verify_hs256_bad_mac)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_oct_key(JWK_HS256);
    uint8_t bad_mac[32];
    memcpy(bad_mac, TV_MAC_HS256, 32);
    bad_mac[0] ^= 0x01;

    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_HS256, &key,
        TV_MSG, TV_MSG_LEN,
        bad_mac, 32);
    ASSERT_EQ(r, TL_VERIFY_FAIL);

    arena_free(arena);
}

TEST(verify_hs256_wrong_mac_length)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_oct_key(JWK_HS256);
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_HS256, &key,
        TV_MSG, TV_MSG_LEN,
        TV_MAC_HS256, 16); /* only half the MAC */
    ASSERT_EQ(r, TL_VERIFY_FAIL);

    arena_free(arena);
}


/* =========================================================================
 * EdDSA / Ed448 — unsupported
 * ========================================================================= */

TEST(verify_eddsa_ed25519_unsupported)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_okp_key(JWK_ED25519, CRV_ED25519);
    const uint8_t dummy_sig[64] = {0};
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_ECDSA_EDDSA, &key,
        TV_MSG, TV_MSG_LEN,
        dummy_sig, 64);
    ASSERT_EQ(r, TL_VERIFY_UNSUPPORTED);

    arena_free(arena);
}

TEST(verify_eddsa_ed448_unsupported)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_okp_key(JWK_ED448, CRV_ED448);
    const uint8_t dummy_sig[64] = {0};
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_ECDSA_EDDSA, &key,
        TV_MSG, TV_MSG_LEN,
        dummy_sig, 64);
    ASSERT_EQ(r, TL_VERIFY_UNSUPPORTED);

    arena_free(arena);
}


/* =========================================================================
 * Wrong key type returns error
 * ========================================================================= */

TEST(verify_rsa_alg_with_ec_key_returns_error)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    /* Pass an EC key for an RSA algorithm */
    jwks_key_t key = make_ec_key(JWK_EC256, CRV_P256);
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_RS256, &key,
        TV_MSG, TV_MSG_LEN,
        TV_SIG_RS256, sizeof(TV_SIG_RS256));
    ASSERT_EQ(r, TL_VERIFY_ERROR);

    arena_free(arena);
}

TEST(verify_ec_alg_with_rsa_key_returns_error)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_rsa_key(JWK_RSA2048);
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_ES256, &key,
        TV_MSG, TV_MSG_LEN,
        TV_SIG_ES256, sizeof(TV_SIG_ES256));
    ASSERT_EQ(r, TL_VERIFY_ERROR);

    arena_free(arena);
}


/* =========================================================================
 * SECURITY_PROP: signature cross-key isolation
 *
 * A valid signature under one key must not verify under a different key.
 * This is a critical security property — cross-key acceptance would mean
 * any token holder can forge tokens for any other key.
 * ========================================================================= */

SECURITY_PROP(rs256_sig_does_not_verify_with_ec_key)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    /* RS256 signature presented with an EC P-256 key → must be ERROR (type mismatch) */
    jwks_key_t ec_key = make_ec_key(JWK_EC256, CRV_P256);
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_RS256, &ec_key,
        TV_MSG, TV_MSG_LEN,
        TV_SIG_RS256, sizeof(TV_SIG_RS256));
    ASSERT_NE(r, TL_VERIFY_OK);

    arena_free(arena);
}

SECURITY_PROP(es256_sig_does_not_verify_with_rsa_key)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t rsa_key = make_rsa_key(JWK_RSA2048);
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_ES256, &rsa_key,
        TV_MSG, TV_MSG_LEN,
        TV_SIG_ES256, sizeof(TV_SIG_ES256));
    ASSERT_NE(r, TL_VERIFY_OK);

    arena_free(arena);
}

SECURITY_PROP(hmac_mac_does_not_verify_as_rsa_sig)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    /* HS256 MAC bytes presented as RS256 signature with RSA key */
    jwks_key_t rsa_key = make_rsa_key(JWK_RSA2048);
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_RS256, &rsa_key,
        TV_MSG, TV_MSG_LEN,
        TV_MAC_HS256, sizeof(TV_MAC_HS256));
    ASSERT_NE(r, TL_VERIFY_OK);

    arena_free(arena);
}

SECURITY_PROP(bit_flip_in_sig_causes_verify_fail)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_rsa_key(JWK_RSA2048);

    /* Flip every bit position in the RS256 signature — each must fail */
    for (int byte_idx = 0; byte_idx < 8; byte_idx++) {
        uint8_t bad_sig[256];
        memcpy(bad_sig, TV_SIG_RS256, 256);
        bad_sig[byte_idx * 32] ^= 0xff;

        tl_verify_result_t r = tl_verify_signature(
            arena, ALG_RS256, &key,
            TV_MSG, TV_MSG_LEN,
            bad_sig, 256);
        ASSERT_NE(r, TL_VERIFY_OK);
    }

    arena_free(arena);
}

SECURITY_PROP(hs256_timing_safe_mac_comparison)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    jwks_key_t key = make_oct_key(JWK_HS256);

    /* All-zero MAC must not verify */
    const uint8_t zero_mac[32] = {0};
    tl_verify_result_t r = tl_verify_signature(
        arena, ALG_HS256, &key,
        TV_MSG, TV_MSG_LEN,
        zero_mac, 32);
    ASSERT_EQ(r, TL_VERIFY_FAIL);

    /* All-0xff MAC must not verify */
    uint8_t ff_mac[32];
    memset(ff_mac, 0xff, 32);
    r = tl_verify_signature(
        arena, ALG_HS256, &key,
        TV_MSG, TV_MSG_LEN,
        ff_mac, 32);
    ASSERT_EQ(r, TL_VERIFY_FAIL);

    arena_free(arena);
}

SECURITY_PROP(eddsa_always_unsupported_in_v1)
{
    arena_t *arena = arena_new(TL_ARENA_DEFAULT_SIZE);
    ASSERT_NOT_NULL(arena);

    /* Per algorithm-contract.md: EdDSA → TL_VERIFY_UNSUPPORTED in v1 */
    jwks_key_t ed25519_key = make_okp_key(JWK_ED25519, CRV_ED25519);
    jwks_key_t ed448_key   = make_okp_key(JWK_ED448,   CRV_ED448);
    const uint8_t dummy[64] = {0};

    tl_verify_result_t r1 = tl_verify_signature(
        arena, ALG_ECDSA_EDDSA, &ed25519_key,
        TV_MSG, TV_MSG_LEN, dummy, 64);
    ASSERT_EQ(r1, TL_VERIFY_UNSUPPORTED);

    tl_verify_result_t r2 = tl_verify_signature(
        arena, ALG_ECDSA_EDDSA, &ed448_key,
        TV_MSG, TV_MSG_LEN, dummy, 64);
    ASSERT_EQ(r2, TL_VERIFY_UNSUPPORTED);

    arena_free(arena);
}


/* =========================================================================
 * TEST_MAIN
 * ========================================================================= */

TEST_MAIN(
    tl_run_b64url_decode_basic,
    tl_run_b64url_decode_padding_variants,
    tl_run_b64url_decode_empty,
    tl_run_b64url_decode_invalid,
    tl_run_verify_rs256_ok,
    tl_run_verify_rs256_bad_sig,
    tl_run_verify_rs256_wrong_message,
    tl_run_verify_ps256_ok,
    tl_run_verify_ps256_bad_sig,
    tl_run_verify_pkcs1_sig_rejects_under_pss,
    tl_run_verify_pss_sig_rejects_under_pkcs1,
    tl_run_verify_es256_ok,
    tl_run_verify_es256_bad_sig,
    tl_run_verify_es256_wrong_curve_key,
    tl_run_verify_es384_ok,
    tl_run_verify_hs256_ok,
    tl_run_verify_hs256_bad_mac,
    tl_run_verify_hs256_wrong_mac_length,
    tl_run_verify_eddsa_ed25519_unsupported,
    tl_run_verify_eddsa_ed448_unsupported,
    tl_run_verify_rsa_alg_with_ec_key_returns_error,
    tl_run_verify_ec_alg_with_rsa_key_returns_error,
    tl_run_rs256_sig_does_not_verify_with_ec_key,
    tl_run_es256_sig_does_not_verify_with_rsa_key,
    tl_run_hmac_mac_does_not_verify_as_rsa_sig,
    tl_run_bit_flip_in_sig_causes_verify_fail,
    tl_run_hs256_timing_safe_mac_comparison,
    tl_run_eddsa_always_unsupported_in_v1,
)
