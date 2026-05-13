# Algorithm Contract — tokenlint v1

---

## Core principle

> The token declares its algorithm. The token never authorizes its algorithm.

Authorization requires **both**:
1. Algorithm appears in `accepts.algorithms` (policy check)
2. Algorithm is compatible with the matched JWKS key (key check)

These are independent checks with different failure modes and different remediation
paths. Passing one does not imply the other.

---

## Token evaluation order

```
Step 1: Parse JWT header
        header missing or unparseable
        → FAIL TL-V000, halt

Step 2: alg field presence
        alg field absent from header
        → FAIL TL-V001, halt

Step 3: alg=none check (non-suppressible)
        alg == "none" (case-insensitive)
        → FAIL TL-S001, halt
        No verification attempted. Ever.

Step 4: Algorithm recognition
        alg not in tokenlint v1 recognized set
        → FAIL TL-V002, halt

Step 5: Policy allowlist check
        alg not in accepts.algorithms
        → FAIL TL-V003
        Continue to key selection regardless —
        key incompatibility is a separate finding

Step 6: Key selection
        Execute JWKS kid resolution per JWKS contract
        Key selection failure → halt algorithm checks
        Key selection success → continue

Step 7: Key type compatibility check
        Check token alg against key kty/crv/use/key_ops
        Incompatible → FAIL TL-V004
        Continue to step 8 regardless

Step 8: Key alg field check
        If JWKS key has explicit alg field:
          token alg must exactly match
          mismatch → FAIL TL-V005
        If JWKS key has no alg field:
          skip, no finding

Step 9: Signature verification
        Only reached if steps 1-8 produced no FAIL
        Use exact algorithm named in token alg field
        Failure → FAIL TL-V006
        Success → continue to claim checks

Step 10: Emit all algorithm findings
         No short-circuit between steps 5-8
         All applicable findings emitted
```

---

## Recognized algorithm set

### Asymmetric — permitted

| String | Full name | Notes |
|---|---|---|
| `RS256` | RSASSA-PKCS1-v1_5 + SHA-256 | |
| `RS384` | RSASSA-PKCS1-v1_5 + SHA-384 | |
| `RS512` | RSASSA-PKCS1-v1_5 + SHA-512 | |
| `PS256` | RSASSA-PSS + SHA-256 | |
| `PS384` | RSASSA-PSS + SHA-384 | |
| `PS512` | RSASSA-PSS + SHA-512 | |
| `ES256` | ECDSA + P-256 | |
| `ES384` | ECDSA + P-384 | |
| `ES512` | ECDSA + P-521 | |
| `EdDSA` | Ed25519 / Ed448 | Ed25519 supported; Ed448: recognized but FAIL TL-V002 in v1 |

### Symmetric — conditionally permitted

| String | Full name | Notes |
|---|---|---|
| `HS256` | HMAC + SHA-256 | prod: FAIL TL-A005; non-prod: WARN |
| `HS384` | HMAC + SHA-384 | prod: FAIL TL-A005; non-prod: WARN |
| `HS512` | HMAC + SHA-512 | prod: FAIL TL-A005; non-prod: WARN |

### Explicitly forbidden

| String | Behavior |
|---|---|
| `none` | FAIL TL-S001 at token evaluation; FAIL TL-S002 if in policy. Non-suppressible. |

### Unknown strings

Any string not in the above tables: FAIL TL-V002 at token evaluation, FAIL TL-S010
if present in policy.

---

## Key compatibility matrix

### RS\* family (PKCS1-v1_5 padding)

Compatible key:
- `kty: RSA`
- `use: sig` (if present)
- `key_ops` containing `verify` (if present)

RS256, RS384, RS512 are **mutually exclusive by hash function**.  
RS256 does not authorize RS384 or RS512 tokens — hash function is part of the
algorithm declaration, not decoration.

**PS\* family is explicitly incompatible** even on an RSA key. Same `kty`, different
padding scheme.
- `RSASSA-PKCS1-v1_5` ≠ `RSASSA-PSS`

### PS\* family (PSS padding)

Compatible key:
- `kty: RSA`
- `use: sig` (if present)
- `key_ops` containing `verify` (if present)

PS256, PS384, PS512 are mutually exclusive by hash function.  
RS\* family explicitly incompatible even on RSA key.

**Distinguishing RS\* from PS\* when key has no `alg` field:**  
A JWKS key with `kty: RSA` and no `alg` field is structurally compatible with
both RS\* and PS\* families. The policy allowlist is the discriminator.

If both RS256 and PS256 are in `accepts.algorithms` and the key has no `alg` field:
both are structurally compatible. WARN TL-W016 (v2) emitted.

### ES\* family (ECDSA)

| Algorithm | Required curve |
|---|---|
| `ES256` | `crv: P-256` |
| `ES384` | `crv: P-384` |
| `ES512` | `crv: P-521` |

Curve mismatch: FAIL TL-V004. Curves are not interchangeable.  
`ES256` key does not authorize `ES384` token.

### EdDSA family

Compatible key:
- `kty: OKP`
- `crv: Ed25519` or `crv: Ed448`

Both curves permitted under EdDSA in the algorithm string.  
Ed448: recognized but FAIL TL-V002 in v1 (mbedTLS support limited).

### HS\* family (HMAC)

Compatible key:
- `kty: oct`

HS256, HS384, HS512 are mutually exclusive by hash function.  
`oct` key without `alg` field is structurally compatible with all HS\*.

### `use` field semantics

| Value | Behavior |
|---|---|
| `sig` | compatible with all signature algorithms |
| `enc` | FAIL TL-V004 — key use is 'enc', not 'sig' |
| absent | no finding, compatible assumed |

### `key_ops` field semantics

| Value | Behavior |
|---|---|
| contains `verify` | compatible |
| present, not containing `verify` | FAIL TL-V004 |
| absent | no finding, compatible assumed |

### `alg` field on JWKS key (hard constraint)

If the JWKS key entry has an explicit `alg` field, it is treated as a hard
constraint, not decoration.

Token `alg` must exactly match key `alg` (case-sensitive).  
Mismatch → FAIL TL-V005, regardless of `kty` compatibility.

Example:
```json
{ "kty": "RSA", "alg": "RS256" }
```
Token with `alg: PS256` → FAIL TL-V005:  
`"Token alg PS256 conflicts with key alg RS256"`

---

## Schema-time algorithm checks

These fire during `tokenlint audit` without any token:

| Condition | Finding |
|---|---|
| `none` in `accepts.algorithms` | FAIL TL-S002, non-suppressible |
| Unknown algorithm string in policy | FAIL TL-S010 |
| Empty `accepts.algorithms` | FAIL TL-S009 |
| `HS*` in `accepts.algorithms` + `environment: prod` | FAIL TL-A005 |
| `HS*` in `accepts.algorithms` + non-prod | WARN (v2) |

---

## Finding summary

| ID | Name | Halt? | Suppressible |
|---|---|---|---|
| TL-S001 | TOKEN_ALG_NONE | yes | No |
| TL-S002 | POLICY_ALG_NONE | yes | No |
| TL-S010 | ALG_UNRECOGNIZED (in policy) | yes | No |
| TL-A005 | POLICY_ALG_SYMMETRIC_PROD | no | Yes |
| TL-V001 | TOKEN_ALG_ABSENT | yes | No |
| TL-V002 | TOKEN_ALG_UNRECOGNIZED | yes | No |
| TL-V003 | TOKEN_ALG_NOT_ALLOWED | no | Yes |
| TL-V004 | TOKEN_ALG_KEY_INCOMPATIBLE | no | Yes |
| TL-V005 | TOKEN_ALG_KEY_ALG_CONFLICT | no | Yes |
| TL-V006 | TOKEN_SIG_INVALID | no | No |
