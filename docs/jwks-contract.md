# JWKS Contract — tokenlint v1

---

## Core principle

The JWKS file is loaded once at startup and treated as a static snapshot for the
entire duration of execution. No reload, no rotation, no mid-run mutation.

This guarantees:
- **Reproducibility**: same command produces same output regardless of when it runs
- **Forensic integrity**: the keyset used for evaluation is fixed and known
- **No race conditions**: rotating keys on disk cannot affect an in-progress run

---

## Load behavior

```
1. Load JWKS from jwks.source path at startup
2. Validate JWKS structure before any token processing
3. Freeze keyset in memory for duration of execution
4. No reload during run
5. No rotation during run
```

### Structural validation

| Condition | Finding |
|---|---|
| Missing `keys` array | FAIL TL-S010 |
| Malformed key entry | FAIL TL-S011 |
| Empty keyset (`keys: []`) | FAIL TL-S012 |
| File unreadable | FAIL TL-S013, halt immediately |

### Source contract

- Local file path only in v1
- No URL fetching (air-gapped first)
- Relative paths resolved from CWD at invocation time
- URLs: FAIL TL-S011 at schema parse time

---

## `require_kid` semantics

`require_kid` is a precise security control, not an advisory flag.

### `require_kid: true`

```
Token has kid:
  Find key in JWKS where kid matches exactly (string equality)
  No match → FAIL TL-V010
  Match found, alg compatible → attempt verification
  Match found, alg incompatible → FAIL TL-V004

Token has no kid:
  FAIL TL-V009 immediately
  No fallback attempted
  No signature verification attempted
```

### `require_kid: false`

```
Token has kid:
  Same resolution path as require_kid: true
  kid is always preferred when present

Token has no kid:
  WARN TL-W009 (v2 — kid absent, fallback required)
  Build candidate key set (see below)
  Evaluate candidates per outcome table
```

---

## Fallback key selection (require_kid: false, no kid in token)

Candidate key set is built by filtering JWKS keys:

```
Include key if ALL of:
  kty compatible with token alg
  crv compatible (for EC/OKP keys)
  use == sig OR use absent
  key_ops contains verify OR key_ops absent
  declared alg matches token alg OR key has no alg field
```

Candidate set is **bounded**. tokenlint does not blindly try every key.

### Outcome table

| Candidates | Signature result | Finding | Verdict |
|---|---|---|---|
| Zero | — | FAIL TL-V011 | FAIL |
| One | verifies | WARN TL-W010 (v2) | PASS |
| One | does not verify | FAIL TL-V011 | FAIL |
| Multiple | any verify | FAIL TL-V012 | FAIL |
| Multiple | none verify | FAIL TL-V011 | FAIL |

**Multiple keys verifying a signature is always a FAIL.**  
Ambiguous verification means the trust model is ambiguous. This is not a pass
with a warning — it is a hard failure.

---

## Reproducibility guarantee

Given identical inputs:
- token
- policy file
- JWKS file
- `--at` value

tokenlint **must** produce identical output every run.

The only source of non-determinism is time-sensitive claims (`exp`, `nbf`, `iat`).
These are neutralized by the `--at` flag.

### Watch mode (future v2)

Even in watch mode, each scan cycle uses a new snapshot:

```
watch tick 1 → load JWKS snapshot A → scan → report
watch tick 2 → load JWKS snapshot B → scan → report
```

Never mutate the active keyset during one scan cycle.

---

## Key struct fields

For reference, the normalized internal representation of a JWKS key:

| Field | Type | Notes |
|---|---|---|
| `kid` | str_t | `STR_NULL` if absent |
| `kty` | enum | `RSA \| EC \| OKP \| OCT \| UNKNOWN` |
| `crv` | enum | `P256 \| P384 \| P521 \| Ed25519 \| Ed448 \| UNSET` |
| `use` | enum | `SIG \| ENC \| UNSET` |
| `declared_alg` | alg_id_t | `ALG_NONE_ALG` if not set in JWKS |
| `key_material` | opaque bytes | Passed to crypto backend only |

---

## Finding summary

| ID | Name | Suppressible | Description |
|---|---|---|---|
| TL-S010 | JWKS_MISSING_KEYS_ARRAY | No | Missing `keys` array |
| TL-S011 | JWKS_URL_SOURCE | No | Source is URL, not local path |
| TL-S012 | JWKS_EMPTY_KEYSET | No | `keys` array is empty |
| TL-S013 | JWKS_SOURCE_UNREADABLE | No | File unreadable |
| TL-V009 | TOKEN_KID_ABSENT_STRICT | Yes | No kid + `require_kid: true` |
| TL-V010 | TOKEN_KID_NO_MATCH | Yes | kid present, no match in JWKS |
| TL-V011 | TOKEN_SIG_UNVERIFIABLE | Yes | No candidate key verified signature |
| TL-V012 | TOKEN_SIG_AMBIGUOUS | Yes | Multiple keys verified signature |
