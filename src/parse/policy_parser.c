/*
 * src/parse/policy_parser.c
 *
 * libyaml → policy_t.
 *
 * This is the only file that calls libyaml.  It reads the YAML policy file,
 * validates every field per schema-contract.md, emits TL-S findings into fs,
 * and produces a fully compiled policy_t.
 *
 * The evaluator never sees raw YAML strings.  By the time policy_parse()
 * returns TL_OK, all strings have been resolved to typed enums or compiled
 * matchers.
 *
 * Schema halt conditions (return TL_ERR_SCHEMA):
 *   TL-S001  alg=none in accepts.algorithms
 *   TL-S002  POLICY_ALG_NONE (same)
 *   TL-S003  FIELD_VALUE_INVALID (zero/negative limit)
 *   TL-S004  ENVIRONMENT_INVALID
 *   TL-S005  TOKEN_TYPE_EMPTY
 *   TL-S006  TOKEN_TYPE_UNSUPPORTED
 *   TL-S007  TOKEN_TYPE_MULTIPLE
 *   TL-S008  MODE_UNSUPPORTED
 *   TL-S009  FIELD_EMPTY
 *   TL-S010  ALG_UNRECOGNIZED
 *   TL-S011  JWKS_URL_SOURCE
 *   TL-S020  SUPPRESSION_MISSING_REQUIRED_FIELD
 *
 * Non-halt findings emitted here:
 *   TL-S021  SUPPRESSION_UNKNOWN_FINDING_ID (warn)
 *   TL-S022  SUPPRESSION_EXPIRED (warn)
 *   TL-S023  SUPPRESSION_EXPIRING_SOON (warn)
 *   TL-S024  SUPPRESSION_PROD_MISSING_EXPIRY (fail — halt)
 *   TL-A014  REQUIRED_CLAIM_MISSING (fail — non-halt, collected)
 *   TL-A007  TTL_UNBOUNDED (fail — non-halt, collected)
 */

#define _POSIX_C_SOURCE 200809L


#include "tokenlint.h"
#include "str.h"
#include "alg.h"
#include "findings.h"
#include "policy.h"

#include <yaml.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

_Static_assert(sizeof(policy_t) < 4096,
    "policy_t unexpectedly large; check for padding issues");

/* ── known finding IDs for suppression validation ───────────────────────── */

static const char * const KNOWN_FINDING_IDS[] = {
    "TL-S001","TL-S002","TL-S003","TL-S004","TL-S005",
    "TL-S006","TL-S007","TL-S008","TL-S009","TL-S010",
    "TL-S011","TL-S012","TL-S013","TL-S014","TL-S015",
    "TL-S020","TL-S021","TL-S022","TL-S023","TL-S024",
    "TL-A002","TL-A003","TL-A004","TL-A005","TL-A007","TL-A014",
    "TL-V000","TL-V001","TL-V002","TL-V003","TL-V004","TL-V005",
    "TL-V006","TL-V009","TL-V010","TL-V011","TL-V012",
    "TL-V020","TL-V021","TL-V022","TL-V023","TL-V024","TL-V025",
    "TL-C001","TL-I001",
};
#define N_KNOWN_FINDINGS (sizeof(KNOWN_FINDING_IDS)/sizeof(KNOWN_FINDING_IDS[0]))

static int is_known_finding(const char *id) {
    for (size_t i = 0; i < N_KNOWN_FINDINGS; i++)
        if (strcmp(id, KNOWN_FINDING_IDS[i]) == 0) return 1;
    return 0;
}

/* ── finding helpers ────────────────────────────────────────────────────── */

typedef struct {
    arena_t       *arena;
    finding_set_t *fs;
    const char    *policy_path;
} pctx_t;

static void emit(pctx_t *p, const char *id, const char *title,
                  severity_t sev, const char *detail)
{
    finding_t f;
    memset(&f, 0, sizeof f);
    f.id          = str_from_cstr(id);
    f.title       = str_from_cstr(title);
    f.detail      = str_from_cstr(detail);
    f.policy_path = str_from_cstr(p->policy_path);
    f.severity    = sev;
    f.status      = FINDING_ACTIVE;
    int added = findings_add(p->fs, &f, p->arena, NULL, 0);
    TL_UNUSED(added);
}

/* ── libyaml node helpers ───────────────────────────────────────────────── */

/* Get scalar value of a mapping key in a YAML mapping node.
 * Returns the scalar str_t of the value node, or STR_NULL if not found. */
static yaml_node_t *map_get(yaml_document_t *doc, yaml_node_t *map,
                              const char *key)
{
    if (!map || map->type != YAML_MAPPING_NODE) return NULL;
    yaml_node_pair_t *pair = map->data.mapping.pairs.start;
    yaml_node_pair_t *end  = map->data.mapping.pairs.top;
    size_t klen = strlen(key);
    for (; pair < end; pair++) {
        yaml_node_t *knode = yaml_document_get_node(doc, pair->key);
        if (!knode || knode->type != YAML_SCALAR_NODE) continue;
        size_t nlen = knode->data.scalar.length;
        if (nlen == klen && memcmp(knode->data.scalar.value, key, klen) == 0)
            return yaml_document_get_node(doc, pair->value);
    }
    return NULL;
}

/* Get scalar string from a node (must be SCALAR). Returns NULL if not. */
static const char *scalar_str(yaml_node_t *n) {
    if (!n || n->type != YAML_SCALAR_NODE) return NULL;
    return (const char *)n->data.scalar.value;
}

/* ── algorithm string parsing ───────────────────────────────────────────── */

static alg_id_t alg_from_str(const char *s) {
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

/* ── date parsing helper ────────────────────────────────────────────────── */

/* Parse ISO 8601 date "YYYY-MM-DD" → Unix epoch (midnight UTC).
 * Returns 0 on parse error (epoch 0 = 1970-01-01 which is fine as sentinel). */
static int64_t parse_iso_date(const char *s) {
    if (!s || strlen(s) < 10) return 0;
    int year, month, day;
    if (sscanf(s, "%4d-%2d-%2d", &year, &month, &day) != 3) return 0;
    /* Use civil_to_epoch style: days since epoch */
    /* Simplified: use mktime with tm */
    struct tm t;
    memset(&t, 0, sizeof t);
    t.tm_year = year - 1900;
    t.tm_mon  = month - 1;
    t.tm_mday = day;
    t.tm_isdst = -1;
    time_t epoch = timegm(&t);
    if (epoch == (time_t)-1) return 0;
    return (int64_t)epoch;
}

/* ── suppression parsing ─────────────────────────────────────────────────── */

/*
 * Parse suppressions array.  Returns TL_ERR_SCHEMA on hard failures.
 */
static tl_error_t parse_suppressions(pctx_t *p, yaml_document_t *doc,
                                       yaml_node_t *seq,
                                       suppression_t **out, size_t *count_out,
                                       environment_t env, int64_t reference_now)
{
    if (!seq || seq->type != YAML_SEQUENCE_NODE) {
        *out = NULL; *count_out = 0;
        return TL_OK;
    }

    size_t n = (size_t)(seq->data.sequence.items.top -
                        seq->data.sequence.items.start);
    if (n == 0) { *out = NULL; *count_out = 0; return TL_OK; }

    suppression_t *arr = ARENA_ALLOC_ARRAY(p->arena, suppression_t, n);
    TL_RETURN_IF_NULL(arr, "arena exhausted for suppressions");

    size_t filled = 0;
    for (yaml_node_item_t *it = seq->data.sequence.items.start;
         it < seq->data.sequence.items.top; it++) {
        yaml_node_t *entry = yaml_document_get_node(doc, *it);
        if (!entry || entry->type != YAML_MAPPING_NODE) continue;

        suppression_t s;
        memset(&s, 0, sizeof s);

        /* id — required */
        yaml_node_t *nid = map_get(doc, entry, "id");
        const char *id_s = scalar_str(nid);
        if (!id_s || strlen(id_s) == 0) {
            emit(p, "TL-S020", "SUPPRESSION_MISSING_REQUIRED_FIELD",
                 SEV_FAIL, "Suppression entry missing 'id' field");
            return tl_error(TL_ERR_SCHEMA, "suppression missing id", STR_NULL);
        }
        s.finding_id = arena_strdup(p->arena, str_from_cstr(id_s));

        /* reason — required */
        yaml_node_t *nreason = map_get(doc, entry, "reason");
        const char *reason_s = scalar_str(nreason);
        if (!reason_s || strlen(reason_s) == 0) {
            emit(p, "TL-S020", "SUPPRESSION_MISSING_REQUIRED_FIELD",
                 SEV_FAIL, "Suppression entry missing 'reason' field");
            return tl_error(TL_ERR_SCHEMA, "suppression missing reason", STR_NULL);
        }
        s.reason = arena_strdup(p->arena, str_from_cstr(reason_s));

        /* owner — required */
        yaml_node_t *nowner = map_get(doc, entry, "owner");
        const char *owner_s = scalar_str(nowner);
        if (!owner_s || strlen(owner_s) == 0) {
            emit(p, "TL-S020", "SUPPRESSION_MISSING_REQUIRED_FIELD",
                 SEV_FAIL, "Suppression entry missing 'owner' field");
            return tl_error(TL_ERR_SCHEMA, "suppression missing owner", STR_NULL);
        }
        s.owner = arena_strdup(p->arena, str_from_cstr(owner_s));

        /* ticket — optional */
        yaml_node_t *nticket = map_get(doc, entry, "ticket");
        const char *ticket_s = scalar_str(nticket);
        if (ticket_s && strlen(ticket_s) > 0)
            s.ticket = arena_strdup(p->arena, str_from_cstr(ticket_s));

        /* expires — optional, required in prod */
        yaml_node_t *nexpires = map_get(doc, entry, "expires");
        const char *expires_s = scalar_str(nexpires);
        if (expires_s && strlen(expires_s) > 0) {
            s.expires       = arena_strdup(p->arena, str_from_cstr(expires_s));
            s.expires_epoch = parse_iso_date(expires_s);
        }

        /* TL-S024: prod requires expires */
        if ((env == ENV_PROD || env == ENV_UNKNOWN) &&
            STR_IS_NULL(s.expires)) {
            emit(p, "TL-S024", "SUPPRESSION_PROD_MISSING_EXPIRY",
                 SEV_FAIL,
                 "Production suppression entry has no 'expires' field");
            return tl_error(TL_ERR_SCHEMA,
                            "prod suppression missing expiry", STR_NULL);
        }

        /* TL-S021: unknown finding ID */
        if (!is_known_finding(id_s)) {
            emit(p, "TL-S021", "SUPPRESSION_UNKNOWN_FINDING_ID",
                 SEV_WARN, "Suppression references unknown finding code");
        }

        /* TL-S022: expired */
        if (s.expires_epoch > 0 && reference_now > 0 &&
            s.expires_epoch < reference_now) {
            emit(p, "TL-S022", "SUPPRESSION_EXPIRED",
                 SEV_WARN, "Suppression expiry date is in the past");
        }

        /* TL-S023: expiring within 14 days */
        if (s.expires_epoch > 0 && reference_now > 0) {
            int64_t days_left = (s.expires_epoch - reference_now) / 86400;
            if (days_left >= 0 && days_left <= 14) {
                emit(p, "TL-S023", "SUPPRESSION_EXPIRING_SOON",
                     SEV_WARN, "Suppression expires within 14 days");
            }
        }

        arr[filled++] = s;
    }

    *out       = arr;
    *count_out = filled;
    return TL_OK;
}

/* ── parse_claim_rules ───────────────────────────────────────────────────── */

static tl_error_t parse_claim_rules(pctx_t *p, yaml_document_t *doc,
                                     yaml_node_t *seq,
                                     claim_rule_t **out, size_t *count_out)
{
    if (!seq || seq->type != YAML_SEQUENCE_NODE) {
        *out = NULL; *count_out = 0; return TL_OK;
    }
    size_t n = (size_t)(seq->data.sequence.items.top -
                        seq->data.sequence.items.start);
    if (n == 0) { *out = NULL; *count_out = 0; return TL_OK; }

    claim_rule_t *arr = ARENA_ALLOC_ARRAY(p->arena, claim_rule_t, n);
    TL_RETURN_IF_NULL(arr, "arena exhausted for claim_rules");

    size_t filled = 0;
    for (yaml_node_item_t *it = seq->data.sequence.items.start;
         it < seq->data.sequence.items.top; it++) {
        yaml_node_t *entry = yaml_document_get_node(doc, *it);
        if (!entry || entry->type != YAML_MAPPING_NODE) continue;

        claim_rule_t r;
        memset(&r, 0, sizeof r);

        /* claim — required */
        yaml_node_t *nclaim = map_get(doc, entry, "claim");
        const char *claim_s = scalar_str(nclaim);
        if (!claim_s || strlen(claim_s) == 0) continue;
        r.claim = arena_strdup(p->arena, str_from_cstr(claim_s));

        /* operator — required */
        yaml_node_t *nop = map_get(doc, entry, "operator");
        const char *op_s = scalar_str(nop);
        if (!op_s) {
            emit(p, "TL-S015", "CLAIM_RULE_MISSING_FIELD",
                 SEV_FAIL, "claim_rule missing 'operator' field");
            return tl_error(TL_ERR_SCHEMA, "claim_rule missing operator", STR_NULL);
        }
        if      (strcmp(op_s, "deny_any")      == 0) r.op = CLAIM_OP_DENY_ANY;
        else if (strcmp(op_s, "allow_only")    == 0) r.op = CLAIM_OP_ALLOW_ONLY;
        else if (strcmp(op_s, "require_match") == 0) r.op = CLAIM_OP_REQUIRE_MATCH;
        else if (strcmp(op_s, "deny_match")    == 0) r.op = CLAIM_OP_DENY_MATCH;
        else if (strcmp(op_s, "require_any")   == 0) r.op = CLAIM_OP_REQUIRE_ANY;
        else if (strcmp(op_s, "require_all")   == 0) r.op = CLAIM_OP_REQUIRE_ALL;
        else {
            emit(p, "TL-S015", "CLAIM_RULE_MISSING_FIELD",
                 SEV_FAIL, "claim_rule has unknown operator");
            return tl_error(TL_ERR_SCHEMA, "unknown claim_rule operator", STR_NULL);
        }

        /* required — optional boolean */
        yaml_node_t *nreq = map_get(doc, entry, "required");
        const char *req_s = scalar_str(nreq);
        if (req_s) r.required = (strcmp(req_s, "true") == 0) ? 1 : 0;

        /* values — array, required for some operators */
        yaml_node_t *nvals = map_get(doc, entry, "values");
        if (nvals && nvals->type == YAML_SEQUENCE_NODE) {
            size_t vc = (size_t)(nvals->data.sequence.items.top -
                                  nvals->data.sequence.items.start);
            if (vc > 0) {
                r.values = ARENA_ALLOC_ARRAY(p->arena, str_t, vc);
                TL_RETURN_IF_NULL(r.values, "arena exhausted for claim_rule values");
                for (yaml_node_item_t *vi = nvals->data.sequence.items.start;
                     vi < nvals->data.sequence.items.top; vi++) {
                    yaml_node_t *vn = yaml_document_get_node(doc, *vi);
                    const char *vs = scalar_str(vn);
                    if (vs)
                        r.values[r.value_count++] =
                            arena_strdup(p->arena, str_from_cstr(vs));
                }
            }
        }

        /* pattern — for require_match / deny_match */
        yaml_node_t *npat = map_get(doc, entry, "pattern");
        const char *pat_s = scalar_str(npat);
        if (pat_s) r.pattern = arena_strdup(p->arena, str_from_cstr(pat_s));

        /* Validate: operators needing values */
        if ((r.op == CLAIM_OP_DENY_ANY || r.op == CLAIM_OP_ALLOW_ONLY ||
             r.op == CLAIM_OP_REQUIRE_ANY || r.op == CLAIM_OP_REQUIRE_ALL)
            && r.value_count == 0) {
            emit(p, "TL-S015", "CLAIM_RULE_MISSING_FIELD",
                 SEV_FAIL, "claim_rule operator requires 'values' field");
            return tl_error(TL_ERR_SCHEMA, "claim_rule missing values", STR_NULL);
        }
        if ((r.op == CLAIM_OP_REQUIRE_MATCH || r.op == CLAIM_OP_DENY_MATCH)
            && STR_IS_NULL(r.pattern)) {
            emit(p, "TL-S015", "CLAIM_RULE_MISSING_FIELD",
                 SEV_FAIL, "claim_rule operator requires 'pattern' field");
            return tl_error(TL_ERR_SCHEMA, "claim_rule missing pattern", STR_NULL);
        }

        arr[filled++] = r;
    }

    *out       = arr;
    *count_out = filled;
    return TL_OK;
}

/* ── main parse function ─────────────────────────────────────────────────── */

tl_error_t policy_parse(arena_t       *arena,
                          const char    *path,
                          finding_set_t *fs,
                          policy_t     **out)
{
    pctx_t p = { arena, fs, path };

    /* ── Open file ── */
    FILE *f = fopen(path, "r");
    if (!f) return tl_error(TL_ERR_IO, "policy file not found or unreadable",
                             str_from_cstr(path));

    /* ── Parse YAML ── */
    yaml_parser_t parser;
    yaml_document_t doc;
    if (!yaml_parser_initialize(&parser)) {
        fclose(f);
        return tl_error_internal("yaml_parser_initialize failed");
    }
    yaml_parser_set_input_file(&parser, f);

    int loaded = yaml_parser_load(&parser, &doc);
    yaml_parser_delete(&parser);
    fclose(f);

    if (!loaded) {
        emit(&p, "TL-V000", "TOKEN_UNPARSEABLE", SEV_FAIL,
             "Policy YAML is not valid YAML");
        return tl_error(TL_ERR_SCHEMA, "YAML parse error", str_from_cstr(path));
    }

    yaml_node_t *root = yaml_document_get_root_node(&doc);
    if (!root || root->type != YAML_MAPPING_NODE) {
        yaml_document_delete(&doc);
        emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
             "Policy YAML root is not a mapping");
        return tl_error(TL_ERR_SCHEMA, "policy root is not a mapping",
                         str_from_cstr(path));
    }

    /* Allocate result */
    policy_t *pol = ARENA_ALLOC_ONE(arena, policy_t);
    if (!pol) { yaml_document_delete(&doc); return tl_error_internal("arena OOM"); }

    /* Default time limits */
    pol->time_limits.max_clock_skew_seconds = 60;

    /* ── schema_version ── */
    yaml_node_t *nver = map_get(&doc, root, "schema_version");
    const char *ver_s = scalar_str(nver);
    if (!ver_s || strcmp(ver_s, "tokenlint.validator.v1") != 0) {
        yaml_document_delete(&doc);
        emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
             "schema_version is missing or not 'tokenlint.validator.v1'");
        return tl_error(TL_ERR_SCHEMA, "invalid schema_version",
                         str_from_cstr(path));
    }
    pol->schema_version = arena_strdup(arena, str_from_cstr(ver_s));

    /* ── validator ── */
    yaml_node_t *nvalidator = map_get(&doc, root, "validator");
    if (!nvalidator || nvalidator->type != YAML_MAPPING_NODE) {
        yaml_document_delete(&doc);
        emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
             "Missing required 'validator' block");
        return tl_error(TL_ERR_SCHEMA, "missing validator", str_from_cstr(path));
    }

    /* validator.id */
    yaml_node_t *nid = map_get(&doc, nvalidator, "id");
    const char *id_s = scalar_str(nid);
    if (!id_s || strlen(id_s) == 0) {
        yaml_document_delete(&doc);
        emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
             "validator.id is required and must be non-empty");
        return tl_error(TL_ERR_SCHEMA, "missing validator.id", str_from_cstr(path));
    }
    pol->validator_id = arena_strdup(arena, str_from_cstr(id_s));

    /* validator.environment */
    yaml_node_t *nenv = map_get(&doc, nvalidator, "environment");
    const char *env_s = scalar_str(nenv);
    if (!env_s) {
        yaml_document_delete(&doc);
        emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
             "validator.environment is required");
        return tl_error(TL_ERR_SCHEMA, "missing environment", str_from_cstr(path));
    }
    if      (strcmp(env_s, "prod")    == 0) pol->environment = ENV_PROD;
    else if (strcmp(env_s, "stage")   == 0) pol->environment = ENV_STAGE;
    else if (strcmp(env_s, "dev")     == 0) pol->environment = ENV_DEV;
    else if (strcmp(env_s, "test")    == 0) pol->environment = ENV_TEST;
    else if (strcmp(env_s, "unknown") == 0) pol->environment = ENV_UNKNOWN;
    else {
        yaml_document_delete(&doc);
        emit(&p, "TL-S004", "ENVIRONMENT_INVALID", SEV_FAIL,
             "validator.environment must be prod|stage|dev|test|unknown");
        return tl_error(TL_ERR_SCHEMA, "invalid environment", str_from_cstr(path));
    }

    /* ── accepts ── */
    yaml_node_t *naccepts = map_get(&doc, root, "accepts");
    if (!naccepts || naccepts->type != YAML_MAPPING_NODE) {
        yaml_document_delete(&doc);
        emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL, "Missing required 'accepts' block");
        return tl_error(TL_ERR_SCHEMA, "missing accepts", str_from_cstr(path));
    }

    /* accepts.token_types */
    yaml_node_t *ntt = map_get(&doc, naccepts, "token_types");
    if (!ntt || ntt->type != YAML_SEQUENCE_NODE) {
        yaml_document_delete(&doc);
        emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
             "accepts.token_types is required");
        return tl_error(TL_ERR_SCHEMA, "missing token_types", str_from_cstr(path));
    }
    {
        size_t tt_count = (size_t)(ntt->data.sequence.items.top -
                                    ntt->data.sequence.items.start);
        if (tt_count == 0) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S005", "TOKEN_TYPE_EMPTY", SEV_FAIL,
                 "accepts.token_types must not be empty");
            return tl_error(TL_ERR_SCHEMA, "token_types empty", str_from_cstr(path));
        }
        if (tt_count > 1) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S007", "TOKEN_TYPE_MULTIPLE", SEV_FAIL,
                 "accepts.token_types must have exactly one value in v1");
            return tl_error(TL_ERR_SCHEMA, "token_types multiple", str_from_cstr(path));
        }
        yaml_node_t *tt0 = yaml_document_get_node(&doc,
                               *ntt->data.sequence.items.start);
        const char *tt_s = scalar_str(tt0);
        if (!tt_s || strcmp(tt_s, "jwt") != 0) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S006", "TOKEN_TYPE_UNSUPPORTED", SEV_FAIL,
                 "Only 'jwt' is supported in accepts.token_types for v1");
            return tl_error(TL_ERR_SCHEMA, "unsupported token_type", str_from_cstr(path));
        }
    }

    /* accepts.issuers */
    yaml_node_t *nissuers = map_get(&doc, naccepts, "issuers");
    if (!nissuers || nissuers->type != YAML_MAPPING_NODE) {
        yaml_document_delete(&doc);
        emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
             "accepts.issuers block is required");
        return tl_error(TL_ERR_SCHEMA, "missing issuers", str_from_cstr(path));
    }
    {
        yaml_node_t *nimode = map_get(&doc, nissuers, "mode");
        const char *imode_s = scalar_str(nimode);
        if (!imode_s || strcmp(imode_s, "exact") != 0) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S008", "MODE_UNSUPPORTED", SEV_FAIL,
                 "accepts.issuers.mode must be 'exact' in v1");
            return tl_error(TL_ERR_SCHEMA, "unsupported issuer mode",
                             str_from_cstr(path));
        }
        pol->issuers.mode = ISSUER_MODE_EXACT;

        yaml_node_t *nivals = map_get(&doc, nissuers, "values");
        if (!nivals || nivals->type != YAML_SEQUENCE_NODE) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
                 "accepts.issuers.values is required");
            return tl_error(TL_ERR_SCHEMA, "missing issuers.values",
                             str_from_cstr(path));
        }
        size_t ic = (size_t)(nivals->data.sequence.items.top -
                              nivals->data.sequence.items.start);
        if (ic == 0) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
                 "accepts.issuers.values must not be empty");
            return tl_error(TL_ERR_SCHEMA, "empty issuers.values",
                             str_from_cstr(path));
        }
        pol->issuers.values = ARENA_ALLOC_ARRAY(arena, str_t, ic);
        if (!pol->issuers.values) { yaml_document_delete(&doc);
            return tl_error_internal("arena OOM issuers"); }
        for (yaml_node_item_t *it = nivals->data.sequence.items.start;
             it < nivals->data.sequence.items.top; it++) {
            yaml_node_t *vn = yaml_document_get_node(&doc, *it);
            const char *vs = scalar_str(vn);
            if (!vs || strlen(vs) == 0) continue;
            /* Normalize: strip trailing slash */
            size_t vlen = strlen(vs);
            while (vlen > 0 && vs[vlen-1] == '/') vlen--;
            pol->issuers.values[pol->issuers.count++] =
                arena_strdup(arena, (str_t){ vs, vlen });
        }
        if (pol->issuers.count == 0) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
                 "accepts.issuers.values must not be empty");
            return tl_error(TL_ERR_SCHEMA, "empty issuers.values",
                             str_from_cstr(path));
        }
    }

    /* accepts.audiences */
    yaml_node_t *naudiences = map_get(&doc, naccepts, "audiences");
    if (!naudiences || naudiences->type != YAML_MAPPING_NODE) {
        yaml_document_delete(&doc);
        emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
             "accepts.audiences block is required");
        return tl_error(TL_ERR_SCHEMA, "missing audiences", str_from_cstr(path));
    }
    {
        yaml_node_t *namode = map_get(&doc, naudiences, "mode");
        const char *amode_s = scalar_str(namode);
        if (!amode_s || strcmp(amode_s, "exact") != 0) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S008", "MODE_UNSUPPORTED", SEV_FAIL,
                 "accepts.audiences.mode must be 'exact' in v1");
            return tl_error(TL_ERR_SCHEMA, "unsupported audience mode",
                             str_from_cstr(path));
        }
        pol->audiences.mode = AUDIENCE_MODE_EXACT;

        yaml_node_t *navals = map_get(&doc, naudiences, "values");
        if (!navals || navals->type != YAML_SEQUENCE_NODE) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
                 "accepts.audiences.values is required");
            return tl_error(TL_ERR_SCHEMA, "missing audiences.values",
                             str_from_cstr(path));
        }
        size_t ac = (size_t)(navals->data.sequence.items.top -
                              navals->data.sequence.items.start);
        if (ac == 0) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
                 "accepts.audiences.values must not be empty");
            return tl_error(TL_ERR_SCHEMA, "empty audiences.values",
                             str_from_cstr(path));
        }
        pol->audiences.values = ARENA_ALLOC_ARRAY(arena, str_t, ac);
        if (!pol->audiences.values) { yaml_document_delete(&doc);
            return tl_error_internal("arena OOM audiences"); }
        for (yaml_node_item_t *it = navals->data.sequence.items.start;
             it < navals->data.sequence.items.top; it++) {
            yaml_node_t *vn = yaml_document_get_node(&doc, *it);
            const char *vs = scalar_str(vn);
            if (!vs) continue;
            /* TL-A004: wildcard audience */
            if (strlen(vs) == 0 || strcmp(vs, "*") == 0) {
                emit(&p, "TL-A004", "AUDIENCE_WILDCARD", SEV_CRITICAL,
                     "Wildcard or empty audience is forbidden");
                /* non-halt finding: continue */
            }
            pol->audiences.values[pol->audiences.count++] =
                arena_strdup(arena, str_from_cstr(vs));
        }
        if (pol->audiences.count == 0) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
                 "accepts.audiences.values has no valid entries");
            return tl_error(TL_ERR_SCHEMA, "empty audiences.values",
                             str_from_cstr(path));
        }
    }

    /* accepts.algorithms */
    yaml_node_t *nalgs = map_get(&doc, naccepts, "algorithms");
    if (!nalgs || nalgs->type != YAML_SEQUENCE_NODE) {
        yaml_document_delete(&doc);
        emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
             "accepts.algorithms is required");
        return tl_error(TL_ERR_SCHEMA, "missing algorithms", str_from_cstr(path));
    }
    {
        size_t alg_count = (size_t)(nalgs->data.sequence.items.top -
                                     nalgs->data.sequence.items.start);
        if (alg_count == 0) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
                 "accepts.algorithms must not be empty");
            return tl_error(TL_ERR_SCHEMA, "empty algorithms", str_from_cstr(path));
        }
        for (yaml_node_item_t *it = nalgs->data.sequence.items.start;
             it < nalgs->data.sequence.items.top; it++) {
            yaml_node_t *an = yaml_document_get_node(&doc, *it);
            const char *as  = scalar_str(an);
            if (!as) continue;

            /* alg=none check (non-suppressible) */
            if (strcasecmp(as, "none") == 0) {
                yaml_document_delete(&doc);
                emit(&p, "TL-S002", "POLICY_ALG_NONE", SEV_CRITICAL,
                     "'none' in accepts.algorithms is forbidden");
                return tl_error(TL_ERR_SCHEMA, "alg=none in policy",
                                 str_from_cstr(path));
            }

            alg_id_t alg = alg_from_str(as);
            if (alg == ALG_NONE_ALG) {
                yaml_document_delete(&doc);
                emit(&p, "TL-S010", "ALG_UNRECOGNIZED", SEV_FAIL,
                     "Unrecognized algorithm in accepts.algorithms");
                return tl_error(TL_ERR_SCHEMA, "unrecognized algorithm",
                                 str_from_cstr(path));
            }

            /* TL-A005: symmetric alg in prod */
            if (alg_is_symmetric(alg) &&
                (pol->environment == ENV_PROD ||
                 pol->environment == ENV_UNKNOWN)) {
                emit(&p, "TL-A005", "POLICY_ALG_SYMMETRIC_PROD", SEV_CRITICAL,
                     "HMAC (symmetric) algorithm in prod policy");
            }

            ALLOWSET_ADD(pol->algorithms, alg);
        }
        if (pol->algorithms.bits == 0) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
                 "accepts.algorithms has no valid entries");
            return tl_error(TL_ERR_SCHEMA, "empty algorithms", str_from_cstr(path));
        }
    }

    /* ── jwks ── */
    yaml_node_t *njwks = map_get(&doc, root, "jwks");
    if (!njwks || njwks->type != YAML_MAPPING_NODE) {
        yaml_document_delete(&doc);
        emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL, "Missing required 'jwks' block");
        return tl_error(TL_ERR_SCHEMA, "missing jwks", str_from_cstr(path));
    }
    {
        yaml_node_t *nsrc = map_get(&doc, njwks, "source");
        const char *src_s = scalar_str(nsrc);
        if (!src_s || strlen(src_s) == 0) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
                 "jwks.source is required");
            return tl_error(TL_ERR_SCHEMA, "missing jwks.source",
                             str_from_cstr(path));
        }
        /* TL-S011: URL source */
        if (strncmp(src_s, "http://", 7) == 0 ||
            strncmp(src_s, "https://", 8) == 0) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S011", "JWKS_URL_SOURCE", SEV_FAIL,
                 "jwks.source must be a local path, not a URL");
            return tl_error(TL_ERR_SCHEMA, "jwks.source is a URL",
                             str_from_cstr(path));
        }
        pol->jwks_policy.source = arena_strdup(arena, str_from_cstr(src_s));

        yaml_node_t *nrkid = map_get(&doc, njwks, "require_kid");
        const char *rkid_s = scalar_str(nrkid);
        pol->jwks_policy.require_kid = (rkid_s && strcmp(rkid_s, "true") == 0) ? 1 : 0;
    }

    /* ── requires ── */
    yaml_node_t *nrequires = map_get(&doc, root, "requires");
    if (!nrequires || nrequires->type != YAML_MAPPING_NODE) {
        yaml_document_delete(&doc);
        emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
             "Missing required 'requires' block");
        return tl_error(TL_ERR_SCHEMA, "missing requires", str_from_cstr(path));
    }
    {
        yaml_node_t *nclaims = map_get(&doc, nrequires, "claims");
        if (!nclaims || nclaims->type != YAML_SEQUENCE_NODE) {
            yaml_document_delete(&doc);
            emit(&p, "TL-S009", "FIELD_EMPTY", SEV_FAIL,
                 "requires.claims is required");
            return tl_error(TL_ERR_SCHEMA, "missing requires.claims",
                             str_from_cstr(path));
        }

        static const struct { const char *name; uint32_t bit; } REG_CLAIMS[] = {
            {"iss",CLAIM_ISS},{"sub",CLAIM_SUB},{"aud",CLAIM_AUD},
            {"exp",CLAIM_EXP},{"nbf",CLAIM_NBF},{"iat",CLAIM_IAT},{"jti",CLAIM_JTI},
        };

        for (yaml_node_item_t *it = nclaims->data.sequence.items.start;
             it < nclaims->data.sequence.items.top; it++) {
            yaml_node_t *cn = yaml_document_get_node(&doc, *it);
            const char *cs  = scalar_str(cn);
            if (!cs || strlen(cs) == 0) continue;

            int found = 0;
            for (size_t i = 0; i < 7; i++) {
                if (strcmp(cs, REG_CLAIMS[i].name) == 0) {
                    pol->required_registered_claims |= REG_CLAIMS[i].bit;
                    found = 1; break;
                }
            }
            if (!found) {
                /* Custom claim — store for v2 evaluation */
                /* For v1, just track count */
                pol->required_custom_claim_count++;
            }
        }
    }

    /* TL-A014: exp, iss, aud must be in requires.claims */
    {
        uint32_t mandatory = CLAIM_EXP | CLAIM_ISS | CLAIM_AUD;
        uint32_t missing   = mandatory & ~pol->required_registered_claims;
        if (missing & CLAIM_EXP)
            emit(&p, "TL-A014", "REQUIRED_CLAIM_MISSING", SEV_FAIL,
                 "'exp' must be in requires.claims");
        if (missing & CLAIM_ISS)
            emit(&p, "TL-A014", "REQUIRED_CLAIM_MISSING", SEV_FAIL,
                 "'iss' must be in requires.claims");
        if (missing & CLAIM_AUD)
            emit(&p, "TL-A014", "REQUIRED_CLAIM_MISSING", SEV_FAIL,
                 "'aud' must be in requires.claims");
    }

    /* ── limits (optional) ── */
    yaml_node_t *nlimits = map_get(&doc, root, "limits");
    if (nlimits && nlimits->type == YAML_MAPPING_NODE) {
        yaml_node_t *nttl = map_get(&doc, nlimits, "max_ttl_seconds");
        const char *ttl_s = scalar_str(nttl);
        if (ttl_s) {
            int64_t v = 0;
            str_t sv = str_from_cstr(ttl_s);
            if (!str_to_i64(sv, &v) || v <= 0) {
                yaml_document_delete(&doc);
                emit(&p, "TL-S003", "FIELD_VALUE_INVALID", SEV_FAIL,
                     "limits.max_ttl_seconds must be a positive integer");
                return tl_error(TL_ERR_SCHEMA, "invalid max_ttl_seconds",
                                 str_from_cstr(path));
            }
            pol->time_limits.max_ttl_seconds = v;
        }

        yaml_node_t *nskew = map_get(&doc, nlimits, "max_clock_skew_seconds");
        const char *skew_s = scalar_str(nskew);
        if (skew_s) {
            int64_t v = 0;
            str_t sv = str_from_cstr(skew_s);
            if (!str_to_i64(sv, &v) || v < 0) {
                yaml_document_delete(&doc);
                emit(&p, "TL-S003", "FIELD_VALUE_INVALID", SEV_FAIL,
                     "limits.max_clock_skew_seconds must be non-negative");
                return tl_error(TL_ERR_SCHEMA, "invalid max_clock_skew_seconds",
                                 str_from_cstr(path));
            }
            pol->time_limits.max_clock_skew_seconds = v;
        }
    }

    /* TL-A007: TTL unbounded */
    if (pol->time_limits.max_ttl_seconds == 0) {
        emit(&p, "TL-A007", "TTL_UNBOUNDED", SEV_FAIL,
             "limits.max_ttl_seconds is not set — token lifetime is unconstrained");
    }

    /* ── claim_rules (optional) ── */
    yaml_node_t *ncrules = map_get(&doc, root, "claim_rules");
    {
        tl_error_t cerr = parse_claim_rules(&p, &doc, ncrules,
                                             &pol->claim_rules,
                                             &pol->claim_rule_count);
        if (!tl_ok(cerr)) { yaml_document_delete(&doc); return cerr; }
    }

    /* ── suppressions (optional) ── */
    yaml_node_t *nsupps = map_get(&doc, root, "suppressions");
    {
        int64_t now = (int64_t)time(NULL);
        tl_error_t serr = parse_suppressions(&p, &doc, nsupps,
                                              &pol->suppressions,
                                              &pol->suppression_count,
                                              pol->environment, now);
        if (!tl_ok(serr)) { yaml_document_delete(&doc); return serr; }
    }

    yaml_document_delete(&doc);
    *out = pol;
    return TL_OK;
}
