#!/usr/bin/env python3
"""
tools/check_coverage.py

Verify that every finding in finding_registry.def has both a positive
(fires/triggers) and a negative (no_fire/does not trigger) test function
somewhere in the tests/ directory.

Matching rules
--------------
For finding TL-V003, the script searches all .c and .sh files under tests/
for function names that:

  POSITIVE — contain the ID variant AND one of:
    fires, halts, fails, emits, triggers, nonsuppressible

  NEGATIVE — contain the ID variant AND one of:
    no_fire, no_match, not_expired, never, nonsuppressible,
    allowed, pass, clean, absent

ID variants (case-insensitive, hyphen-optional):
  TL-V003 → matches: v003, tl_v003, tl-v003, TL_V003 etc.

Named-property exemptions
-------------------------
Some findings are covered by SECURITY_PROP tests whose function names do not
embed the finding ID. These are listed in NAMED_PROP_COVERAGE below and are
treated as fully covered (both positive and negative directions) when the
named function exists in the test sources.

Usage:
  python3 tools/check_coverage.py finding_registry.def tests/

Exit:
  0  all findings have coverage
  1  one or more findings are missing test functions
"""

import sys
import os
import re
import glob

POSITIVE_TERMS = frozenset({
    'fires', 'halts', 'fails', 'emits', 'triggers', 'nonsuppressible'
})
NEGATIVE_TERMS = frozenset({
    'no_fire', 'no_match', 'not_expired', 'never', 'nonsuppressible',
    'allowed', 'pass', 'clean', 'absent'
})

# Findings whose coverage comes from named SECURITY_PROP or integration tests
# that do not embed the finding ID in the function name.
#
# Format: "TL-XXXX": (positive_fn, negative_fn)
#   - Each value is a function name that must exist in the test sources.
#   - Use None to fall through to the normal ID-based search.
#   - Both directions may name the same function if it covers both.
#
# Rationale for each entry is documented inline.
NAMED_PROP_COVERAGE = {
    # SUPPRESSION_CANNOT_HIDE_SCHEMA_ERRORS iterates all TL-S IDs explicitly,
    # calls stays_active_despite_suppression() for each, and verifies both
    # that the finding fires AND that it cannot be suppressed.
    # parse_* tests in test_policy_parser.c cover individual positive cases.
    "TL-S001": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S003": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S004": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S005": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S006": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S007": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S008": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S009": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S010": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S012": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S013": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S014": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S015": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S020": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S021": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S022": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S023": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),
    "TL-S024": ("suppression_cannot_hide_schema_errors",
                "suppression_cannot_hide_schema_errors"),

    # parse_full_token / parse_full_valid: a fully valid token parses clean,
    # meaning TL-V000, TL-V001, TL-V002 do not fire. Negative direction only;
    # positive is covered by ID-named tests (empty_jwt_fails_v000 etc.)
    "TL-V000": (None, "parse_full_token"),
    "TL-V002": (None, "parse_full_token"),

    # BAD_SIGNATURE_ALWAYS_FAILS: exercises the signature verification path
    # and asserts TL-V006 fires. Positive only; suppression_nonsuppressible_v006
    # covers the non-suppressibility property.
    "TL-V006": ("bad_signature_always_fails", None),

    # AMBIGUOUS_KEY_MATCH_FAILS: asserts TL-V012 fires when multiple keys
    # verify the same signature, and that the result is always FAIL.
    "TL-V012": ("ambiguous_key_match_fails", "ambiguous_key_match_fails"),

    # AT_FLAG_PRODUCES_DETERMINISTIC_OUTPUT exercises the --at parsing path
    # which fires TL-I001 on bad input. suppression_nonsuppressible_i001
    # covers non-suppressibility. Positive only; negative is forensic_resolve_*.
    "TL-I001": ("at_flag_produces_deterministic_output", None),
}


def load_finding_ids(registry_path):
    """Parse finding_registry.def and return list of string IDs like 'TL-V003'."""
    ids = []
    pattern = re.compile(r'X\(\s*\w+\s*,\s*"(TL-[A-Z]\d+)"\s*\)')
    with open(registry_path) as f:
        for line in f:
            m = pattern.search(line)
            if m:
                ids.append(m.group(1))
    return ids


def id_variants(finding_id):
    """
    Return a frozenset of lowercase substrings that represent this finding ID.

    TL-V003 → {'tl-v003', 'tl_v003', 'v003'}
    """
    fid_lower = finding_id.lower()
    fid_under = fid_lower.replace('-', '_')
    short = fid_lower.split('-', 1)[1]
    return frozenset({fid_lower, fid_under, short})


def load_identifiers(test_dir):
    """Return set of all lowercase identifiers found in .c and .sh under test_dir."""
    identifiers = set()
    for pat in ['**/*.c', '**/*.sh']:
        for path in glob.glob(os.path.join(test_dir, pat), recursive=True):
            try:
                text = open(path).read().lower()
                identifiers |= set(re.findall(r'\b[a-z][a-z0-9_]*\b', text))
            except Exception:
                pass
    return identifiers


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} finding_registry.def tests/")
        sys.exit(1)

    registry_path = sys.argv[1]
    test_dir = sys.argv[2]

    ids = load_finding_ids(registry_path)
    if not ids:
        print(f"ERROR: No finding IDs found in {registry_path}")
        sys.exit(1)

    all_identifiers = load_identifiers(test_dir)

    missing = []

    for fid in ids:
        variants = id_variants(fid)
        prop_pos, prop_neg = NAMED_PROP_COVERAGE.get(fid, (None, None))

        # Check named-property exemptions first
        has_positive = (prop_pos is not None and
                        prop_pos.lower() in all_identifiers)
        has_negative = (prop_neg is not None and
                        prop_neg.lower() in all_identifiers)

        # Fall through to ID-variant search for any uncovered direction
        if not has_positive or not has_negative:
            for name in all_identifiers:
                if not any(v in name for v in variants):
                    continue
                if not has_positive and any(t in name for t in POSITIVE_TERMS):
                    has_positive = True
                if not has_negative and any(t in name for t in NEGATIVE_TERMS):
                    has_negative = True
                if has_positive and has_negative:
                    break

        if not has_positive or not has_negative:
            missing.append((fid, has_positive, has_negative))

    if missing:
        print(f"\nFinding coverage check FAILED ({len(missing)} findings missing tests):\n")
        for fid, has_pos, has_neg in missing:
            short = fid.lower().replace('-', '_')
            if not has_pos:
                print(f"  MISSING  positive test for {fid}  "
                      f"(need function with '{short}' + fires/halts/fails/emits)")
            if not has_neg:
                print(f"  MISSING  negative test for {fid}  "
                      f"(need function with '{short}' + no_fire/never/pass/absent)")
        print(f"\nEvery finding in finding_registry.def requires both test functions.")
        print(f"Add them to tests/ before merging.\n")
        sys.exit(1)
    else:
        print(f"All {len(ids)} findings have test coverage. OK.")
        sys.exit(0)


if __name__ == '__main__':
    main()
