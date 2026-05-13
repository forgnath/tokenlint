#!/usr/bin/env python3
"""
tools/check_coverage.py

Verify that every finding in finding_registry.def has both:
  test_<ID>_fires()
  test_<ID>_no_fire()

somewhere in the tests/ directory.

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

def load_finding_ids(registry_path):
    """Parse finding_registry.def and return list of string IDs."""
    ids = []
    pattern = re.compile(r'X\(\s*\w+\s*,\s*"(TL-[A-Z]\d+)"\s*\)')
    with open(registry_path) as f:
        for line in f:
            m = pattern.search(line)
            if m:
                ids.append(m.group(1))
    return ids

def scan_test_functions(test_dir):
    """Scan all .c and .sh files under test_dir for test function names."""
    found = set()
    patterns = ['**/*.c', '**/*.sh']
    for pat in patterns:
        for path in glob.glob(os.path.join(test_dir, pat), recursive=True):
            try:
                content = open(path).read()
                # Match test_TL_V003_fires and test_TL_V003_no_fire
                # Also match with hyphens replaced by underscores
                for m in re.finditer(r'test_(TL[_-][A-Z]\d+)_(fires|no_fire)', content):
                    raw = m.group(1).replace('_', '-', 1)  # TL_V003 → TL-V003
                    suffix = m.group(2)
                    found.add((raw, suffix))
            except Exception:
                pass
    return found

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

    found = scan_test_functions(test_dir)
    missing = []

    for fid in ids:
        has_fires   = (fid, 'fires')   in found
        has_no_fire = (fid, 'no_fire') in found
        if not has_fires or not has_no_fire:
            missing.append((fid, has_fires, has_no_fire))

    if missing:
        print(f"\nFinding coverage check FAILED ({len(missing)} findings missing tests):\n")
        for fid, has_fires, has_no_fire in missing:
            if not has_fires:
                print(f"  MISSING  test_{fid.replace('-','_')}_fires()")
            if not has_no_fire:
                print(f"  MISSING  test_{fid.replace('-','_')}_no_fire()")
        print(f"\nEvery finding in finding_registry.def requires both test functions.")
        print(f"Add them to tests/ before merging.\n")
        sys.exit(1)
    else:
        print(f"All {len(ids)} findings have test coverage. OK.")
        sys.exit(0)

if __name__ == '__main__':
    main()
