#!/usr/bin/env bash
# tests/cli/run_all.sh
# Shell-level CLI contract tests.
# Requires tokenlint binary in PATH or passed as TL_BIN env var.
# See docs/test-strategy.md for full list of scenarios.

set -euo pipefail

TL_BIN="${TL_BIN:-tokenlint}"

pass=0
fail=0

check() {
    local desc="$1"
    local expected_exit="$2"
    shift 2
    local actual_exit=0
    "$TL_BIN" "$@" > /dev/null 2>&1 || actual_exit=$?
    if [ "$actual_exit" -eq "$expected_exit" ]; then
        echo "PASS  $desc"
        pass=$((pass + 1))
    else
        echo "FAIL  $desc (expected exit $expected_exit, got $actual_exit)"
        fail=$((fail + 1))
    fi
}

# TODO: add CLI contract tests
# Example:
# check "unknown subcommand exits 4" 4 badsubcmd
# check "--version exits 0"          0 --version

echo ""
echo "CLI tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
