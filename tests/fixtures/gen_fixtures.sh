#!/usr/bin/env bash
# tests/fixtures/gen_fixtures.sh
#
# Generates all JWT and JWKS test fixtures.
# Commit the outputs — do not regenerate during CI.
# Run manually when fixtures need to be updated.
#
# Requirements:
#   openssl    key generation
#   python3    JWT construction (pip install pyjwt cryptography)
#
# Usage:
#   bash tests/fixtures/gen_fixtures.sh

set -euo pipefail

FIXTURES="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Generating fixtures in: $FIXTURES"
echo ""
echo "TODO: implement fixture generation"
echo ""
echo "Each fixture should be documented in MANIFEST.md"
echo "with the line number in this script that created it."
echo ""
echo "Suggested structure:"
echo ""
echo "  # Line N: generate RSA keypair for RS256 tests"
echo "  openssl genrsa -out \$FIXTURES/jwks/rsa_rs256_private.pem 2048"
echo "  openssl rsa -in \$FIXTURES/jwks/rsa_rs256_private.pem \\"
echo "    -pubout -out \$FIXTURES/jwks/rsa_rs256_public.pem"
echo "  # convert to JWKS ..."
echo ""
echo "  # Line N: generate valid RS256 token"
echo "  python3 - << 'PYEOF'"
echo "  import jwt, json"
echo "  # ..."
echo "  PYEOF"

