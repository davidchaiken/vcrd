#!/usr/bin/env bash
# Prints the RFC 7638 thumbprint of a JWK read from standard input: SHA-256 over
# its required members (RFC 8037 §2 for an OKP key), in lexicographic order and
# with no whitespace, encoded as base64url. OKP keys only, so far. Needs bash (3.2
# or later), jq, openssl and base64.
set -euo pipefail
here=$(dirname "$0")
jwk=$(jq -cjS 'if .kty == "OKP" then {crv, kty, x} else error("OKP keys only") end')
printf '%s' "$jwk" | openssl dgst -sha256 -binary | "$here/b64url-encode.sh"
echo
