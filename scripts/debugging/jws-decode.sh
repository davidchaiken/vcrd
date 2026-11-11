#!/usr/bin/env bash
# Prints the header and then the payload of a compact JWS (RFC 7515 §7.1), each as
# JSON. This bypasses vcrd's masking: every claim value prints in cleartext.
# Needs bash (3.2 or later), base64 and jq.
set -euo pipefail
here=$(dirname "$0")
jws=${1:?usage: jws-decode.sh FILE}
echo "jws-decode.sh: claim values are not masked" >&2
for n in 1 2; do
  cut -d. -f"$n" "$jws" | "$here/b64url-decode.sh" | jq .
done
