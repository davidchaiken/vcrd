#!/usr/bin/env bash
# Prints the JWK (RFC 8037 §2) of an Ed25519 did:key (did:key v0.9), in the form
# RFC 7638 hashes for a thumbprint. Needs bash (3.2 or later), bc, xxd and base64.
set -euo pipefail
here=$(dirname "$0")
did=${1:?usage: did-key-jwk.sh DID}
alphabet=123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
# z: the multibase prefix for base58btc.
b58=${did#did:key:z}
if [[ $b58 == "$did" || -z $b58 || $b58 == *[!$alphabet]* ]]; then
  echo "did-key-jwk.sh: not a base58btc did:key: $did" >&2
  exit 1
fi
# Each character's position in the alphabet is one base-58 digit. bc prints the
# number in hexadecimal, and wraps long lines with a backslash.
hex=$( { echo 'obase=16; n=0'
         for (( i = 0; i < ${#b58}; i++ )); do
           p=${alphabet%%"${b58:i:1}"*}
           echo "n=n*58+${#p}"
         done
         echo n; } | bc | tr -d '\\\n' )
# The multicodec prefix 0xed, ed25519-pub, as an unsigned varint; then the 32-byte
# key. The prefix leaves no leading zero for bc to drop.
if [[ $hex != ED01* || ${#hex} -ne 68 ]]; then
  echo "did-key-jwk.sh: not an Ed25519 did:key: $did" >&2
  exit 1
fi
x=$(printf '%s' "${hex#ED01}" | xxd -r -p | "$here/b64url-encode.sh")
printf '{"crv":"Ed25519","kty":"OKP","x":"%s"}\n' "$x"
