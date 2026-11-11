#!/usr/bin/env bash
# Decodes base64url (RFC 4648 §5) from standard input, restoring the padding it
# omits. Needs bash (3.2 or later) and base64.
set -euo pipefail
s=$(tr -d '\n' | tr '_-' '/+')
while (( ${#s} % 4 )); do s+="="; done
printf '%s' "$s" | base64 -d
