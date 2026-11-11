#!/usr/bin/env bash
# Encodes standard input as base64url (RFC 4648 §5), without padding or a final
# newline. Needs bash (3.2 or later) and base64.
set -euo pipefail
base64 | tr '+/' '-_' | tr -d '=\n'
