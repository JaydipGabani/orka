#!/bin/bash
set -euo pipefail
if ! go build -o "${TMPDIR:-/tmp}/quantity-client" /src/client.go; then
  exit 125
fi
exec "${TMPDIR:-/tmp}/quantity-client" "$@"
