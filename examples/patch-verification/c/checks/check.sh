#!/bin/bash
set -euo pipefail
if ! gcc -std=c11 -Wall -Wextra -Werror /src/order.c /checks/check.c -o "${TMPDIR:-/tmp}/quantity-check"; then
  exit 125
fi
exec "${TMPDIR:-/tmp}/quantity-check" "$@"
