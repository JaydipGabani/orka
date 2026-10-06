#!/bin/bash
set -euo pipefail
if [[ "${ORKA_LISTEN_FD:-}" != 3 ]]; then
  exit 125
fi
if ! gcc -std=c11 -Wall -Wextra -Werror /checks/service.c -o "${TMPDIR:-/tmp}/inventory-service" 3<&-; then
  exit 125
fi
exec "${TMPDIR:-/tmp}/inventory-service"
