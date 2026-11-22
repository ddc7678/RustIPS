#!/usr/bin/env bash
# Compatibility wrapper for the old create-vm.sh entry point.
#
# New code should use scripts/lab/vm.sh directly. --launch is kept as an alias
# for --start so existing instructions keep working.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
args=()
for arg in "$@"; do
    case "$arg" in
        --launch) args+=(--start) ;;
        *) args+=("$arg") ;;
    esac
done

exec "$SCRIPT_DIR/vm.sh" create "${args[@]}"
