#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
[[ -r /etc/os-release ]] || { echo "Cannot identify Linux distribution."; exit 1; }
# shellcheck disable=SC1091
. /etc/os-release

case "${ID:-}" in
  manjaro|arch)
    exec "$ROOT/install-manjaro.sh" "$@"
    ;;
  ubuntu|debian|linuxmint|pop)
    exec "$ROOT/install-ubuntu.sh" "$@"
    ;;
  *)
    if [[ " ${ID_LIKE:-} " == *" arch "* ]]; then
      exec "$ROOT/install-manjaro.sh" "$@"
    elif [[ " ${ID_LIKE:-} " == *" debian "* ]]; then
      exec "$ROOT/install-ubuntu.sh" "$@"
    fi
    echo "Unsupported distribution: ${PRETTY_NAME:-${ID:-unknown}}"
    echo "Use install-manjaro.sh or install-ubuntu.sh manually only if you have verified compatibility."
    exit 1
    ;;
esac
