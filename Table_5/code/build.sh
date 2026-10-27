#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 1 ]; then echo "Usage: build.sh NEW_BINARY_DIRECTORY" >&2; exit 2; fi
TASK_CODE_ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$1"
TASK_BINARY_DIR="$(cd "$1" && pwd)"
cd "$TASK_CODE_ROOT/go-prototype"
for TASK_COMMAND in fiber-rs direct-smoke fullsplit-smoke; do
  "${GO:-go}" build -mod=vendor -o "$TASK_BINARY_DIR/$TASK_COMMAND" "./cmd/$TASK_COMMAND"
done
cd "$TASK_CODE_ROOT/go-prototype-v2"
"${GO:-go}" build -mod=vendor -o "$TASK_BINARY_DIR/fiber-rs-v2" ./cmd/fiber-rs
