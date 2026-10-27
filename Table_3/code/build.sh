#!/usr/bin/env bash
set -euo pipefail
code_dir="$(cd "$(dirname "$0")" && pwd)"
destination="${1:?Usage: bash code/build.sh /absolute/path/to/binaries}"
mkdir -p "$destination"
destination="$(cd "$destination" && pwd)"
cd "$code_dir/engine"
GOWORK=off go build -mod=vendor -trimpath -o "$destination/precisionbench" ./cmd/precisionbench
GOWORK=off go build -mod=vendor -trimpath -o "$destination/tuplebench" ./cmd/tuplebench
printf 'Built precisionbench and tuplebench in %s\n' "$destination"
