#!/bin/bash
#SBATCH --job-name=pa08-build
#SBATCH --partition=cpu
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=3G
#SBATCH --output=logs/build-%j.out
#SBATCH --error=logs/build-%j.err
set -euo pipefail
cd "$SLURM_SUBMIT_DIR"
test "$(hostname)" != workstation
export LC_ALL=C GOMAXPROCS=2 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
export GOCACHE="$PWD/build/go-cache"
export PATH="$HOME/projects/ckks-codex-20260910/work/go/bin:$PATH"
PA_ROOT="$PWD"
cd code/engine
go test -mod=vendor ./internal/zeromean
go build -mod=vendor -o "$PA_ROOT/build/zeromean" ./cmd/zeromean
sha256sum "$PA_ROOT/build/zeromean" > "$PA_ROOT/build/binary.sha256"
