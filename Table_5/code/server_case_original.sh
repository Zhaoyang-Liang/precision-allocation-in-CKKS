#!/bin/bash
#SBATCH --partition=cpu
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=24G
#SBATCH --output=logs/slurm-%j.out
#SBATCH --error=logs/slurm-%j.err
set -euo pipefail
: "${SLURM_JOB_ID:?Use Slurm}"
cd "$SLURM_SUBMIT_DIR"
test "$(hostname)" != workstation
TASK_ROOT="$PWD"
TASK_CODE_ROOT="$HOME/projects/low-n-bootstrap-20261024-r17"
TASK_CASE="$1"
TASK_SEED="$2"
TASK_TRIALS="${3:-3}"
TASK_OUT="$TASK_ROOT/results/run-$SLURM_JOB_ID"
mkdir -p "$TASK_OUT"
export LC_ALL=C GOMAXPROCS=2 GOMEMLIMIT="${PA_MEMORY:-20GiB}"
{ date -u; hostname; lscpu; awk '/Cpus_allowed_list|Mems_allowed_list/' /proc/self/status; } > "$TASK_OUT/environment.txt"
printf '%s\n' "$TASK_CASE" > "$TASK_OUT/case.txt"
cd "$TASK_CODE_ROOT/go-prototype"
TASK_BIN=fiber-rs
TASK_ARGS=(--logN 16 --logn 15 --messages 8 --r 8 --degree 63 --output-level 13 --output-bits 30 --em-bits 25 --eval-q-bits 25 --units ../units/R8-s40-calibrated.json --trials "$TASK_TRIALS" --workers 1 --active-branches 1 --check-square=false --statistics=false --inverse-sqrt-iterations 0 --application-before-return=false --calibrate-application-scale=false --chain-length 0 --amplitude .1 --seed "$TASK_SEED" --paired-timing)
case "$TASK_CASE" in
 direct16) TASK_ARGS+=(--no-rs --logn 16);;
 leaf16-15) ;;
 leaf17-15) TASK_ARGS+=(--em-bits 26 --eval-q-bits 26 --logN 17);;
 leaf16-14) TASK_BIN=fiber-rs-v2; TASK_ARGS+=(--logn 14 --output-level 1 --p-bits 26 --p-count 1 --sse-base 14 --main-base 14);;
 direct13)
  TASK_BIN=direct-smoke
  TASK_ARGS=(--trials "$TASK_TRIALS" --unit-circle=true --amplitude 1 --check-square=false --seed "$TASK_SEED" --target-bits 1 --chain-length 0 --main-base 9 --output-bits 17 --q-chain 1032193,114689,147457,163841,557057,638977,737281,786433,1097729,1130497 --input-bits 20 --ratio-bits 2 --output-level 2 --degree 63 --double-angle 1 --paired-timing --enforce-reference);;
 leaf17-13)
  TASK_BIN=fullsplit-smoke
  TASK_ARGS=(--logN 17 --logn 13 --workers 2 --trials "$TASK_TRIALS" --verify-serial=true --messages 1 --prune-only --stage-diagnostics=false --seed "$TASK_SEED" --target-bits 1 --check-square=false);;
 *) exit 2;;
esac
if [ "${PA_DIAGNOSTICS:-0}" = 1 ]; then TASK_ARGS+=(--diagnostics); fi
sha256sum "$TASK_CODE_ROOT/build/$TASK_BIN" > "$TASK_OUT/binary.sha256"
printf '%q ' "$TASK_CODE_ROOT/build/$TASK_BIN" "${TASK_ARGS[@]}" --out "$TASK_OUT/result.json" > "$TASK_OUT/command.txt"
printf '\n' >> "$TASK_OUT/command.txt"
/usr/bin/time -v -o "$TASK_OUT/resource.txt" "$TASK_CODE_ROOT/build/$TASK_BIN" "${TASK_ARGS[@]}" --out "$TASK_OUT/result.json" > "$TASK_OUT/run.log" 2>&1
