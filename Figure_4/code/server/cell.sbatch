#!/bin/bash
#SBATCH --job-name=pa08-mean-cell
#SBATCH --partition=cpu
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=3G
#SBATCH --output=logs/cell-%A-%a.out
#SBATCH --error=logs/cell-%A-%a.err
set -euo pipefail
cd "$SLURM_SUBMIT_DIR"
test "$(hostname)" != workstation
export LC_ALL=C GOMAXPROCS=1 GOMEMLIMIT=2GiB PYTHONINTMAXSTRDIGITS=0
export PYTHONPATH="$PWD/code/python_deps"
PA_PYTHON="$HOME/projects/ckks-codex-20260910/work/python/bin/python3"
PA_MODE="${1:-formal}"
PA_EXTRA=()
if [ "$PA_MODE" = pilot ]; then PA_EXTRA=(--pilot); fi
"$PA_PYTHON" code/zero_mean_experiment.py run --task-index "$SLURM_ARRAY_TASK_ID" --binary "$PWD/build/zeromean" --out "$PWD/results/${PA_MODE}_${SLURM_ARRAY_JOB_ID}/cell_${SLURM_ARRAY_TASK_ID}" "${PA_EXTRA[@]}"
