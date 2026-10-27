#!/bin/bash
#SBATCH --job-name=pa08-mean-worker
#SBATCH --partition=cpu
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=6
#SBATCH --mem=18G
#SBATCH --output=logs/worker-%A-%a.out
#SBATCH --error=logs/worker-%A-%a.err
set -euo pipefail
cd "$SLURM_SUBMIT_DIR"
test "$(hostname)" != workstation
export LC_ALL=C GOMAXPROCS=1 GOMEMLIMIT=2GiB PYTHONINTMAXSTRDIGITS=0
export PYTHONPATH="$PWD/code/python_deps"
PA_PYTHON="$HOME/projects/ckks-codex-20260910/work/python/bin/python3"
"$PA_PYTHON" code/server/run_worker.py
