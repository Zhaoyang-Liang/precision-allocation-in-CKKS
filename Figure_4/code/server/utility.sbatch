#!/bin/bash
#SBATCH --job-name=pa08-export
#SBATCH --partition=cpu
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=2G
#SBATCH --output=logs/utility-%j.out
#SBATCH --error=logs/utility-%j.err
set -euo pipefail
cd "$SLURM_SUBMIT_DIR"
test "$(hostname)" != workstation
export LC_ALL=C PYTHONINTMAXSTRDIGITS=0
export PYTHONPATH="$PWD/code/python_deps"
PA_PYTHON="$HOME/projects/ckks-codex-20260910/work/python/bin/python3"
"$PA_PYTHON" "$@"
