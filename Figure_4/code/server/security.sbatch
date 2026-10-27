#!/bin/bash
#SBATCH --job-name=pa08-security
#SBATCH --partition=cpu
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=3G
#SBATCH --output=logs/security-%A-%a.out
#SBATCH --error=logs/security-%A-%a.err
set -euo pipefail
cd "$SLURM_SUBMIT_DIR"
test "$(hostname)" != workstation
export LC_ALL=C PYTHONINTMAXSTRDIGITS=0 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
export DOT_SAGE="$PWD/build/dot-sage-$SLURM_ARRAY_TASK_ID"
mkdir -p "$DOT_SAGE"
PA_PYTHON="$HOME/projects/ckks-codex-20260910/work/python/bin/python3"
"$HOME/projects/tuple8-study-20261017-a/tools/sage/bin/sage" -python -c 'import sys; print(sys.executable); print(sys.version)'
"$PA_PYTHON" code/server/security_worker.py
