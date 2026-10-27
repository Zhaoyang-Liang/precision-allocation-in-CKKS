# Figure 4: Zero and negative average precision targets

N=32768 and 256 useful messages with a 20-bit target. Panels show depths 0 and 4 for inputs in [1,2] or their reciprocals. The retained campaign also includes depths 1 and 2. Average targets are 10, 0, -10, and -20 bits. The CKKS reference is extended horizontally for comparison. F marks a failed search-ceiling candidate, not a successful measurement.

There are 72 tasks, 1500 run attempts, 4270 layer records, and five final validation runs per task. Exactly 71 tasks meet both recovery and the useful-slot target. These are empirical candidates from the declared family, not globally minimal moduli. They do not pass the original generic sufficient bound; failure of that bound is not equivalent to decryption failure. The unused-slot precision target is not an output acceptance condition.

From this figure directory:

    python3 code/regenerate.py
    python3 code/audit_results.py
    cd code/engine
    go build -mod=vendor -o /tmp/ckks-zero-mean ./cmd/zeromean

From this figure directory, start a new experiment with:

    PYTHONDONTWRITEBYTECODE=1 python3 code/zero_mean_experiment.py run --task-index 8 --binary /tmp/ckks-zero-mean --out /tmp/ckks-zero-mean-new-run

Task 8 uses four classes, average target -20, growing inputs, and depth 0. `code/configurations/tasks.json` and `selected_parameters.json` retain task definitions and chosen schedules. Security inputs, estimator outputs, guideline, and envelope evidence are in `result/metadata/`. Timing fields in this diagnostic campaign are not performance measurements. Server scripts retain historical environment assumptions.

Start with `result/reproduced/paper_data*.csv` for the displayed results. Detailed observations are retained in the result folder.
