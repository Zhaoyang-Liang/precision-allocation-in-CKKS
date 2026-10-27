# Table 4: Explicit bounds and observed errors for four squarings

Four equal groups contain independent useful messages with targets (160,32,32,32). The retained allocated and ordinary diagnostic runs use inputs in [3/4,7/8] and four squarings. The paper table uses the allocated run. All-slot maxima come from error_comparison.csv; exact slot-0 values allow a separate recurrence audit. These diagnostics are not performance benchmarks.

    python3 code/regenerate.py
    python3 code/slot0_validation/verify_results.py
    cd code/engine
    go build -mod=vendor -o /tmp/ckks-bounds ./cmd/profilebench

From this table directory, validate the retained configuration without HE:

    python3 code/run_configuration.py --binary /tmp/ckks-bounds --config code/configurations/configs/allocated_joint.json

To execute a new diagnostic run, add `--run --out /tmp/ckks-bounds-new-run`. The ordinary comparison configuration is `ordinary_joint.json`.

The verifier recomputes the public certificate and verifies the four-step error recurrence using exact retained slot-0 values. Full historical slot and coefficient arrays were removed before this archive was created; the compact all-slot maxima cannot be independently rescanned here. The coefficient summary and group maxima remain available, along with exact slot-0 records. `backend_bound_log2` is the bound for the implemented backend; `paper_reference_bound_log2` is a separate reference and should not replace it silently. The last paper-table row uses an input-uniform bound.

Start with `result/reproduced/paper_data*.csv` for the displayed results. Detailed observations are retained in the result folder.
