# Table 2: Resources for 224-bit output precision

The three rows select 256 inputs in [1,2], six squarings, and a 224-bit useful-slot target. The selection rule is min_N_then_Q. Online time is the median of five runs; precision is the worst observed over those runs. Security values come from retained estimator evidence. `result/paper_table.tex` is the exact table source excerpt and depends on the paper's preamble.

    python3 code/regenerate.py

## Rebuilding and running the retained candidate family

From this artifact directory:

    cd code/engine
    go build -mod=vendor -o /tmp/ckks-profilebench ./cmd/profilebench

Return to the artifact directory. To freeze a new campaign using the retained selection and security evidence (public planning, no HE evaluation):

    python3 code/cost_campaign.py freeze --selection code/configurations/small_m256_p224_k6_grow/selection.json --binary /tmp/ckks-profilebench --out /tmp/ckks-resource-new-campaign

To execute it (expensive; five repeats for each selected candidate):

    python3 code/cost_campaign.py run --campaign /tmp/ckks-resource-new-campaign --binary /tmp/ckks-profilebench --out /tmp/ckks-resource-new-runs

Choose another selection.json under code/configurations for another task. The archive retains 548 measured configurations and 2740 runs across 144 tasks. Public units, finite search summaries, per-candidate security evidence, estimator wrappers, and the exact integer reference logic are included. Temporary full run directories and ciphertext/key dumps were removed in the original retention process; compact CSVs preserve their summaries and provenance hashes. The original end-to-end audit expects a newly executed run directory. Use regenerate.py to extract the displayed data from the retained CSVs. Native runtime and hardware can change new timings.

Start with `result/reproduced/paper_data*.csv` for the displayed results. Detailed observations are retained in the result folder.
