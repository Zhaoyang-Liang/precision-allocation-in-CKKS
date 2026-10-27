# Figure 3: Transfer and useful-message capacity tradeoffs

Panel (a) uses theta_Q.csv at depth=4 and queried_for_layout_theta=True. Missing selected candidates are not plotted as successful points. Panel (b) selects capacity/boundary tasks at depth=4 with priority=online_word_proxy. Its y-axis is speedup, computed as the median CKKS online time divided by the method's median online time for the same message count and input family. Every batch required for the requested message count is included.

    python3 code/regenerate.py

`regenerate.py` computes the speedup values used in the paper.
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
