# Table 5: Ring-switching bootstrapping performance

The same six configurations generate Tables 4 and 5. Both folders contain complete copies so each can be moved independently. Data are from the final bootstrap-only campaign (18 jobs, 93 paired serial/parallel trials); the source is the corresponding retained round-17 code. No application or frontend is included in the timed output. Results are measured after returning to the original ring.

From this table directory:

    python3 code/audit_results.py
    python3 code/regenerate.py
    bash code/build.sh /tmp/ckks-bootstrap-binaries

A fresh local execution (potentially memory-intensive):

    bash code/run_case.sh leaf16-15 202610241801 /tmp/ckks-bootstrap-new-run /tmp/ckks-bootstrap-binaries 3

Available cases: direct16, leaf16-15, leaf17-15, leaf16-14, direct13, leaf17-13. The direct13 case uses 16 trials per key; all other cases use 3. The run list `result/formal-jobs.tsv` identifies the three independent seeds per case. `go-prototype-v2` is used only for leaf16-14; its binary is named fiber-rs-v2. Public units and both modified dependency snapshots are included. Default build/run wrappers need Go and Bash, not Slurm. The original Slurm driver is also included.

`result/raw_runs/` preserves the 18 job outputs, logs, commands, hardware, and resource records. `result/security/` contains exact estimator inputs and outputs. The audit rederives the saved summary and verifies all 93 serial/parallel pairs and output targets. Stage times use parallel mode; ModRaise includes SSE and lift/trace. Server key sizes are serialized evaluation material in GiB. New local timing is not comparable to the recorded Intel Xeon Gold 6240R measurements without controlling the environment.

Table columns, in order, are leaf17-15, leaf17-13, direct16, leaf16-15, leaf16-14, direct13. `result/paper_table.tex` is the exact source excerpt; it depends on the paper's preamble. Security scripts are under code/security and use a separate output directory.


`result/table_parameters.json` records the six configurations and their associated runs.

Start with `result/reproduced/paper_data*.csv` for the displayed results. Detailed observations are retained in the result folder.
