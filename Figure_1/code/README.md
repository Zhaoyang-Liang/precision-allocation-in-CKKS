# Figure 1: Precision transfer and recoverable depth

N=32768, log2 Q approximately 744, log2 P approximately 112, initial scale 2^92, average precision target 64 bits, and at most seven squarings. Two or four precision classes contain 4096 useful inputs in [1,2] or their reciprocals. Recovery failure is distinguished from failing a useful-slot precision target. The retained campaign has 2032 runs and 7914 layer records; curves show the median recoverable depth at each tested transfer. F means failure before the first squaring.

From this figure directory:

    python3 code/regenerate.py
    cd code
    go build -mod=vendor -o /tmp/ckks-depth ./cmd/boundary

A fresh run (potentially expensive; output paths must be new):

    /tmp/ckks-depth -mode keys -settings parameters/settings.json -out /tmp/ckks-depth-new-keys
    /tmp/ckks-depth -mode run -settings parameters/settings.json -unit parameters/units/r2_theta0080.json -keys /tmp/ckks-depth-new-keys -input grow -out /tmp/ckks-depth-new-run

Use `shrink` for reciprocal inputs. Exact units and settings are in `code/parameters/`; Python construction and export routines are in `code/python/`. `runs.csv` supplies the plotted points; `layers.csv`, `boundaries.csv`, `units.csv`, and `examples.csv` retain the detailed evidence.

Start with `result/reproduced/paper_data*.csv` for the displayed results. Detailed observations are retained in the result folder.
