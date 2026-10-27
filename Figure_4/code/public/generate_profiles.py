#!/usr/bin/env python3
"""Public construction outputs, never HE results. Refuses to overwrite."""
import argparse
import json
from pathlib import Path
from multipliers import design_profile

ap = argparse.ArgumentParser()
ap.add_argument("out")
args = ap.parse_args()
profiles = [[160,32,32,32], [96,80,48,32], [96,32,96,32]]
profiles += [[b] + [0]*(r-1) for b in [96,160,224] for r in [2,4,8]]
rows = [design_profile(p) for p in profiles]
with Path(args.out).open("x", encoding="utf-8") as f:
    json.dump({"HE_executions":0,"profiles":rows},f,indent=2)
for row in rows:
    print(row["target_bits"], "coeff_bits",row["coefficient_bits"],
          "log_weight_deviation",round(row["max_log2_deviation_display"],4))
