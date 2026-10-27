"""Rerun the five recorded classical lattice estimates using SageMath."""
import argparse
import json
import math
import subprocess
import sys
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--case", choices=("fewer_s70", "tuple_base102"), required=True)
parser.add_argument("--estimator", type=Path, required=True, help="Lattice Estimator checkout at the recorded commit")
parser.add_argument("--out", type=Path, required=True, help="New output file; existing files are never overwritten")
args = parser.parse_args()
commit = "53da5982597709ba0fdf94ea37a84d822310fd84"
checkout = args.estimator.resolve()
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip() == commit
assert not subprocess.check_output(["git", "diff", "HEAD", "--", "estimator"], cwd=checkout)
sys.path.insert(0, str(checkout))
from sage.all import ZZ, oo, log
from estimator import LWE, ND, RC

evidence = Path(__file__).resolve().parents[1] / "configurations/evidence" / (args.case + ".json")
old = json.loads(evidence.read_text())
qp = math.prod(map(int, old["Q"] + old["P"]))
assert qp == int(old["qp_exact"])
bits = (qp - 1).bit_length()
assert bits == old["estimator_q_bits"]
problem = LWE.Parameters(n=old["N"], q=ZZ(2) ** bits,
                         Xs=ND.SparseBinomial(eta=1, hw=128, n=old["N"]),
                         Xe=ND.DiscreteGaussian(3.2), m=oo)
attacks = [("primal_usvp", LWE.primal_usvp, {}),
           ("primal_bdd", LWE.primal_bdd, {}),
           ("primal_hybrid_mitm", LWE.primal_hybrid, {"mitm": True, "babai": True}),
           ("primal_hybrid_bdd", LWE.primal_hybrid, {"mitm": False, "babai": False}),
           ("dual_hybrid_matzov", LWE.dual_hybrid, {})]
args.out.parent.mkdir(parents=True, exist_ok=True)
with args.out.open("x") as stream:
    stream.write("{}\n")
result = {"case": args.case, "N": old["N"], "Q": old["Q"], "P": old["P"],
          "estimator_q_bits": bits, "estimator_commit": commit,
          "secret_model": old["secret_model"], "cost_model": "RC.MATZOV",
          "scope": old["scope"], "attacks": {}, "finished": False}
for label, function, kwargs in attacks:
    start = time.monotonic()
    try:
        cost = function(problem, red_cost_model=RC.MATZOV, **kwargs)
        work = float(log(cost["rop"], 2))
        entry = {"log2_rop": work if math.isfinite(work) else str(work), "finite": math.isfinite(work),
                 "target128_pass": math.isfinite(work) and work >= 128,
                 "raw_cost": {str(k): str(v) for k, v in cost.items()}}
    except Exception as error:
        entry = {"error": repr(error), "target128_pass": False}
    entry["seconds"] = time.monotonic() - start
    result["attacks"][label] = entry
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(label, entry.get("log2_rop", entry.get("error")), flush=True)
result["finished"] = True
result["target128_pass"] = all(a["target128_pass"] for a in result["attacks"].values())
args.out.write_text(json.dumps(result, indent=2) + "\n")
