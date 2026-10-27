# Security estimates

This wrapper runs the actual Lattice Estimator under SageMath. It does not replace missing estimates with heuristics. The uniform-ternary experiments use n=N, q=2^ceil(log2(QP)), unlimited samples, sigma=3.2, and RC.MATZOV, with primal_usvp, primal_bdd, and dual_hybrid. The implementation truncates noise at 19.2; this distinction is recorded in the evidence.

The retained resource-campaign estimates used commit 6019056011d10d7e9c30a0d5da2d2f729fbc2eec. Each result file records the estimator version, inputs, and attack estimates.

To produce new estimates with an installed estimator:

    sage -python estimate_cases.py --plan PARAMETER_PLAN.json --estimator /path/to/lattice-estimator --out NEW_SECURITY.json

The input-wrapper tests do not execute security estimation. The negative-mean campaign additionally retains its published parameter guideline and envelope estimate under result/metadata; nonfinite point estimates remain unavailable, not finite security claims.
