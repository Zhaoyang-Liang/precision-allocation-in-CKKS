# Security-estimation source

The retained evidence is in ../../result/security. The scripts here write to ../../result/recomputed_security by default, leaving archived estimates unchanged. Set CKKS_SECURITY_WORK to use another output directory. Set LATTICE_ESTIMATOR to the path of the required Lattice Estimator checkout before the first new run. Use the commit recorded in the evidence when reproducing it.

Run under Sage Python:

    sage -python run_estimates.py
    sage -python run_sparse_estimates.py
    sage -python summarize_estimates.py

The sparse-secret model and nonfinite attack costs are documented in the retained inputs and security report. New estimates have not been executed during packaging. The original server and runtime information in the archived result files is historical provenance.
