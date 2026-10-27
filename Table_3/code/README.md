# Table 3: Tuple CKKS comparison

The complete Go benchmark, its dependencies, 20 configurations, two recorded
security estimates, and all 20 run records are included. Ten paired repetitions
evaluate eight squarings at N=32768 on the same inputs in [255/256,1), with 8192
useful outputs targeting 80 bits. The remaining 8192 inputs are nonzero; their
targets differ between methods: 1 bit for precision allocation and 32 bits for
Tuple CKKS. The comparison uses a Lattigo reference implementation of Tuple
CKKS, not the authors' optimized HEaaN implementation.

## Regenerate the table

Run from the Table_3 directory:

    python3 code/regenerate.py

This checks the retained source, configurations, paired inputs, and records,
then regenerates `result/reproduced/paper_data.csv`. It does not rerun encrypted
computation or security estimation.

## Build and run a new experiment

Go 1.24 or later and Python 3 are required. Dependencies are included in
`engine/vendor/`; the build does not need to download them.

    bash code/build.sh /tmp/ckks-table3-bin
    python3 code/run_benchmark.py --repeat 1 --binaries /tmp/ckks-table3-bin --check-only

The check prepares both methods' parameters without encrypted evaluation.
To execute both methods, use a new output directory:

    python3 code/run_benchmark.py --repeat 1 --binaries /tmp/ckks-table3-bin --out /tmp/ckks-table3-r01

Use repetitions 1 through 10 with separate output directories to reproduce
the campaign. The wrapper uses the recorded input seeds, alternates method
order, limits each process to one Go thread, and retains failures. Encryption
and key generation use fresh randomness. Recorded timings were collected on
an Intel Xeon Gold 6240R; new timings depend on the machine and software.

## Files

- `engine/`: complete benchmark source and vendored dependencies.
- `configurations/`: ten configurations per method and the original experiment
  specification, stored as `experiment.json`. Its hashes are checked by the
  benchmark before evaluation; the wrapper resolves its historical paths to
  the included files.
- `configurations/evidence/`: the two original five-attack security estimates.
- `security/`: instructions and a script for rerunning those estimates.
- `../result/source_data/results/`: all ten paired repetitions.

The reported evaluation time and output storage use the native representation;
conversion to ordinary CKKS is recorded separately. The comparison fixes the
slot layout and measures useful-slot accuracy. It does not optimize Tuple
CKKS packing for a different layout.
