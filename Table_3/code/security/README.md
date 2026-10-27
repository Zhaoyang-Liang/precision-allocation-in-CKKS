# Security estimates

The recorded estimates are in `../configurations/evidence/`. They use the
actual Q and P primes, degree 32768, fixed Hamming weight 128 with independent
random signs, Gaussian noise with sigma 3.2, and five classical lattice
attack estimates with the MATZOV cost model. The recorded minima are 132.54
bits for precision allocation and 138.04 bits for Tuple CKKS.

To rerun an estimate, use SageMath and a checkout of
https://github.com/malb/lattice-estimator at commit
`53da5982597709ba0fdf94ea37a84d822310fd84`:

```sh
sage -python code/security/estimate.py --case fewer_s70 --estimator /path/to/lattice-estimator --out /tmp/table3-unit-security.json
sage -python code/security/estimate.py --case tuple_base102 --estimator /path/to/lattice-estimator --out /tmp/table3-tuple-security.json
```

These are heuristic estimates for the recorded classical attacks, not a
security proof. New estimates are written separately from the retained data.
