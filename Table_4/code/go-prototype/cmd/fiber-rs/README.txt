Fiber RS + PA driver

This executable runs the whole top-ring/leaf-ring round trip. No secret-key
access is used by the online leaf refresh. Decode/carry diagnostics occur only
after timing (or in a separate identical rerun when --diagnostics is enabled).

Pipeline
1. k independent complex messages per leaf are repeated at focus slots
   s%R==0, message index (s/R)%k. Guards are zero. Build inverse-unit leaf
   plaintexts, coefficient-merge them, encrypt in top ring, then multiply g.
2. Input is genuinely level1. Ring entry performs a real KS and all coefficient
   branches are retained. Default --shape-entry=true conjugates this KS/Split by
   g^-1 and g; --shape-entry=false is the ordinary-entry ablation.
3. Ordinary fiber StC at level1 with plaintext scale q1, then ordinary rescale,
   leaves level0 and measures its actual scale. beta = q0 / actual StC scale.
4. Same-ring SSE main->H32 KS at q0*P; centered public component lift to main Q;
   sparse->uniform-main KS; raw trace at rotations k,2k,... with no division.
5. Ordinary fiber CtS gain = 2^EM/(2*q0*K*(slots/k)). At its high scale,
   conjugation+addition yields real, subtraction and exact -i yields imaginary.
   Each is then PA-rescaled once. No modular inverse of 2 is substituted for a
   CKKS division. Plaintext CtS diagonal scale is the final 61-bit prime.
6. PA EvalMod receives actual normalized input (I+z/beta)/K and target fractional
   scale beta*2^outputBits. Optional inverse-degree>0 executes genuine arcsin
   with its added depth. Real/imag are recombined.
7. Conjugated return KS: inverse g, coefficient Merge, actual return key switch,
   multiply g. Output level is checked, followed by actual square/relin/rescale.

Defaults
logN16, logn15, k64, R4, degree31+DA3, output level3, input scale40,
output scale35, EM scale40, q0bits50, EvalMod primes40, CtS prime61,
P=two 55-bit primes. Main/top secret is uniform ternary P(nonzero)=2/3;
SSE is fixed-total H32 with independent signs. All primes are generated for
TOP degree, and reused in leaf parameters. The security reference 868/162 is
only a model screening label, not a certification. Actual logQP is reported.

The executable needs an explicit unit candidate for power>0, e.g.
  --units ../../units/candidates/R2-s8-calibrated.json --r 2
--power0 ignores the unit file and uses exact identity, preserving the same
fiber layout and transforms. This is the relevant PA arithmetic ablation.
Different process runs use independent cryptographic randomness; they are not
paired same-key measurements. --seed controls payloads only.

Dry runs perform no key generation or encryption and need no unit file:
  go run ./cmd/fiber-rs --dry-run --output-level 9 --out dry-L9.json
  go run ./cmd/fiber-rs --dry-run --degree 63 --output-level 8 --out dry-d63-L8.json
The latter has one extra EvalMod level and main logQP about861 bits; degree63
with output9 exceeds the 868-bit reference (about896).

Suggested HPC first candidates (build once with -mod=vendor):
  ./fiber-rs --messages 8 --r 2 --degree 63 --output-level 8 \
    --units ../../units/candidates/R2-s8-calibrated.json --diagnostics --trials 3
  ./fiber-rs --messages 8 --r 2 --degree 63 --output-level 8 --power 0 --trials 3
  ./fiber-rs --messages 64 --r 4 --degree 63 --output-level 8 \
    --units ../../units/candidates/R4-s8-calibrated.json --diagnostics --trials 3
Use --out for each result. --workers 1 or2 selects actual branch concurrency;
all leaf evaluators have independent scratch state. Matrices and keys are shared
immutable. Record GOMAXPROCS and allocated CPUs with the server job.

Metrics
All precision bits are -log2 absolute error, not relative precision. MaxErrorBits
uses worst active slot; MeanErrorBits and RMSBits are also reported. Top reference
is an independently ordinary-encoded/merged ideal plaintext (inputScale40), not
the noisy input ciphertext. Leaf references are the original message vectors.
Initial and PreBootstrap are level1 here, InternalMaximum is the large lifted Q,
Output is actual returned Q. These must not be conflated. Square compares to the
actual intended top-slot value squared. No prior application is invented.

With --diagnostics, branch CtS data yields a nearest-integer carry diagnostic,
readout error, pure approximation error and oracle-vs-message error. This is a
posterior diagnostic using the known test message, not an online decoding step or
a formal failure-probability bound. Diagnostics rerun must match timed ciphertext.

Local verification only used N512->256, k8, R2, never production-sized FHE.
Full mathematical interface, real ciphertext flow, all intermediate levels,
returned level3, and subsequent square level2 pass. Degree63 + calibrated R2-s8
candidate produced about21.9-22.4 bits in two independent small-ring samples;
this is NOT evidence that N65536->32768 will meet20bits. Server tests determine
that. Power0 small-ring output was about13.35bits. Root-level ordinary and race
suites also passed. No keys or ciphertexts are serialized in result JSON.
