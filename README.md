# CKKS Experiments

This folder contains the experiment code, parameters, and recorded results
for the paper. Folders are named after the corresponding figure or table.

| Folder | Experiment |
|---|---|
| [Figure_1](Figure_1/) | Precision transfer and supported computation depth |
| [Figure_2](Figure_2/) | Modulus and ring dimension at different precision requirements |
| [Figure_3](Figure_3/) | Precision transfer, useful-slot capacity, and runtime |
| [Figure_4](Figure_4/) | Zero and negative average precision requirements |
| [Table_2](Table_2/) | Resource comparison at 224-bit precision |
| [Table_3](Table_3/) | Comparison with Tuple CKKS |
| [Table_4](Table_4/) | Measured errors and theoretical bounds |

Table 1 contains analytical operation counts and has no experimental dataset.

Each experiment folder contains:

- `code/`: source code, parameters, and instructions for running the experiment.
- `result/`: recorded results and summary data.

To view the numbers used in the paper, open `result/reproduced/paper_data*.csv`.
To regenerate these summaries from the recorded results, run this command
inside the corresponding figure or table folder:

```sh
python3 code/regenerate.py
```

To run a new experiment, follow that folder's `code/README.md` and save the
new results in a separate directory. Python 3 is needed for summaries, Go
for encrypted computation, and SageMath for security estimation. Experiment
instructions specify any additional requirements. Runtime measurements
will depend on the machine used.
