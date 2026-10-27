"""Index the exact units used by measured configurations, without timing claims."""
import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--runs', type=Path, required=True)
    ap.add_argument('--units', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    with args.runs.open() as f:
        used = sorted({(int(r['classes']), int(r['theta'])) for r in csv.DictReader(f)})
    rows = []
    ids = defaultdict(set)
    for classes, theta in used:
        path = args.units / f'r{classes}_theta{theta:04d}.json'
        unit = json.loads(path.read_text())
        coeff = [int(x) for x in unit['coefficients']]
        inv = [int(x) for x in unit['inverse_coefficients']]
        identity = hashlib.sha256(json.dumps([classes, coeff], separators=(',', ':')).encode()).hexdigest()
        ids[classes].add(identity)
        logs = unit['actual_log2_weights_display']
        rows.append(dict(classes=classes, theta=theta,
                         nominal_useful_gain_bits=(classes - 1) * theta,
                         actual_useful_weight_gain_bits_display=-float(logs[0]),
                         unit_coefficient_bits=max(abs(x).bit_length() for x in coeff),
                         inverse_coefficient_bits=max(abs(x).bit_length() for x in inv),
                         nonzero_unit_terms=sum(x != 0 for x in coeff),
                         nonzero_inverse_terms=sum(x != 0 for x in inv),
                         max_log2_deviation_display=unit['max_log2_deviation_display'],
                         actual_log2_weights_display=json.dumps(logs),
                         identical_unit_id=identity,
                         parameter_file_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / 'units.csv').open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    summary = {
        'measured_nominal_unit_configurations': len(rows),
        'distinct_exact_units_by_class_count': {str(k): len(v) for k, v in ids.items()},
        'maximum_unit_coefficient_bits': max(x['unit_coefficient_bits'] for x in rows),
        'maximum_inverse_coefficient_bits': max(x['inverse_coefficient_bits'] for x in rows),
        'maximum_log2_deviation_display': max(float(x['max_log2_deviation_display']) for x in rows),
        'scope': 'Nominal theta is sampled on an integer grid, but exact units are discrete and adjacent nominal points may use the same unit. Weight logarithms here are display values; exact rational embedding intervals remain in the unit JSON. Coefficient sizes are original integer sizes, not modulo-Q storage sizes and not runtime measurements.'
    }
    (args.output / 'units_summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
