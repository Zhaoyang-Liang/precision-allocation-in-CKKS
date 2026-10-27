"""Rebuild the Tuple CKKS comparison from the supplied paired run records."""
from pathlib import Path
import collections
import csv
import hashlib
import json
import math
import statistics

SOURCE = Path(__file__).resolve().parents[1] / "result/source_data"
OUTPUT = Path(__file__).resolve().parents[1] / "result/reproduced"
CODE = Path(__file__).resolve().parent
SPEC = CODE / "configurations/experiment.json"
experiment = json.loads(SPEC.read_text())
experiment_hash = hashlib.sha256(SPEC.read_bytes()).hexdigest()
for name, expected in experiment["source_files"].items():
    assert hashlib.sha256((CODE / "engine" / name).read_bytes()).hexdigest() == expected
for task in experiment["tasks"]:
    config = CODE / "configurations" / Path(task["config"]).name
    assert hashlib.sha256(config.read_bytes()).hexdigest() == task["config_sha256"]
for evidence in experiment["security_evidence"].values():
    path = CODE / "configurations" / evidence["path"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == evidence["sha256"]
rows = list(csv.DictReader((SOURCE / "tuple_paired_runs.csv").open(encoding="utf-8-sig")))
assert len(rows) == 20
observations = collections.defaultdict(list)
files = {}
pair_checks = []


def read(path):
    raw = path.read_bytes()
    files[str(path.relative_to(SOURCE))] = hashlib.sha256(raw).hexdigest()
    return json.loads(raw)


for repeat in range(1, 11):
    folder = SOURCE / "results" / f"r{repeat:02d}"
    record = read(folder / "run_record.json")
    assert record["finished"] and record["all_accuracy_pass"]
    assert record["manifest_sha256"] == experiment_hash
    expected_order = ["new_unit", "tuple"] if repeat % 2 else ["tuple", "new_unit"]
    assert [task["row"] for task in record["tasks"]] == expected_order
    datasets = []
    for method in ["new_unit", "tuple"]:
        report_path = folder / method / "results.json"
        report = read(report_path)
        original_task = next(t for t in experiment["tasks"] if t["repeat"] == repeat and t["row"] == method)
        evidence = experiment["security_evidence"][original_task["security_case"]]
        assert report["security_qualification"]["evidence_sha256"] == evidence["sha256"]
        case = report["cases"][0]
        task = next(task for task in record["tasks"] if task["row"] == method)
        assert files[str(report_path.relative_to(SOURCE))] == task["report_sha256"]
        assert task["returncode"] == 0
        assert case["status"] == "completed" and case["observed_targets_pass"]
        assert case["online_completed"] and case["inputs_unchanged"]
        assert len(case["configuration"]["branches"][0]["rescale_counts"]) == 8
        assert report["backend"] == "github.com/tuneinsight/lattigo/v6@v6.2.0"
        datasets.append(report["dataset_sha256"])
        errors = {entry["group"]: entry for entry in case["final_errors_low_high"]}
        assert int(errors["high"]["checked_results"]) == 8192
        assert errors["high"]["target_bits"] == 80
        params = (case["branches"][0]["work_parameters"] if method == "new_unit"
                  else case["actual_extended_key_parameters"])
        assert params["n"] == 32768
        assert "H=128, random signs" in params["secret_distribution"]
        csv_row = next(row for row in rows
                       if int(row["repeat"]) == repeat and row["row"] == method)
        time_s = int(case["online"]["wall_ns"]) / 1e9
        precision = errors["high"]["precision_bits_display"]
        assert abs(float(csv_row["online_ms"]) / 1000 - time_s) < 1e-10
        assert abs(float(csv_row["high_bits"]) - precision) < 1e-10
        observations[method].append({
            "repeat": repeat,
            "online_s": time_s,
            "high_precision_bits": precision,
            "low_precision_bits": errors["low"]["precision_bits_display"],
            "low_target_bits": errors["low"]["target_bits"],
            "log2_Q": sum(math.log2(int(q)) for q in params["Q"]),
            "log2_QP": params["log2_qp_display"],
            "scale_bits": case["configuration"]["branches"][0]["scale_bits"],
            "recorded_security_bits": report["security_qualification"]["minimum_estimated_classical_bits"],
            "security_evidence_sha256": report["security_qualification"]["evidence_sha256"],
            "key_payload_MiB": int(case["key_totals_deduplicated"]["coefficient_payload_bytes"]) / 2**20,
            "native_output_payload_MiB": int(case["native_view"]["coefficient_payload_bytes"]) / 2**20,
            "ordinary_output_payload_MiB": int(case["business"]["output_coefficient_payload_bytes"]) / 2**20,
            "relinearizations": int(case["operation_totals"]["calls_by_kind"]["relinearize"]),
        })
    assert datasets[0] == datasets[1]
    pair_checks.append({"repeat": repeat, "same_input_dataset": True,
                        "execution_order": expected_order, "cpu_models": record["cpu_models"]})

summary = {}
for method, entries in observations.items():
    summary[method] = {
        "runs": len(entries),
        "mean_online_s": statistics.mean(entry["online_s"] for entry in entries),
        "sample_sd_online_s": statistics.stdev(entry["online_s"] for entry in entries),
        "minimum_high_precision_bits": min(entry["high_precision_bits"] for entry in entries),
    }
    for key in entries[0]:
        if key not in ["repeat", "online_s", "high_precision_bits", "low_precision_bits"]:
            values = {entry[key] for entry in entries}
            assert len(values) == 1, (method, key, values)
            summary[method][key] = next(iter(values))

summary["time_reduction_percent"] = 100 * (
    1 - summary["new_unit"]["mean_online_s"] / summary["tuple"]["mean_online_s"])
summary["key_reduction_percent"] = 100 * (
    1 - summary["new_unit"]["key_payload_MiB"] / summary["tuple"]["key_payload_MiB"])
OUTPUT.mkdir(parents=True, exist_ok=True)
with (OUTPUT / "paper_data.csv").open("w", newline="") as f:
    columns = ["method", *summary["new_unit"].keys()]
    w = csv.DictWriter(f, fieldnames=columns)
    w.writeheader()
    w.writerows(dict(method=m, **summary[m]) for m in ("new_unit", "tuple"))
print("Verified the source, configurations, recorded security evidence, 20 runs, and Table 3 summary.")
