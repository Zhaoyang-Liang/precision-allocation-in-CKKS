"""Run one paired Table 3 repetition, retaining failures and both methods."""
import argparse
import datetime
import hashlib
import json
import math
import os
import platform
import subprocess
import time
from pathlib import Path

CODE = Path(__file__).resolve().parent
CONFIGS = CODE / "configurations"
EXPERIMENT = CONFIGS / "experiment.json"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_tasks(repeat):
    experiment = json.loads(EXPERIMENT.read_text())
    tasks = [task for task in experiment["tasks"] if task["repeat"] == repeat]
    assert len(tasks) == 2 and {t["row"] for t in tasks} == {"new_unit", "tuple"}
    for task in tasks:
        config = CONFIGS / Path(task["config"]).name
        assert digest(config) == task["config_sha256"]
        evidence = experiment["security_evidence"][task["security_case"]]
        path = CONFIGS / evidence["path"]
        assert digest(path) == evidence["sha256"]
        record = json.loads(path.read_text())
        assert record["finished"] and record["target128_pass"]
        assert len(record["attacks"]) == 5
        assert all(a["finite"] and math.isfinite(float(a["log2_rop"])) and float(a["log2_rop"]) >= 128
                   for a in record["attacks"].values())
    return tasks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, choices=range(1, 11), default=1)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--check-only", action="store_true", help="Check recorded inputs without encryption or timing runs.")
    args = parser.parse_args()
    tasks = load_tasks(args.repeat)
    binaries = args.binaries.resolve()
    environment = dict(os.environ)
    environment.update({key: "1" for key in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "GOMAXPROCS")})
    environment["TUPLE8_FORMAL_MANIFEST"] = str(EXPERIMENT)
    if args.check_only:
        for task in tasks:
            binary = binaries / ("precisionbench" if task["row"] == "new_unit" else "tuplebench")
            config = CONFIGS / Path(task["config"]).name
            subprocess.run([str(binary), "-mode", "plan", "-config", str(config), "-cases", task["case"]],
                           env=environment, check=True, stdout=subprocess.DEVNULL)
        print(f"Repetition {args.repeat}: both configurations and recorded security estimates checked; no HE run.")
        return
    if args.out is None:
        parser.error("--out is required for a fresh experiment")
    out = args.out.resolve()
    if out == CODE.parent / "result" or CODE.parent / "result" in out.parents:
        parser.error("Use a new directory outside the retained result folder")
    out.mkdir(parents=True, exist_ok=False)
    record = {"repeat": args.repeat, "seed": tasks[0]["seed"], "host": platform.node(),
              "platform": platform.platform(), "started_at": datetime.datetime.now().astimezone().isoformat(),
              "tasks": [], "finished": False}

    def save():
        temporary = out / "run_record.tmp"
        temporary.write_text(json.dumps(record, indent=2) + "\n")
        temporary.replace(out / "run_record.json")

    save()
    for task in tasks:
        binary = binaries / ("precisionbench" if task["row"] == "new_unit" else "tuplebench")
        config = CONFIGS / Path(task["config"]).name
        destination = out / task["row"]
        started = time.monotonic()
        print(f"Running repetition {args.repeat}: {task['row']}", flush=True)
        with (out / (task["row"] + ".stdout.txt")).open("w") as stdout, (out / (task["row"] + ".stderr.txt")).open("w") as stderr:
            process = subprocess.run([str(binary), "-mode", "run", "-config", str(config),
                                      "-cases", task["case"], "-out", str(destination)],
                                     env=environment, stdout=stdout, stderr=stderr)
        item = {"row": task["row"], "case": task["case"], "returncode": process.returncode,
                "process_wall_seconds": time.monotonic() - started}
        report_path = destination / "results.json"
        item["report_present"] = report_path.is_file()
        if report_path.is_file():
            report = json.loads(report_path.read_text())
            item["observed_targets_pass"] = all(c["status"] == "completed" and c.get("observed_targets_pass") is True
                                                for c in report["cases"])
        record["tasks"].append(item)
        save()
    record["finished"] = True
    record["finished_at"] = datetime.datetime.now().astimezone().isoformat()
    record["all_accuracy_pass"] = all(t.get("observed_targets_pass") is True for t in record["tasks"])
    save()
    if not all(t["report_present"] and t["returncode"] == 0 for t in record["tasks"]):
        raise SystemExit("A method failed; all available records were retained.")
    print(f"Finished. Accuracy targets passed: {record['all_accuracy_pass']}. Results: {out}")


if __name__ == "__main__":
    main()
