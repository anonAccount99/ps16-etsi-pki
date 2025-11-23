#!/usr/bin/env python3
import sys, json, time, socket, statistics as stats
from pathlib import Path

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <per_iter_json> <out_json>")
        sys.exit(1)
    per_iter_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    with per_iter_path.open("r", encoding="utf-8") as f:
        per_iter = json.load(f)

    benchmarks = []
    for name, samples in per_iter.items():
        if not samples:
            continue
        # samples are microseconds per inner-iteration
        samples = [float(x) for x in samples]
        mean = stats.fmean(samples)
        median = stats.median(samples)
        stddev = stats.pstdev(samples)  # population stddev to match GB's default for aggregates
        cv = (stddev / mean) if mean else 0.0
        base = {
            "family_index": 0,
            "per_family_instance_index": 0,
            "run_name": name,
            "run_type": "aggregate",
            "repetitions": 1,
            "threads": 1,
            "aggregate_unit": "time",
            "iterations": len(samples),
            "cpu_time": mean,
            "real_time": mean,
            "time_unit": "us",
        }
        row_mean = dict(base, name=f"{name}_mean", aggregate_name="mean")
        row_median = dict(base, name=f"{name}_median", aggregate_name="median", real_time=median, cpu_time=median)
        row_std = dict(base, name=f"{name}_stddev", aggregate_name="stddev", real_time=stddev, cpu_time=stddev)
        row_cv = dict(base, name=f"{name}_cv", aggregate_name="cv", aggregate_unit="percentage", real_time=cv, cpu_time=cv)
        benchmarks.extend([row_mean, row_median, row_std, row_cv])

    payload = {
        "context": {
            "date": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
            "host_name": socket.gethostname(),
            "executable": "groupsig_bench (manual aggregation)",
            "json_schema_version": 1,
        },
        "benchmarks": benchmarks,
        "per_iteration": per_iter,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

if __name__ == "__main__":
    main()

