"""Freeze a family-isolated development/test split of the clean matrix.

Equivalence variants of one base family always land on the same side. The
split is drawn before any detection prediction runs and is frozen with
hashes; the test side may be evaluated exactly once per frozen detector.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from pathlib import Path


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20260916)
    parser.add_argument("--dev-fraction", type=float, default=0.6)
    args = parser.parse_args()
    gt = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    rows = [r for r in gt["rows"] if r["label"] in ("present", "absent")]
    families = sorted({r["family"] for r in rows})
    rng = random.Random(args.seed)
    rng.shuffle(families)
    target_dev = int(round(args.dev_fraction * len(rows)))
    dev_families, test_families, dev_count = [], [], 0
    for family in families:
        size = sum(1 for r in rows if r["family"] == family)
        if dev_count < target_dev:
            dev_families.append(family)
            dev_count += size
        else:
            test_families.append(family)
    split = {
        "schema_version": "p0-clean-matrix-split-1",
        "seed": args.seed,
        "dev_fraction": args.dev_fraction,
        "dev": {"families": dev_families, "samples": [r["sample_id"] for r in rows if r["family"] in dev_families]},
        "test": {"families": test_families, "samples": [r["sample_id"] for r in rows if r["family"] in test_families]},
        "counts": {
            "labeled_rows": len(rows),
            "dev_samples": sum(1 for r in rows if r["family"] in dev_families),
            "test_samples": sum(1 for r in rows if r["family"] in test_families),
            "dev_families": len(dev_families), "test_families": len(test_families),
        },
        "label_balance": {
            "dev": {"present": sum(1 for r in rows if r["family"] in dev_families and r["label"] == "present"),
                    "absent": sum(1 for r in rows if r["family"] in dev_families and r["label"] == "absent")},
            "test": {"present": sum(1 for r in rows if r["family"] in test_families and r["label"] == "present"),
                     "absent": sum(1 for r in rows if r["family"] in test_families and r["label"] == "absent")},
        },
        "unknown_rows_excluded": [r["sample_id"] for r in gt["rows"] if r["label"] == "unknown"],
        "rule": "families assigned whole (equivalence variants stay together); drawn before any prediction run",
        "created_time_ns": time.time_ns(),
        "ground_truth_sha256": sha(args.ground_truth),
    }
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "SPLIT.json").write_text(json.dumps(split, indent=2, sort_keys=True) + "\n")
    print(json.dumps({**split["counts"], "labels": split["label_balance"]}, sort_keys=True))


if __name__ == "__main__":
    main()
