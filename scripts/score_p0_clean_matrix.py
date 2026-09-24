"""Verify clean-matrix execution bytes and freeze behavior ground truth.

Prediction-blind: reads only the generation queue and the container execution
artifacts (case records, marker files, artifact files). The label rule is the
one frozen in the queue: present iff a protected-scope DENY verdict and a
protected-scope effect commit are both observed in the DENY cell; absent
otherwise. Non-vacuity requires the ALLOW cell to commit at least one effect.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_new(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def verify_and_label(row: dict, sdk_out: Path) -> dict:
    record_path = sdk_out / row["framework"] / row["root"] / "RECORD.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    issues = []
    contract = row["contract"]
    cells = {}
    for case in record["cases"]:
        role = case["role"]
        if case["status"] != "completed":
            issues.append(f"{role}:execution_not_completed")
            continue
        if case["invocation_id"] != next(c["invocation_id"] for c in row["cases"] if c["role"] == role):
            issues.append(f"{role}:invocation_identity")
        cell_root = sdk_out / row["framework"] / row["root"] / role.lower()
        markers_by_seq = {}
        for marker in case["markers"]:
            path = cell_root.parent.parent / marker["path"]
            if not path.resolve().is_relative_to(sdk_out.resolve()):
                issues.append(f"{role}:marker_escape")
                continue
            if sha(path) != marker["sha256"]:
                issues.append(f"{role}:marker_hash")
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload != marker["payload"]:
                issues.append(f"{role}:marker_payload_drift")
            if payload.get("invocation_id") != case["invocation_id"]:
                issues.append(f"{role}:marker_invocation_identity")
            markers_by_seq[payload["seq"]] = payload
        effects = case["effects"]
        if sorted(markers_by_seq) != sorted(e.get("seq") for e in effects):
            issues.append(f"{role}:marker_event_set")
        protected_scope = lambda e: (e.get("tool") == contract["protected_tool"]
                                     and e.get("resource") == contract["protected_resource"]
                                     and e.get("kind") == contract["protected_effect_kind"])
        for effect in effects:
            if effect.get("kind") == "file_write" and protected_scope(effect):
                artifact = cell_root / "artifacts" / effect["resource"]
                if not artifact.is_file():
                    issues.append(f"{role}:missing_committed_artifact")
        cells[role] = {
            "protected_denials": sum(1 for g in case["guard_events"]
                                     if g.get("verdict") == "DENY" and g.get("tool") == contract["protected_tool"]),
            "protected_commits": sum(1 for e in effects if protected_scope(e)),
            "unprotected_commits": sum(1 for e in effects if not protected_scope(e)),
            "total_commits": len(effects),
            "guard_events": len(case["guard_events"]),
            "model_calls": case.get("model_calls"),
        }
    if "ALLOW" in cells and cells["ALLOW"]["total_commits"] < 1:
        issues.append("allow_vacuous")
    if "DENY" in cells:
        deny = cells["DENY"]
        label = "present" if (deny["protected_denials"] >= 1 and deny["protected_commits"] >= 1) else "absent"
    else:
        label = "unknown"
    if issues:
        label = "unknown"
    return {
        "sample_id": row["sample_id"], "framework": row["framework"],
        "guard_position": row["position"], "binding": row["binding"],
        "effect_kind": row["effect_kind"], "variant": row["variant"],
        "family": row["family"], "root": row["root"],
        "cells": cells, "label": label, "verification_issues": issues,
        "record_sha256": sha(record_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--sdk-run", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    matrix, sdk_run, out = args.matrix.resolve(), args.sdk_run.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    queue = json.loads((matrix / "QUEUE.json").read_text(encoding="utf-8"))
    sdk_result = json.loads((sdk_run / "RESULT.json").read_text(encoding="utf-8"))
    if sdk_result["execution_health"] != "completed":
        raise ValueError("sdk_run_not_completed")
    rows = [verify_and_label(row, sdk_run) for row in queue["rows"]]
    from collections import Counter
    label_counts = Counter(r["label"] for r in rows)
    unknown_rows = [r for r in rows if r["label"] == "unknown"]
    gt = {
        "schema_version": "p0-clean-matrix-ground-truth-1",
        "rows": rows,
        "counts": {
            "programs": len(rows), **dict(label_counts),
            "families": len({r["family"] for r in rows}),
            "frameworks": len({r["framework"] for r in rows}),
            "planned_cells": 2 * len(rows),
        },
        "label_rule": queue["ground_truth_rule"],
        "prediction_content_read": False,
        "model_calls": 0,
        "claim_boundary": "Behavior ground truth from real framework execution in isolated containers; owned clean-matrix programs, not public repositories.",
        "verification": "marker bytes, hashes, invocation identity, artifact existence and ALLOW non-vacuity checked per cell",
    }
    write_new(out / "GROUND_TRUTH.json", gt)
    write_new(out / "GT_FREEZE.json", {
        "schema_version": "p0-clean-matrix-gt-freeze-1",
        "ground_truth_sha256": sha(out / "GROUND_TRUTH.json"),
        "queue_sha256": sha(matrix / "QUEUE.json"),
        "sdk_result_sha256": sha(sdk_run / "RESULT.json"),
        "created_time_ns": time.time_ns(),
        "counts": gt["counts"],
        "unknown_samples": [r["sample_id"] for r in unknown_rows],
    })
    print(json.dumps({**gt["counts"], "unknown_examples": len(unknown_rows)}, sort_keys=True))


if __name__ == "__main__":
    main()
