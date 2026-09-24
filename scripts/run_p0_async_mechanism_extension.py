"""Run an owned inert-canary async DEC mechanism extension."""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import hashlib
import json
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]
CASES = ("await_commit_then_deny", "cancel_before_commit", "background_sibling_survives_deny",
         "exception_after_schedule", "stage_abort_on_deny")


class Denied(Exception):
    pass


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


async def _write_after_yield(marker: Path, events: list[str]):
    events.append("effect_scheduled")
    await asyncio.sleep(0.01)
    marker.write_text("inert-canary\n", encoding="utf-8")
    events.append("effect_committed")


async def execute_case(case: str, verdict: str, marker: Path) -> dict:
    if case not in CASES or verdict not in {"ALLOW", "DENY"}:
        raise ValueError("async_case_identity")
    events = ["operation_selected"]
    if case == "await_commit_then_deny":
        await _write_after_yield(marker, events)
        events.append("guard_allow" if verdict == "ALLOW" else "guard_deny")
    elif case == "cancel_before_commit":
        task = asyncio.create_task(_write_after_yield(marker, events))
        await asyncio.sleep(0)
        if verdict == "DENY":
            events.append("guard_deny")
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                events.append("effect_cancelled")
        else:
            events.append("guard_allow")
            await task
    elif case == "background_sibling_survives_deny":
        task = asyncio.create_task(_write_after_yield(marker, events))
        await asyncio.sleep(0)
        events.append("guard_allow" if verdict == "ALLOW" else "guard_deny")
        await task
    elif case == "exception_after_schedule":
        task = asyncio.create_task(_write_after_yield(marker, events))
        await asyncio.sleep(0)
        try:
            if verdict == "DENY":
                events.append("guard_deny_exception")
                raise Denied()
            events.append("guard_allow")
        except Denied:
            events.append("deny_exception_caught_by_harness")
        await task
    else:
        events.append("effect_staged")
        if verdict == "DENY":
            events.extend(["guard_deny", "staged_effect_aborted"])
        else:
            events.append("guard_allow")
            marker.write_text("inert-canary\n", encoding="utf-8")
            events.append("effect_committed")
    return {"case": case, "verdict": verdict, "events": events,
            "effect_committed": marker.is_file(),
            "marker_sha256": sha(marker) if marker.is_file() else None}


def run(out: Path) -> dict:
    rows = []
    for case in CASES:
        cells = {}
        for verdict in ("ALLOW", "DENY"):
            directory = out / "work" / case / verdict.lower()
            directory.mkdir(parents=True)
            cells[verdict] = asyncio.run(execute_case(case, verdict, directory / "marker.txt"))
        if not cells["ALLOW"]["effect_committed"]:
            raise ValueError("async_allow_vacuous:" + case)
        label = "VIOLATION-PRESENT" if cells["DENY"]["effect_committed"] else "CONFORMANT-WITHIN-SCOPE"
        rows.append({"case": case, "contract": "DENY implies no inert marker commit for the selected operation",
                     "DEC_behavior_label": label, "cells": cells, "execution_health": "completed"})
    counts = Counter(row["DEC_behavior_label"] for row in rows)
    return {"schema_version": "p0-async-mechanism-extension-1", "rows": rows,
            "counts": {"cases": len(rows), **dict(counts)},
            "framework_axis": "independent_framework_neutral_owned_mechanism_extension",
            "behavior_ground_truth_established": True,
            "claim_boundary": ("Owned inert-canary async mechanism evidence only. It tests scheduling, cancellation, "
                               "sibling/background survival, exception propagation and staged abort; it is not a "
                               "sixth-framework transfer result or real-repository prevalence.")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(); out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "experiments"):
        parser.error("output must be new and under experiments")
    inputs = {str(Path(__file__).resolve().relative_to(ROOT)): sha(Path(__file__).resolve())}
    out.mkdir(parents=True)
    plan = {"schema_version": "p0-async-mechanism-extension-plan-1",
            "task_version": "async-mechanism-1-1", "created_time_ns": time.time_ns(),
            "cases": list(CASES), "cells": 2 * len(CASES), "inputs": inputs,
            "network": "none", "effect": "temporary_inert_marker_only", "model_calls": 0}
    (out / "RUN_PLAN.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    result = run(out); result["inputs"] = inputs
    (out / "RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    manifest = {"schema_version": "p0-async-mechanism-extension-manifest-1",
                "plan_sha256": sha(out / "RUN_PLAN.json"), "result_sha256": sha(out / "RESULT.json"),
                "execution_health": "completed", "scientific_outcome": "owned_async_behavior_measured",
                "planned": len(CASES), "completed": len(result["rows"]), "finished_time_ns": time.time_ns()}
    (out / "RUN_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result["counts"], sort_keys=True))


if __name__ == "__main__": main()
