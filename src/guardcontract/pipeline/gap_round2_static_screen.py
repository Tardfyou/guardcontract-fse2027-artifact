"""Static screen for the second gap-search materialized pool."""
import hashlib
import json
from collections import Counter
from pathlib import Path

from guardcontract.discovery.generic_effect_catalog import inventory as generic_effect_inventory
from guardcontract.discovery.registration import discover_registrations
from guardcontract.paths import project_root

ROOT = project_root()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(frame_path, materialization_path, output_path):
    frame = json.loads(Path(frame_path).read_bytes())
    materialization = json.loads(Path(materialization_path).read_bytes())
    locations = {row["repository"]: row for row in materialization["repositories"]
                 if row.get("status") == "completed"}
    rows = []
    for selected in frame["selected"]:
        name = selected["repository"]["full_name"]
        location = locations.get(name)
        if location is None:
            rows.append({"repository": name, "framework": selected["framework"], "status": "source_unavailable"})
            continue
        root = Path(location["destination"])
        try:
            registration = discover_registrations(root, max_groups=80)
            generic = generic_effect_inventory(root)
            rows.append({"repository": name, "framework": selected["framework"],
                         "pinned_commit": selected["pinned_commit"],
                         "registration_groups": len(registration["groups"]),
                         "registration_effect_groups": sum(bool(group["effects"]) for group in registration["groups"]),
                         "registration_effects": sum(len(group["effects"]) for group in registration["groups"]),
                         "generic_effects": len(generic["effects"]),
                         "registration_health": registration["execution_health"],
                         "generic_errors": generic["errors"],
                         "status": "completed"})
        except Exception as exc:
            rows.append({"repository": name, "framework": selected["framework"],
                         "status": "error", "error_kind": type(exc).__name__})
    result = {"schema_version": "gap-round2-static-screen-1", "rows": rows,
              "counts": {"repositories": len(rows),
                         "registration_effect_groups": sum(row.get("registration_effect_groups", 0) for row in rows),
                         "registration_effects": sum(row.get("registration_effects", 0) for row in rows),
                         "generic_effects": sum(row.get("generic_effects", 0) for row in rows),
                         "completed": sum(row.get("status") == "completed" for row in rows),
                         "errors": sum(row.get("status") == "error" for row in rows)},
              "inputs_sha256": {str(Path(path).resolve().relative_to(ROOT)): sha(path)
                                for path in (frame_path, materialization_path, Path(__file__))},
              "model_calls": 0, "holdout_eligible": False, "behavior_labels": False,
              "claim_boundary": "Static registration and generic sink candidates only; no policy, path, runtime, issue or holdout claim."}
    Path(output_path).write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return result


if __name__ == "__main__":
    output = ROOT / "artifacts/development/gap-round2-static-screen-20260912.json"
    result = run(ROOT / "experiments/prospective-gap-round2-materialization-n315-v2/FRAME.json",
                 ROOT / "experiments/prospective-gap-round2-materialization-n315-v2/RESULT.json", output)
    print(json.dumps(result["counts"], sort_keys=True))
