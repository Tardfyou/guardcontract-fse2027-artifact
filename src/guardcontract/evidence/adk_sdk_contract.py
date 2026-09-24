"""Enroll narrow Google ADK 2.7.0 callback semantics from frozen controls."""
import hashlib
import json
from pathlib import Path


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def enroll(directory):
    directory = Path(directory)
    generation, scoring = (json.loads((directory / name).read_bytes()) for name in
                           ("GENERATION_RUN_MANIFEST.json", "SCORE_RUN_MANIFEST.json"))
    expected_raw = next(row["sha256"] for row in generation["files"] if row["path"].endswith("/raw-result.json") and row["role"] == "artifact-output")
    expected_score = next(row["sha256"] for row in scoring["files"] if row["path"].endswith("/scored-result.json") and row["role"] == "artifact-output")
    if sha(directory / "raw-result.json") != expected_raw or sha(directory / "scored-result.json") != expected_score:
        raise ValueError("adk_contract_artifact_drift")
    raw, score, config = (json.loads((directory / name).read_bytes()) for name in
                          ("raw-result.json", "scored-result.json", "MVE_CONFIG.json"))
    if not score["gate_passed"] or score["counts"] != {"completed": 4, "passed_checks": 12, "planned": 4, "total_checks": 12}:
        raise ValueError("adk_contract_score_gate")
    cells = {(row["mode"], row["verdict"]): row for row in raw["cells"]}
    if len(cells) != 4 or set(cells) != {(mode, verdict) for mode in ("vulnerable", "repaired") for verdict in ("ALLOW", "DENY")}:
        raise ValueError("adk_contract_cell_inventory")
    if ([cells[("vulnerable", d)]["effect_count"] for d in ("ALLOW", "DENY")] != [1, 1]
            or [cells[("repaired", d)]["effect_count"] for d in ("ALLOW", "DENY")] != [1, 0]):
        raise ValueError("adk_contract_effect_semantics")
    contract = {"schema_version": "google-adk-sdk-contract-1", "framework_versions": {"google-adk": config["framework"]["version"]},
        "facts": {"before_tool_non_none_skips_selected_tool": True, "before_tool_none_continues_to_selected_tool": True,
                  "after_tool_callback_occurs_after_successful_tool": True, "one_fixed_request_completes_with_two_model_calls": True},
        "limits": ["InMemoryRunner", "one LlmAgent", "one fixed tool request", "normal local IO", "no external callbacks"],
        "evidence": {"raw_result_sha256": expected_raw, "scored_result_sha256": expected_score,
                     "config_sha256": sha(directory / "MVE_CONFIG.json")},
        "application_path_or_effect_verified": False}
    contract["contract_sha256"] = hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return contract
