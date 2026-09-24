"""Check independent provisional reviews against pinned source and compare axes.

Agreement is reported as agreement, never accuracy or human gold. Unknown and
invalid reviews stay visible; no vote creates an executable-risk label.
"""
from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from guardcontract.paths import project_root

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import subprocess

ROOT = project_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from guardcontract.evidence.repository_evidence import git_tree, safe_path, unit_source

AXES = ("object_role", "api_identity", "registration", "bound_effect", "guard_effect_path", "runtime_ordering")
LABELS = {"supported", "refuted", "unknown"}
ROLES = {"application", "library_integration", "framework_source", "tutorial", "unknown"}
IDENTITY = ("sample_id", "repository", "commit", "path", "line", "cell", "file_sha256")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class SourceVerifier:
    def __init__(self, root, materializations):
        self.root = root
        self.mats = {}
        for payload in materializations:
            for row in payload.get("repositories", []):
                if row.get("status") != "completed":
                    continue
                key = (row["repository"], row.get("commit"), row.get("tree"))
                self.mats.setdefault(key, []).append(row["destination"])
        self.trees = {}
        self.files = {}

    def source(self, sample, path, cell=None):
        key = (sample["repository"], sample["commit"], sample["tree"])
        candidates = self.mats.get(key, [])
        if not candidates:
            raise ValueError("no_matching_pinned_materialization")
        errors = []
        for destination in sorted(set(candidates)):
            try:
                repo = safe_path(self.root, destination)
                tree_key = (destination, sample["commit"], sample["tree"])
                if tree_key not in self.trees:
                    self.trees[tree_key] = git_tree(repo, sample["commit"], sample["tree"])
                file_key = (*tree_key, path)
                if file_key not in self.files:
                    target = safe_path(repo, path)
                    if target.stat().st_size > 5 * 1024 * 1024:
                        raise ValueError("oversize_evidence")
                    raw = target.read_bytes()
                    expected = self.trees[tree_key].get(path)
                    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                    representation = "exact_git_blob"
                    if blob != expected:
                        lf = raw.replace(b"\r\n", b"\n")
                        equivalent = raw == lf.replace(b"\n", b"\r\n") and raw != lf
                        normalized = hashlib.sha1(b"blob " + str(len(lf)).encode() + b"\0" + lf).hexdigest()
                        if not equivalent or normalized != expected:
                            raise ValueError("evidence_git_blob_mismatch")
                        representation = "uniform_crlf_to_lf_git_blob"
                    self.files[file_key] = (raw, {"file_sha256": sha(raw), "git_blob": expected,
                                                 "representation": representation, "destination": destination})
                raw, metadata = self.files[file_key]
                if path.endswith(".ipynb"):
                    text = unit_source(raw, path, cell)
                else:
                    if cell is not None:
                        raise ValueError("unexpected_cell")
                    text = raw.decode("utf-8-sig")
                return text.splitlines(), dict(metadata)
            except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError) as exc:
                errors.append(type(exc).__name__ + (":" + str(exc) if isinstance(exc, ValueError) else ""))
        raise ValueError("evidence_unavailable:" + "|".join(errors))


def validate_review(review, template, verifier, slot):
    if not isinstance(review, dict) or review.get("reviewer_kind") != "ai_provisional" or review.get("reviewer_slot") != slot:
        raise ValueError("review_kind_or_slot_mismatch")
    if review.get("schema_version") != 1 or review.get("task_version") != "154-1":
        raise ValueError("review_version_mismatch")
    samples = review.get("samples")
    if not isinstance(samples, list) or any(not isinstance(r, dict) or not isinstance(r.get("sample_id"), str) for r in samples):
        raise ValueError("review_samples_schema")
    by_id = {s["sample_id"]: s for s in samples}
    expected = {s["sample_id"]: s for s in template["samples"]}
    if len(by_id) != len(samples) or set(by_id) != set(expected):
        raise ValueError("sample_set_missing_duplicate_or_extra")
    results = []
    for sid, source in expected.items():
        proposed = by_id[sid]
        errors = []
        for field in IDENTITY:
            if field not in proposed or type(proposed[field]) is not type(source[field]) or proposed[field] != source[field]:
                errors.append("identity_mismatch:" + field)
        if proposed.get("source_record_id", source.get("source_record_id")) != source.get("source_record_id"):
            errors.append("identity_mismatch:source_record_id")
        try:
            lines, meta = verifier.source(source, source["path"], source["cell"])
            if meta["file_sha256"] != source["file_sha256"]:
                errors.append("template_file_sha256_mismatch")
            if type(source["line"]) is not int or not 1 <= source["line"] <= len(lines):
                errors.append("anchor_line_out_of_range")
        except (OSError, ValueError) as exc:
            errors.append("anchor_integrity:" + str(exc))
        annotation = proposed.get("annotation")
        checked_axes = {}
        if not isinstance(annotation, dict) or set(annotation) != set(AXES):
            errors.append("annotation_axes_schema")
            annotation = annotation if isinstance(annotation, dict) else {}
        for axis in AXES:
            axis_errors = []
            value = annotation.get(axis)
            if not isinstance(value, dict):
                checked_axes[axis] = {"valid": False, "label": None, "errors": ["axis_object_required"]}
                continue
            if set(value) != {"label", "reason", "evidence"}:
                axis_errors.append("axis_fields_schema")
            label = value.get("label")
            allowed = ROLES if axis == "object_role" else LABELS
            if not isinstance(label, str) or label not in allowed:
                axis_errors.append("invalid_label")
            if not isinstance(value.get("reason"), str) or not value["reason"].strip():
                axis_errors.append("reason_required")
            refs = value.get("evidence")
            if not isinstance(refs, list):
                axis_errors.append("evidence_array_required")
                refs = []
            if label != "unknown" and not refs:
                axis_errors.append("non_unknown_requires_evidence")
            if axis == "runtime_ordering" and label != "unknown":
                axis_errors.append("no_runtime_evidence_in_this_review")
            verified_refs = []
            for ref in refs:
                if not isinstance(ref, dict) or not {"path", "start_line", "end_line"} <= set(ref) or set(ref) - {"path", "start_line", "end_line", "cell"}:
                    axis_errors.append("evidence_reference_schema")
                    continue
                try:
                    content, metadata = verifier.source(source, ref["path"], ref.get("cell"))
                    low, high = ref["start_line"], ref["end_line"]
                    if type(low) is not int or type(high) is not int or not 1 <= low <= high <= len(content):
                        raise ValueError("invalid_evidence_range")
                    # Hash a canonical line rendering as well as original bytes;
                    # include coordinates so it cannot migrate between locations.
                    span_hash = sha("\n".join(content[low - 1:high]).encode())
                    verified_refs.append({**ref, **metadata, "span_sha256": span_hash})
                except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:
                    axis_errors.append("invalid_evidence:" + str(exc))
            checked_axes[axis] = {"valid": not axis_errors, "label": label, "reason": value.get("reason"),
                                  "verified_evidence": verified_refs, "errors": axis_errors}
        valid = not errors and all(value["valid"] for value in checked_axes.values())
        results.append({"sample_id": sid, "identity_valid": not errors, "errors": errors, "valid": valid, "axes": checked_axes})
    return {"reviewer_slot": slot, "reviewer_kind": "ai_provisional", "samples": results,
            "counts": {"planned": len(expected), "valid": sum(r["valid"] for r in results), "invalid": sum(not r["valid"] for r in results)}}


def compare(valid_a, valid_b):
    a = {r["sample_id"]: r for r in valid_a["samples"]}
    b = {r["sample_id"]: r for r in valid_b["samples"]}
    if set(a) != set(b):
        raise ValueError("validation_sample_set_mismatch")
    axes = {}
    for axis in AXES:
        pairs = [(a[sid]["axes"][axis]["label"], b[sid]["axes"][axis]["label"]) for sid in a
                 if a[sid]["identity_valid"] and b[sid]["identity_valid"] and a[sid]["axes"][axis]["valid"] and b[sid]["axes"][axis]["valid"]]
        n = len(pairs)
        agreed = sum(left == right for left, right in pairs)
        ca, cb = Counter(x for x, _ in pairs), Counter(y for _, y in pairs)
        expected = sum(ca[k] * cb[k] for k in ca.keys() | cb.keys()) / n ** 2 if n else None
        observed = agreed / n if n else None
        kappa = (observed - expected) / (1 - expected) if n and expected != 1 else None
        axes[axis] = {"planned_pairs": len(a), "valid_pairs": n, "invalid_pairs": len(a) - n,
                      "agreed_pairs": agreed, "disagreed_pairs": n - agreed,
                      "agreement": observed, "cohen_kappa": kappa,
                      "a_labels": dict(ca), "b_labels": dict(cb),
                      "interpretation": "provisional_AI_inter_review_agreement_not_accuracy"}
    rows = []
    for sid in sorted(a):
        agreed, disputed, invalid = {}, {}, []
        for axis in AXES:
            left, right = a[sid]["axes"][axis], b[sid]["axes"][axis]
            if not a[sid]["identity_valid"] or not b[sid]["identity_valid"] or not left["valid"] or not right["valid"]:
                invalid.append(axis)
            elif left["label"] == right["label"]:
                agreed[axis] = left["label"]
            else:
                disputed[axis] = {"A": left["label"], "B": right["label"]}
        rows.append({"sample_id": sid, "agreed_provisional_axes": agreed,
                     "disputed_axes": disputed, "invalid_axes": invalid,
                     "adjudication_required": True, "gold_status": "not_established",
                     "primary_measurement_eligible": False})
    return {"axes": axes, "samples": rows,
            "counts": {"samples": len(rows), "samples_with_disagreement": sum(bool(r["disputed_axes"]) for r in rows),
                       "samples_with_invalid_axes": sum(bool(r["invalid_axes"]) for r in rows),
                       "gold_samples": 0, "primary_measurement_eligible": 0}}


def run(config, root):
    inputs = {}
    def read(path):
        raw = safe_path(root, path).read_bytes()
        inputs[path] = sha(raw)
        return json.loads(raw)
    template_a, template_b = read(config["template_a"]), read(config["template_b"])
    if template_a["samples"] != template_b["samples"]:
        raise ValueError("templates_do_not_match")
    verifier = SourceVerifier(root, [read(path) for path in config["materializations"]])
    a = validate_review(read(config["review_a"]), template_a, verifier, "A")
    b = validate_review(read(config["review_b"]), template_b, verifier, "B")
    comparison = compare(a, b)
    valid = a["counts"]["invalid"] == b["counts"]["invalid"] == 0
    return {"schema_version": 1, "task_version": config["task_version"], "captured_at": datetime.now(timezone.utc).isoformat(),
            "execution_health": "completed" if valid else "partial", "scientific_outcome": "unscored",
            "inputs_sha256": inputs, "reviews": {"A": a, "B": b}, "comparison": comparison,
            "annotation_scopes": {"api_identity": "selected_source_occurrence", "registration": "related_source_configuration_not_runtime_activation",
                                  "bound_effect": "related_protected_effect_code", "guard_effect_path": "related_source_workflow", "runtime_ordering": "requires_separate_runtime_evidence"},
            "claim_boundary": "Checks source identity, evidence location and annotation schema. Does not verify semantic truth, establish human gold, infer prevalence or confirm runtime risk. All samples remain subject to adjudication."}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--result", required=True, type=Path)
    a = p.parse_args()
    if a.result.exists():
        raise FileExistsError(a.result)
    result = run(json.loads(a.config.read_text()), Path.cwd().resolve())
    with a.result.open("x") as f:
        json.dump(result, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    print(json.dumps({"reviews": {k: v["counts"] for k, v in result["reviews"].items()}, "comparison": result["comparison"]["counts"]}))
    return 0 if result["execution_health"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
