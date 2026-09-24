"""Conservative guard-policy surface checks for proposed source repairs."""

from __future__ import annotations

import ast
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from guardcontract.core.schemas import PatchEnvelope
from guardcontract.evidence.validation import safe_relative_path
from guardcontract.repair.model_proposals import (
    _job,
    _roots,
    check_patch,
    hydrate_redacted_patch_context,
)


GUARD_SLOTS = {
    "input_guardrails",
    "output_guardrails",
    "tool_input_guardrails",
    "tool_output_guardrails",
    "before_tool_callback",
    "after_tool_callback",
    "guardrail",
}


def _value_count(node: ast.AST) -> int:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return len(node.elts)
    if isinstance(node, ast.Constant) and node.value is None:
        return 0
    return 1


def policy_surface(source: bytes) -> dict[str, int]:
    counts: Counter[str] = Counter()
    tree = ast.parse(source)
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        for keyword in call.keywords:
            if keyword.arg in GUARD_SLOTS:
                counts[keyword.arg] += _value_count(keyword.value)
    return dict(sorted(counts.items()))


def tool_surface(source: bytes) -> dict[str, int]:
    """Recover stable tool identities, normalizing clone wrappers and aliases."""
    tree = ast.parse(source)
    assignments = {}
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name):
                assignments[targets[0].id] = node.value

    def dotted(node):
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute):
            parent = dotted(node.value); return f"{parent}.{node.attr}" if parent else node.attr
        return None

    def identity(node, seen=frozenset()):
        if isinstance(node, ast.Name) and node.id in assignments and node.id not in seen:
            return identity(assignments[node.id], seen | {node.id})
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "clone":
                return dotted(node.func.value)
            return dotted(node.func)
        return dotted(node)

    counts = Counter()
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        for keyword in call.keywords:
            if keyword.arg != "tools" or not isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
                continue
            for item in keyword.value.elts:
                if (name := identity(item)):
                    counts[name] += 1
    return dict(sorted(counts.items()))


def validate_policy_surface(model_revalidation: Mapping[str, Any], queue: Mapping[str, Any],
                            materialization: Mapping[str, Any]) -> dict[str, Any]:
    roots = _roots(materialization)
    candidates = {row.get("candidate_id"): row for row in queue.get("candidates", [])
                  if isinstance(row, Mapping)}
    source_records = model_revalidation.get("records")
    if not isinstance(source_records, list):
        correction = model_revalidation.get("record")
        source_records = ([{"candidate_id": correction.get("candidate_id"),
                            "selected_proposal": correction.get("proposal")}]
                          if isinstance(correction, Mapping) else [])
    records = []
    for record in source_records:
        candidate_id = record.get("candidate_id")
        output = {"candidate_id": candidate_id, "state": "unavailable", "verified_repair": False}
        try:
            candidate = candidates[candidate_id]
            root, commit = roots[candidate["repository"]]
            job, _ = _job(candidate, root, commit, role="critic")
            proposal = record.get("selected_proposal")
            if not isinstance(proposal, Mapping):
                raise ValueError("no selected proposal")
            patch = PatchEnvelope.from_dict(proposal)
            integrity = check_patch(root, job, patch)
            if not integrity["accepted"]:
                raise ValueError("proposal no longer passes deterministic patch integrity")
            effective_diff, _, placeholder = hydrate_redacted_patch_context(root, job, patch.unified_diff)
            if placeholder:
                raise ValueError("redaction placeholder in added line")
            with tempfile.TemporaryDirectory(prefix="guardcontract-policy-surface-") as temporary:
                scratch = Path(temporary)
                for relative in job.allowed_paths:
                    source = root.joinpath(*safe_relative_path(relative).parts)
                    target = scratch.joinpath(*safe_relative_path(relative).parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
                applied = subprocess.run(
                    ["git", "apply", "--recount", "--whitespace=nowarn", "-"], cwd=scratch,
                    input=effective_diff.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                )
                if applied.returncode != 0:
                    raise ValueError("isolated patch application failed")
                before, after = Counter(), Counter()
                before_tools, after_tools = Counter(), Counter()
                for relative in patch.touched_paths:
                    if relative.endswith(".py"):
                        before.update(policy_surface(root.joinpath(*safe_relative_path(relative).parts).read_bytes()))
                        after.update(policy_surface(scratch.joinpath(*safe_relative_path(relative).parts).read_bytes()))
                        before_tools.update(tool_surface(root.joinpath(*safe_relative_path(relative).parts).read_bytes()))
                        after_tools.update(tool_surface(scratch.joinpath(*safe_relative_path(relative).parts).read_bytes()))
            reductions = {slot: before[slot] - after[slot] for slot in GUARD_SLOTS if before[slot] > after[slot]}
            additions = {slot: after[slot] - before[slot] for slot in GUARD_SLOTS if after[slot] > before[slot]}
            tool_reductions = {tool: before_tools[tool] - after_tools[tool]
                               for tool in before_tools if before_tools[tool] > after_tools[tool]}
            tool_additions = {tool: after_tools[tool] - before_tools[tool]
                              for tool in after_tools if after_tools[tool] > before_tools[tool]}
            gates = {
                "patch_integrity": True,
                "existing_guard_slots_not_reduced": not reductions,
                "registered_tool_surface_not_reduced": not tool_reductions,
                "paired_deny_allow_replay_completed": False,
                "resource_boundary_not_expanded": False if tool_additions else None,
            }
            output.update(
                state="requires_equivalence_replay" if reductions or tool_reductions else "requires_paired_behavior_replay",
                before_surface=dict(sorted(before.items())), after_surface=dict(sorted(after.items())),
                reductions=dict(sorted(reductions.items())), additions=dict(sorted(additions.items())), gates=gates,
                before_tool_surface=dict(sorted(before_tools.items())),
                after_tool_surface=dict(sorted(after_tools.items())),
                tool_reductions=dict(sorted(tool_reductions.items())),
                tool_additions=dict(sorted(tool_additions.items())),
                gate_passed=False,
            )
        except (KeyError, OSError, ValueError, SyntaxError) as exc:
            output["error"] = {"type": type(exc).__name__, "message": str(exc)[:500]}
        records.append(output)
    return {
        "schema_version": "repair-policy-surface-validation-1",
        "counts": {"records": len(records),
                   "requires_equivalence_replay": sum(r["state"] == "requires_equivalence_replay" for r in records),
                   "requires_paired_behavior_replay": sum(
                       r["state"] == "requires_paired_behavior_replay" for r in records),
                   "verified_repairs": 0},
        "source_tree_writes": 0,
        "records": records,
        "claim_boundary": "Conservative static comparison of guard slots and normalized registered-tool identities after isolated patch application. Tool or guard reductions fail ALLOW-surface preservation; remaining proposals still require paired behavior and resource checks.",
    }
