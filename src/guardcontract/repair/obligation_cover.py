#!/usr/bin/env python3
"""Exact weighted cover for lifecycle obligations with explicit AND-join semantics."""

from __future__ import annotations

from decimal import Decimal
from itertools import combinations
from typing import Any, Mapping


class ObligationModelError(ValueError):
    """The obligation model is malformed or exceeds the exact solver boundary."""


def synthesize_obligation_repair(
    model: Mapping[str, Any], *, max_candidates: int = 20
) -> dict[str, Any]:
    obligations = tuple(model.get("obligations", ()))
    raw_candidates = model.get("candidates", ())
    if not obligations or len(obligations) != len(set(obligations)):
        raise ObligationModelError("obligations must be non-empty and unique")
    if not isinstance(raw_candidates, list) or not raw_candidates:
        raise ObligationModelError("candidates must be a non-empty list")
    if len(raw_candidates) > max_candidates:
        raise ObligationModelError(
            f"candidate count {len(raw_candidates)} exceeds max_candidates={max_candidates}"
        )

    obligation_set = set(obligations)
    candidates: dict[str, dict[str, Any]] = {}
    for raw in raw_candidates:
        node_id = raw.get("id")
        if not isinstance(node_id, str) or not node_id or node_id in candidates:
            raise ObligationModelError("candidate IDs must be non-empty and unique")
        cost = raw.get("cost")
        distance = raw.get("distance")
        covers = raw.get("covers")
        if isinstance(cost, bool) or not isinstance(cost, (int, float)) or cost <= 0:
            raise ObligationModelError(f"candidate {node_id} has invalid cost")
        if isinstance(distance, bool) or not isinstance(distance, int) or distance < 0:
            raise ObligationModelError(f"candidate {node_id} has invalid distance")
        if not isinstance(covers, list) or not covers or not set(covers) <= obligation_set:
            raise ObligationModelError(f"candidate {node_id} has invalid coverage")
        candidates[node_id] = {
            "cost": Decimal(str(cost)),
            "distance": distance,
            "covers": set(covers),
        }

    ranked: list[tuple[tuple[Any, ...], tuple[str, ...]]] = []
    for size in range(1, len(candidates) + 1):
        for selected in combinations(sorted(candidates), size):
            covered: set[str] = set()
            for node_id in selected:
                covered |= candidates[node_id]["covers"]
            if covered != obligation_set:
                continue
            objective = (
                sum((candidates[node]["cost"] for node in selected), Decimal(0)),
                len(selected),
                sum(candidates[node]["distance"] for node in selected),
                selected,
            )
            ranked.append((objective, selected))
    if not ranked:
        raise ObligationModelError("no candidate set covers every obligation")
    ranked.sort(key=lambda item: item[0])
    best, selected = ranked[0]
    minimum_cost = best[0]
    minimum_cost_sets = [
        list(nodes) for objective, nodes in ranked if objective[0] == minimum_cost
    ]
    return {
        "status": "repaired",
        "selected_nodes": list(selected),
        "objective": [float(best[0]), best[1], best[2], list(best[3])],
        "obligation_count": len(obligations),
        "minimum_cost_set_count": len(minimum_cost_sets),
        "minimum_cost_sets": minimum_cost_sets,
    }
