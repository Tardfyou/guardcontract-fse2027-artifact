#!/usr/bin/env python3
"""Framework-neutral effect-graph audit and exact repair synthesis."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from decimal import Decimal
from itertools import combinations
import math
from typing import Any, Iterable, Mapping, Sequence


class EffectGraphError(ValueError):
    """Base class for graph or solver failures that must remain visible."""


class GraphValidationError(EffectGraphError):
    """The graph schema or references are invalid."""


class GraphCycleError(EffectGraphError):
    """The graph contains a cycle and must be finitely unrolled."""


class PathLimitExceeded(EffectGraphError):
    """Path enumeration exceeded its declared resource bound."""


class CandidateLimitExceeded(EffectGraphError):
    """Exact repair search exceeded its declared candidate bound."""


@dataclass(frozen=True)
class PathRecord:
    effect: str
    nodes: tuple[str, ...]
    mediated_by: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect,
            "path": list(self.nodes),
            "mediated_by": list(self.mediated_by),
        }


@dataclass(frozen=True)
class EffectGraph:
    entry: str
    protected_effects: tuple[str, ...]
    nodes: Mapping[str, Mapping[str, Any]]
    successors: Mapping[str, tuple[str, ...]]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EffectGraph":
        if not isinstance(data, Mapping):
            raise GraphValidationError("graph must be an object")

        raw_nodes = data.get("nodes")
        if not isinstance(raw_nodes, list) or not raw_nodes:
            raise GraphValidationError("nodes must be a non-empty list")

        nodes: dict[str, Mapping[str, Any]] = {}
        for raw in raw_nodes:
            if not isinstance(raw, Mapping):
                raise GraphValidationError("each node must be an object")
            node_id = raw.get("id")
            kind = raw.get("kind")
            if not isinstance(node_id, str) or not node_id:
                raise GraphValidationError("node id must be a non-empty string")
            if node_id in nodes:
                raise GraphValidationError(f"duplicate node id: {node_id}")
            if not isinstance(kind, str) or not kind:
                raise GraphValidationError(f"node {node_id} has invalid kind")
            nodes[node_id] = dict(raw)

        entry = data.get("entry")
        if not isinstance(entry, str) or entry not in nodes:
            raise GraphValidationError("entry must reference a known node")
        if nodes[entry]["kind"] != "entry":
            raise GraphValidationError("entry node must have kind=entry")

        raw_effects = data.get("protected_effects")
        if not isinstance(raw_effects, list) or not raw_effects:
            raise GraphValidationError("protected_effects must be a non-empty list")
        if any(not isinstance(effect, str) for effect in raw_effects):
            raise GraphValidationError("protected effect ids must be strings")
        protected_effects = tuple(raw_effects)
        if len(set(protected_effects)) != len(protected_effects):
            raise GraphValidationError("protected_effects contains duplicates")
        for effect in protected_effects:
            if effect not in nodes:
                raise GraphValidationError(f"unknown protected effect: {effect}")
            if nodes[effect]["kind"] != "effect":
                raise GraphValidationError(
                    f"protected effect {effect} must have kind=effect"
                )

        raw_edges = data.get("edges")
        if not isinstance(raw_edges, list):
            raise GraphValidationError("edges must be a list")
        successors: dict[str, list[str]] = {node_id: [] for node_id in nodes}
        seen_edges: set[tuple[str, str]] = set()
        for raw_edge in raw_edges:
            if (
                not isinstance(raw_edge, list)
                or len(raw_edge) != 2
                or not all(isinstance(value, str) for value in raw_edge)
            ):
                raise GraphValidationError("each edge must be a two-node string list")
            source, target = raw_edge
            if source not in nodes or target not in nodes:
                raise GraphValidationError(
                    f"edge references unknown node: {source}->{target}"
                )
            edge = (source, target)
            if edge in seen_edges:
                raise GraphValidationError(f"duplicate edge: {source}->{target}")
            seen_edges.add(edge)
            successors[source].append(target)

        for node_id, node in nodes.items():
            if "decision" in node:
                cls._validate_decision(node_id, node["decision"], protected_effects)
            if "candidate" in node:
                cls._validate_candidate(node_id, node["candidate"], protected_effects)

        frozen_successors = {
            node_id: tuple(sorted(targets)) for node_id, targets in successors.items()
        }
        graph = cls(
            entry=entry,
            protected_effects=protected_effects,
            nodes=nodes,
            successors=frozen_successors,
        )
        graph._reject_cycles()
        graph._require_reachable_effects()
        return graph

    @staticmethod
    def _validate_scope(
        node_id: str,
        metadata: Mapping[str, Any],
        protected_effects: Sequence[str],
    ) -> None:
        if "protects" not in metadata:
            return
        protects = metadata["protects"]
        if not isinstance(protects, list) or not protects:
            raise GraphValidationError(f"node {node_id} has invalid protects scope")
        if any(not isinstance(effect, str) for effect in protects):
            raise GraphValidationError(f"node {node_id} has non-string scope")
        unknown = sorted(set(protects) - set(protected_effects))
        if unknown:
            raise GraphValidationError(
                f"node {node_id} protects unknown effects: {', '.join(unknown)}"
            )

    @classmethod
    def _validate_decision(
        cls,
        node_id: str,
        metadata: Any,
        protected_effects: Sequence[str],
    ) -> None:
        if not isinstance(metadata, Mapping):
            raise GraphValidationError(f"node {node_id} decision must be an object")
        if not isinstance(metadata.get("release_conditioned"), bool):
            raise GraphValidationError(
                f"node {node_id} decision requires boolean release_conditioned"
            )
        cls._validate_scope(node_id, metadata, protected_effects)

    @classmethod
    def _validate_candidate(
        cls,
        node_id: str,
        metadata: Any,
        protected_effects: Sequence[str],
    ) -> None:
        if not isinstance(metadata, Mapping):
            raise GraphValidationError(f"node {node_id} candidate must be an object")
        cost = metadata.get("cost")
        if (
            isinstance(cost, bool)
            or not isinstance(cost, (int, float))
            or not math.isfinite(float(cost))
            or float(cost) <= 0
        ):
            raise GraphValidationError(f"node {node_id} has invalid candidate cost")
        public_api = metadata.get("public_api")
        if not isinstance(public_api, str) or not public_api.strip():
            raise GraphValidationError(f"node {node_id} lacks a public API")
        if not isinstance(metadata.get("allow_passthrough"), bool):
            raise GraphValidationError(
                f"node {node_id} requires boolean allow_passthrough"
            )
        cls._validate_scope(node_id, metadata, protected_effects)

    def _reject_cycles(self) -> None:
        state: dict[str, int] = {node_id: 0 for node_id in self.nodes}

        def visit(node_id: str) -> None:
            if state[node_id] == 1:
                raise GraphCycleError(
                    "graph contains a cycle; unroll retry/loop paths before analysis"
                )
            if state[node_id] == 2:
                return
            state[node_id] = 1
            for target in self.successors[node_id]:
                visit(target)
            state[node_id] = 2

        for node_id in sorted(self.nodes):
            visit(node_id)

    def _require_reachable_effects(self) -> None:
        reachable = {self.entry}
        pending = [self.entry]
        while pending:
            source = pending.pop()
            for target in self.successors[source]:
                if target not in reachable:
                    reachable.add(target)
                    pending.append(target)
        missing = sorted(set(self.protected_effects) - reachable)
        if missing:
            raise GraphValidationError(
                f"protected effects are unreachable from entry: {', '.join(missing)}"
            )

    @staticmethod
    def _in_scope(metadata: Mapping[str, Any], effect: str) -> bool:
        return effect in metadata.get("protects", (effect,))

    def decision_mediates(self, node_id: str, effect: str) -> bool:
        metadata = self.nodes[node_id].get("decision")
        return bool(
            metadata
            and metadata["release_conditioned"]
            and self._in_scope(metadata, effect)
        )

    def candidate_is_eligible(self, node_id: str, effect: str) -> bool:
        metadata = self.nodes[node_id].get("candidate")
        return bool(
            metadata
            and metadata["allow_passthrough"]
            and self._in_scope(metadata, effect)
        )

    def effect_paths(self, max_paths: int = 256) -> tuple[PathRecord, ...]:
        if isinstance(max_paths, bool) or not isinstance(max_paths, int) or max_paths <= 0:
            raise GraphValidationError("max_paths must be a positive integer")
        records: list[PathRecord] = []

        def walk(node_id: str, effect: str, path: tuple[str, ...]) -> None:
            if node_id == effect:
                mediated_by = tuple(
                    candidate
                    for candidate in path[:-1]
                    if self.decision_mediates(candidate, effect)
                )
                records.append(PathRecord(effect, path, mediated_by))
                if len(records) > max_paths:
                    raise PathLimitExceeded(
                        f"entry-to-effect paths exceed max_paths={max_paths}"
                    )
                return
            for target in self.successors[node_id]:
                walk(target, effect, (*path, target))

        for effect in sorted(self.protected_effects):
            walk(self.entry, effect, (self.entry,))
        return tuple(records)

    def distance_to_effect(self, node_id: str) -> int:
        candidate = self.nodes[node_id]["candidate"]
        scoped_effects = {
            effect
            for effect in self.protected_effects
            if self._in_scope(candidate, effect)
        }
        pending: deque[tuple[str, int]] = deque([(node_id, 0)])
        seen = {node_id}
        while pending:
            current, distance = pending.popleft()
            if current in scoped_effects:
                return distance
            for target in self.successors[current]:
                if target not in seen:
                    seen.add(target)
                    pending.append((target, distance + 1))
        raise GraphValidationError(
            f"candidate {node_id} cannot reach an in-scope protected effect"
        )


def _coerce_graph(graph: EffectGraph | Mapping[str, Any]) -> EffectGraph:
    return graph if isinstance(graph, EffectGraph) else EffectGraph.from_dict(graph)


def audit_effect_graph(
    graph: EffectGraph | Mapping[str, Any], max_paths: int = 256
) -> dict[str, Any]:
    model = _coerce_graph(graph)
    paths = model.effect_paths(max_paths=max_paths)
    uncovered = tuple(record for record in paths if not record.mediated_by)
    minimal = min(
        uncovered,
        key=lambda record: (len(record.nodes), record.nodes, record.effect),
        default=None,
    )
    return {
        "conforms": not uncovered,
        "violation": bool(uncovered),
        "path_count": len(paths),
        "mediated_path_count": len(paths) - len(uncovered),
        "unmediated_path_count": len(uncovered),
        "paths": [record.to_dict() for record in paths],
        "unmediated_paths": [record.to_dict() for record in uncovered],
        "minimal_counterexample": minimal.to_dict() if minimal else None,
    }


def verify_repair(
    graph: EffectGraph | Mapping[str, Any],
    selected_nodes: Iterable[str],
    max_paths: int = 256,
) -> dict[str, Any]:
    model = _coerce_graph(graph)
    selected = tuple(selected_nodes)
    if len(set(selected)) != len(selected):
        raise GraphValidationError("selected repair contains duplicate nodes")
    for node_id in selected:
        if node_id not in model.nodes:
            raise GraphValidationError(f"selected repair references unknown node: {node_id}")
        if "candidate" not in model.nodes[node_id]:
            raise GraphValidationError(f"selected node is not a candidate: {node_id}")

    uncovered_after: list[PathRecord] = []
    for record in model.effect_paths(max_paths=max_paths):
        patched = any(
            node_id in record.nodes[:-1]
            and model.candidate_is_eligible(node_id, record.effect)
            for node_id in selected
        )
        if not record.mediated_by and not patched:
            uncovered_after.append(record)

    allow_preserved = all(
        bool(model.nodes[node_id]["candidate"]["allow_passthrough"])
        for node_id in selected
    )
    return {
        "deny_safe": not uncovered_after,
        "allow_preserved": allow_preserved,
        "unmediated_after_repair": [
            record.to_dict() for record in uncovered_after
        ],
    }


def synthesize_effect_repair(
    graph: EffectGraph | Mapping[str, Any],
    max_paths: int = 256,
    max_candidates: int = 20,
) -> dict[str, Any]:
    model = _coerce_graph(graph)
    if (
        isinstance(max_candidates, bool)
        or not isinstance(max_candidates, int)
        or max_candidates <= 0
    ):
        raise GraphValidationError("max_candidates must be a positive integer")

    audit = audit_effect_graph(model, max_paths=max_paths)
    if audit["conforms"]:
        verification = verify_repair(model, (), max_paths=max_paths)
        return {
            "status": "already_conforming",
            "selected_nodes": [],
            "patch": [],
            "total_cost": 0.0,
            "objective": [0.0, 0, 0, []],
            "audit": audit,
            "verification": verification,
        }

    uncovered = tuple(
        PathRecord(
            effect=row["effect"],
            nodes=tuple(row["path"]),
            mediated_by=tuple(row["mediated_by"]),
        )
        for row in audit["unmediated_paths"]
    )
    candidate_ids = sorted(
        node_id
        for node_id, node in model.nodes.items()
        if "candidate" in node
        and any(
            node_id in record.nodes[:-1]
            and model.candidate_is_eligible(node_id, record.effect)
            for record in uncovered
        )
    )
    if len(candidate_ids) > max_candidates:
        raise CandidateLimitExceeded(
            f"eligible candidates exceed max_candidates={max_candidates}"
        )

    coverage: dict[str, frozenset[int]] = {
        node_id: frozenset(
            index
            for index, record in enumerate(uncovered)
            if node_id in record.nodes[:-1]
            and model.candidate_is_eligible(node_id, record.effect)
        )
        for node_id in candidate_ids
    }
    uncovered_indexes = frozenset(range(len(uncovered)))
    impossible = [
        uncovered[index].to_dict()
        for index in sorted(uncovered_indexes)
        if not any(index in covered for covered in coverage.values())
    ]
    if impossible:
        return {
            "status": "unrepairable",
            "selected_nodes": [],
            "patch": [],
            "total_cost": None,
            "objective": None,
            "audit": audit,
            "verification": {
                "deny_safe": False,
                "allow_preserved": True,
                "unmediated_after_repair": audit["unmediated_paths"],
            },
            "unrepairable_paths": impossible,
        }

    best_nodes: tuple[str, ...] | None = None
    best_objective: tuple[Decimal, int, int, tuple[str, ...]] | None = None
    for size in range(1, len(candidate_ids) + 1):
        for selected in combinations(candidate_ids, size):
            covered = frozenset().union(*(coverage[node_id] for node_id in selected))
            if covered != uncovered_indexes:
                continue
            cost = sum(
                (
                    Decimal(str(model.nodes[node_id]["candidate"]["cost"]))
                    for node_id in selected
                ),
                Decimal(0),
            )
            distance = sum(model.distance_to_effect(node_id) for node_id in selected)
            objective = (cost, len(selected), distance, selected)
            if best_objective is None or objective < best_objective:
                best_objective = objective
                best_nodes = selected

    if best_nodes is None or best_objective is None:
        raise EffectGraphError("internal solver error: feasible cover was not found")

    verification = verify_repair(model, best_nodes, max_paths=max_paths)
    patch = [
        {
            "node_id": node_id,
            "cost": float(model.nodes[node_id]["candidate"]["cost"]),
            "public_api": model.nodes[node_id]["candidate"]["public_api"],
            "allow_passthrough": model.nodes[node_id]["candidate"][
                "allow_passthrough"
            ],
        }
        for node_id in best_nodes
    ]
    return {
        "status": "repaired",
        "selected_nodes": list(best_nodes),
        "patch": patch,
        "total_cost": float(best_objective[0]),
        "objective": [
            float(best_objective[0]),
            best_objective[1],
            best_objective[2],
            list(best_objective[3]),
        ],
        "audit": audit,
        "verification": verification,
    }
