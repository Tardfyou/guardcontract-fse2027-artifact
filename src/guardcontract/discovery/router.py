from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from guardcontract.core.schemas import EvidenceJob
from guardcontract.core.contracts import classify_guard_lifecycle
from guardcontract.discovery.scout import EffectSite, discover_repository_candidates, effect_sites_in_function
from guardcontract.evidence.slicing import EvidenceSlice, slice_file


@dataclass(frozen=True)
class RoutedJob:
    reason: str
    job: EvidenceJob
    slices: tuple[EvidenceSlice, ...]
    context: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"reason": self.reason, "job": self.job.to_dict(), "slices": [item.to_dict() for item in self.slices], "context": dict(self.context)}


def stable_node_id(repository_id: str, kind: str, path: str, line: int, symbol: str) -> str:
    canonical = "\0".join((repository_id, kind, path, str(line), symbol)).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _source_location(value: Any) -> tuple[str, int] | None:
    if not isinstance(value, str) or ":" not in value:
        return None
    path, raw_line = value.rsplit(":", 1)
    try:
        line = int(raw_line)
    except ValueError:
        return None
    return (path, line) if path and line > 0 else None


def uncertainty_reasons(site: Mapping[str, Any]) -> tuple[str, ...]:
    reasons = []
    tools = site.get("tool_evidence") if isinstance(site.get("tool_evidence"), Mapping) else {}
    if site.get("decidability") == "unknown_dynamic":
        reasons.append("unknown_guard_decidability")
    if tools.get("effect_status") == "unknown":
        reasons.append("unknown_effect")
    unresolved = tools.get("unresolved_tools", tools.get("unresolved", []))
    if isinstance(unresolved, list) and unresolved:
        reasons.append("unresolved_tool_binding")
    effects = tools.get("explicit_effects", [])
    if isinstance(effects, list) and any(isinstance(item, Mapping) and item.get("confidence") != "high" for item in effects):
        reasons.append("uncertain_effect_binding")
    return tuple(reasons)


QUESTIONS = {
    "unknown_guard_decidability": "Which supplied nodes and calls determine whether the guard decision requires data produced after a protected effect?",
    "unknown_effect": "Does the bound tool cause an externally observable effect, and what cited call establishes its effect family?",
    "unresolved_tool_binding": "Which supplied tool node is bound to this guarded execution path, if any?",
    "uncertain_effect_binding": "Is the cited possible effect reachable from the bound tool on this guarded path?",
    "semantic_contract_review": "Is there source-supported evidence that an externally observable effect can occur before DENY is enforced, or that a protected path can bypass this guard?",
    "repository_semantic_scout": "Does the supplied repository-local effect participate in a guarded agent path that can execute before DENY or bypass the guard?",
}


def _scout_jobs(
    root: Path,
    repository_id: str,
    *,
    mode: str,
    context_lines: int,
    max_slice_bytes: int,
    max_jobs: int,
    include_tests: bool,
    framework: str,
) -> list[RoutedJob]:
    routed = []
    candidates = discover_repository_candidates(root, include_tests=include_tests, max_candidates=max_jobs)
    for candidate in candidates:
        locations = [(candidate.guard_path, candidate.guard_line)]
        if candidate.guard_definition is not None:
            locations.append(candidate.guard_definition)
        locations.append((candidate.effect.path, candidate.effect.line))
        slices = []
        seen = set()
        for path, line in locations:
            if any(item.span.path == path and item.span.start_line <= line <= item.span.end_line for item in slices):
                continue
            line_count = len((root / path).read_bytes().splitlines())
            sliced = slice_file(
                root, path, max(1, line - context_lines), min(line_count, line + context_lines),
                cloud=mode == "cloud", max_bytes=max_slice_bytes,
            )
            key = (sliced.span.path, sliced.span.start_line, sliced.span.end_line)
            if key not in seen:
                seen.add(key)
                slices.append(sliced)
        guard_node = stable_node_id(repository_id, "guard", candidate.guard_path, candidate.guard_line, candidate.guard_marker)
        effect_node = stable_node_id(repository_id, "effect", candidate.effect.path, candidate.effect.line, candidate.effect.call)
        identity = "\0".join((repository_id, candidate.guard_path, str(candidate.guard_line), candidate.effect.path, str(candidate.effect.line), "repository_semantic_scout")).encode()
        job_id = "job:" + hashlib.sha256(identity).hexdigest()
        catalog = (
            f"guard {guard_node} = {candidate.guard_marker!r} at {candidate.guard_path}:{candidate.guard_line}; "
            f"effect {effect_node} = {candidate.effect.family}:{candidate.effect.call} at {candidate.effect.path}:{candidate.effect.line}"
        )
        decidability, contract_reason = classify_guard_lifecycle(framework, candidate.guard_marker)
        question = (
            QUESTIONS["repository_semantic_scout"]
            + f" Static lifecycle context: framework={framework}, decidability={decidability}, reason={contract_reason}."
            + " Node catalog: " + catalog
        )
        job = EvidenceJob(job_id, repository_id, question, (guard_node, effect_node), tuple(item.span for item in slices), 65_536, mode)
        routed.append(RoutedJob("repository_semantic_scout", job, tuple(slices), {
            "source": "repository_scout",
            "framework": framework,
            "decidability": decidability,
            "contract_reason": contract_reason,
            "effect_family": candidate.effect.family,
            "guard_definition_supplied": candidate.guard_definition is not None,
            "ast_tool_effect_binding": True,
        }))
    return routed


def route_analysis(
    analysis: Mapping[str, Any],
    materialization: Mapping[str, Any],
    *,
    mode: str,
    context_lines: int = 24,
    max_slice_bytes: int = 32_768,
    max_jobs: int = 10_000,
    routing_policy: str = "uncertainty",
    repository_allowlist: set[str] | None = None,
    max_evidence_slices: int = 4,
    max_total_slice_bytes: int = 65_536,
    max_jobs_per_repository: int | None = None,
    scout_include_tests: bool = False,
) -> list[RoutedJob]:
    if mode not in {"local", "cloud"}:
        raise ValueError("mode must be local or cloud")
    if routing_policy not in {"uncertainty", "semantic_all_sites", "repository_scout"}:
        raise ValueError("routing_policy must be uncertainty, semantic_all_sites, or repository_scout")
    if not 1 <= max_evidence_slices <= 16 or max_total_slice_bytes < 1024:
        raise ValueError("invalid evidence slice budget")
    if max_jobs_per_repository is not None and max_jobs_per_repository < 1:
        raise ValueError("max_jobs_per_repository must be positive")
    roots = {
        row["repository"]: Path(row["destination"])
        for row in materialization.get("repositories", [])
        if row.get("status") == "completed"
    }
    routed: list[RoutedJob] = []
    for repository in analysis.get("repositories", []):
        name, commit = repository.get("repository"), repository.get("commit")
        if not isinstance(name, str) or not isinstance(commit, str) or name not in roots:
            continue
        if repository_allowlist is not None and name not in repository_allowlist:
            continue
        repository_id = f"{name}@{commit}"
        root = roots[name]
        if routing_policy == "repository_scout":
            remaining = max_jobs - len(routed)
            per_repository = remaining if max_jobs_per_repository is None else min(remaining, max_jobs_per_repository)
            try:
                routed.extend(_scout_jobs(
                    root, repository_id, mode=mode, context_lines=context_lines,
                    max_slice_bytes=max_slice_bytes, max_jobs=per_repository, include_tests=scout_include_tests,
                    framework=str(repository.get("framework", "unknown")),
                ))
            except (OSError, ValueError):
                pass
            if len(routed) >= max_jobs:
                return routed[:max_jobs]
            continue
        repository_jobs = 0
        for site in repository.get("sites", []):
            if max_jobs_per_repository is not None and repository_jobs >= max_jobs_per_repository:
                break
            if not isinstance(site, Mapping):
                continue
            reasons = (
                ("semantic_contract_review",)
                if routing_policy == "semantic_all_sites"
                else uncertainty_reasons(site)
            )
            if not reasons:
                continue
            path, line = site.get("path"), site.get("line")
            if not isinstance(path, str) or not isinstance(line, int):
                continue
            target = root / path
            try:
                line_count = len(target.read_bytes().splitlines())
                sliced = slice_file(root, path, max(1, line - context_lines), min(line_count, line + context_lines), cloud=mode == "cloud", max_bytes=max_slice_bytes)
            except (OSError, ValueError):
                continue
            guard = str(site.get("guard", "unknown"))
            site_node = stable_node_id(repository_id, "guard", path, line, guard)
            allowed = [site_node]
            tools = site.get("tool_evidence") if isinstance(site.get("tool_evidence"), Mapping) else {}
            slices = [sliced]
            slice_locations = {(sliced.span.path, sliced.span.start_line, sliced.span.end_line)}
            total_slice_bytes = len(sliced.content.encode("utf-8"))
            resolved_locations: dict[str, tuple[str, int]] = {}
            discovered_effects: list[EffectSite] = []
            resolved_tools = tools.get("resolved_tools", [])
            if isinstance(resolved_tools, list):
                for resolved in resolved_tools:
                    if not isinstance(resolved, Mapping) or not isinstance(resolved.get("name"), str):
                        continue
                    location = _source_location(resolved.get("function"))
                    if location is not None:
                        resolved_locations[resolved["name"]] = location
                        discovered_effects.extend(effect_sites_in_function(root, location[0], location[1]))

            extra_locations = list(dict.fromkeys(resolved_locations.values()))
            extra_locations.extend((effect.path, effect.line) for effect in discovered_effects)
            explicit_effects = tools.get("explicit_effects", [])
            if isinstance(explicit_effects, list):
                for effect in explicit_effects:
                    if isinstance(effect, Mapping) and isinstance(effect.get("path"), str) and isinstance(effect.get("line"), int):
                        extra_locations.append((effect["path"], effect["line"]))
            for extra_path, extra_line in dict.fromkeys(extra_locations):
                if len(slices) >= max_evidence_slices:
                    break
                if any(item.span.path == extra_path and item.span.start_line <= extra_line <= item.span.end_line for item in slices):
                    continue
                try:
                    extra_target = root / extra_path
                    extra_line_count = len(extra_target.read_bytes().splitlines())
                    extra_slice = slice_file(
                        root,
                        extra_path,
                        max(1, extra_line - context_lines),
                        min(extra_line_count, extra_line + context_lines),
                        cloud=mode == "cloud",
                        max_bytes=max_slice_bytes,
                    )
                except (OSError, ValueError):
                    continue
                location_key = (extra_slice.span.path, extra_slice.span.start_line, extra_slice.span.end_line)
                encoded_size = len(extra_slice.content.encode("utf-8"))
                if location_key in slice_locations or total_slice_bytes + encoded_size > max_total_slice_bytes:
                    continue
                slices.append(extra_slice)
                slice_locations.add(location_key)
                total_slice_bytes += encoded_size
            raw_bound_tools = tools.get("bound_tools", [])
            bound_tools = list(dict.fromkeys(tool for tool in raw_bound_tools if isinstance(tool, str))) if isinstance(raw_bound_tools, list) else []
            for tool in bound_tools:
                tool_path, tool_line = resolved_locations.get(tool, (path, line))
                allowed.append(stable_node_id(repository_id, "tool", tool_path, tool_line, tool))
            node_catalog = [f"guard {site_node} = {guard!r}"]
            for node_id, tool in zip(allowed[1:], bound_tools):
                tool_path, tool_line = resolved_locations.get(tool, (path, line))
                node_catalog.append(f"tool {node_id} = {tool!r} at {tool_path}:{tool_line}")
            included_effects = [
                effect for effect in dict.fromkeys(discovered_effects)
                if any(item.span.path == effect.path and item.span.start_line <= effect.line <= item.span.end_line for item in slices)
            ]
            for effect in included_effects:
                effect_node = stable_node_id(repository_id, "effect", effect.path, effect.line, effect.call)
                if effect_node not in allowed:
                    allowed.append(effect_node)
                    node_catalog.append(f"effect {effect_node} = {effect.family}:{effect.call} at {effect.path}:{effect.line}")
            for reason in reasons:
                identity = "\0".join((
                    repository_id,
                    str(repository.get("framework", "unknown")),
                    str(site.get("lifecycle", "unknown")),
                    path,
                    str(line),
                    guard,
                    reason,
                )).encode()
                job_id = "job:" + hashlib.sha256(identity).hexdigest()
                question = (
                    QUESTIONS[reason]
                    + f" Static lifecycle context: framework={repository.get('framework', 'unknown')}, lifecycle={site.get('lifecycle', 'unknown')}, decidability={site.get('decidability', 'unknown_dynamic')}."
                    + " Node catalog: " + "; ".join(node_catalog)
                )
                job = EvidenceJob(job_id, repository_id, question, tuple(allowed), tuple(item.span for item in slices), 65_536, mode)
                routed.append(RoutedJob(reason, job, tuple(slices), {
                    "source": "static_site",
                    "framework": repository.get("framework", "unknown"),
                    "lifecycle": site.get("lifecycle", "unknown"),
                    "decidability": site.get("decidability", "unknown_dynamic"),
                    "effect_status": tools.get("effect_status", "unknown"),
                }))
                repository_jobs += 1
                if len(routed) >= max_jobs:
                    return routed
                if max_jobs_per_repository is not None and repository_jobs >= max_jobs_per_repository:
                    break
    return routed
