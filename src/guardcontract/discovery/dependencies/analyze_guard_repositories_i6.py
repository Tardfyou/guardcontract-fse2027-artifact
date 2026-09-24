from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from guardcontract.paths import project_root

import argparse
import ast
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml


PROJECT_DIR = project_root()
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from guardcontract.discovery.dependencies import analyze_guard_repositories_i3 as core
from guardcontract.discovery.dependencies import analyze_guard_repositories_i5 as base


def subscript_string(node: ast.AST | None) -> str | None:
    if not isinstance(node, ast.Subscript):
        return None
    value = node.slice
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return None


class HybridRepositoryIndex(base.ConfigAwareRepositoryIndex):
    def __init__(self, modules: list[core.ModuleRecord]) -> None:
        super().__init__(modules)
        self.modules_by_symbol: dict[str, list[core.ModuleRecord]] = defaultdict(list)
        for module in modules:
            for name in core.module_candidates(module.path) | {module.module}:
                self.modules_by_symbol[name].append(module)
        self._hybrid_effect_cache: dict[core.FunctionRef, list[dict[str, Any]]] = {}

    def function_effects(
        self,
        function: core.FunctionRef,
        active: frozenset[core.FunctionRef] = frozenset(),
    ) -> list[dict[str, Any]]:
        cached = self._hybrid_effect_cache.get(function)
        if cached is not None:
            return cached
        effects = {
            (item["path"], item["line"], item["call"]): item
            for item in super().function_effects(function, active)
        }
        module = next(item for item in self.modules if item.path == function.path)
        for call in (item for item in ast.walk(function.node) if isinstance(item, ast.Call)):
            if not isinstance(call.func, ast.Attribute) or call.func.attr != "invoke":
                continue
            receiver = call.func.value
            if not isinstance(receiver, ast.Call):
                continue
            constructor = module.normalize_name(core.dotted_name(receiver.func)) or ""
            if constructor.endswith(".QuerySQLDatabaseTool"):
                modeled = {
                    "path": function.path,
                    "line": call.lineno,
                    "call": f"{constructor}.invoke",
                    "family": "database-or-process",
                    "model": "exact-nested-sql-tool-call",
                    "confidence": "high",
                    "via": function.qualified_name,
                    "effect_semantics": (
                        "the SQL tool issues a database query before a later task-output denial"
                    ),
                }
                effects[(modeled["path"], modeled["line"], modeled["call"])] = modeled
        result = sorted(
            effects.values(), key=lambda item: (item["path"], item["line"], item["call"])
        )
        self._hybrid_effect_cache[function] = result
        return result

    def imported_assignment(
        self,
        reference: str,
        module: core.ModuleRecord,
    ) -> tuple[ast.AST, core.ModuleRecord] | None:
        normalized = module.normalize_name(reference) or reference
        owner, dot, symbol = normalized.rpartition(".")
        if not dot:
            return None
        modules = self.modules_by_symbol.get(owner, [])
        matches = [item for item in modules if symbol in item.assignments]
        if len(matches) != 1:
            return None
        return matches[0].assignments[symbol], matches[0]

    def unique_function(self, reference: str, module: core.ModuleRecord) -> core.FunctionRef | None:
        resolved, _ = self.resolve_function(reference, module)
        if resolved is not None:
            return resolved
        simple = reference.rsplit(".", 1)[-1]
        matches = self.functions_by_simple.get(simple, [])
        return matches[0] if len(matches) == 1 else None

    def tool_targets(
        self,
        node: ast.AST | None,
        module: core.ModuleRecord,
        seen: frozenset[tuple[str, str]] = frozenset(),
    ) -> list[tuple[str, str, core.ModuleRecord]]:
        if node is None:
            return []
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return [
                target
                for item in node.elts
                for target in self.tool_targets(item, module, seen)
            ]
        if isinstance(node, ast.Starred):
            return self.tool_targets(node.value, module, seen)
        if isinstance(node, ast.Name):
            key = (module.path, node.id)
            if key in seen:
                return []
            if node.id in module.assignments:
                return self.tool_targets(
                    module.assignments[node.id], module, seen | {key}
                )
            imported = self.imported_assignment(node.id, module)
            if imported:
                value, owner = imported
                return self.tool_targets(value, owner, seen | {key})
            return [("function", module.normalize_name(node.id) or node.id, module)]
        if isinstance(node, ast.Attribute):
            reference = module.normalize_name(core.dotted_name(node)) or core.dotted_name(node) or ""
            return [("function", reference, module)]
        if isinstance(node, ast.Call):
            reference = module.normalize_name(core.dotted_name(node.func)) or core.dotted_name(node.func) or ""
            return [("constructor", reference, module)]
        return []

    def agent_call_from_factory(
        self, reference: str, module: core.ModuleRecord
    ) -> tuple[ast.Call, core.ModuleRecord, core.FunctionRef] | None:
        function = self.unique_function(reference, module)
        if function is None:
            return None
        owner = next(item for item in self.modules if item.path == function.path)
        calls = [
            node
            for node in ast.walk(function.node)
            if isinstance(node, ast.Call)
            and (owner.normalize_name(core.dotted_name(node.func)) or "") == "crewai.Agent"
        ]
        if len(calls) != 1:
            return None
        return calls[0], owner, function

    def evidence_from_agent_factory(
        self, reference: str, module: core.ModuleRecord
    ) -> dict[str, Any]:
        found = self.agent_call_from_factory(reference, module)
        if found is None:
            return empty_evidence(reference, "agent-factory-not-unique")
        agent_call, owner, function = found
        evidence = self.evidence_from_tool_node(core.call_keyword(agent_call, "tools"), owner)
        evidence["agent_factory"] = f"{function.path}:{function.node.lineno}"
        evidence["agent_factory_resolution"] = "repository-unique"
        return evidence

    def evidence_from_tool_node(
        self, node: ast.AST | None, module: core.ModuleRecord
    ) -> dict[str, Any]:
        targets = self.tool_targets(node, module)
        effects: dict[tuple[str, int, str], dict[str, Any]] = {}
        resolved = []
        unresolved = []
        class_index = base.ToolRegistryIndex(self.modules, self)
        for kind, reference, owner in targets:
            if kind == "function":
                function = self.unique_function(reference, owner)
                if function is None:
                    unresolved.append({"name": reference, "resolution": "function-not-unique"})
                    continue
                found_effects = self.function_effects(function)
                resolved.append(
                    {
                        "name": reference,
                        "function": f"{function.path}:{function.node.lineno}",
                        "resolution": "repository-unique",
                        "effects": found_effects,
                    }
                )
            else:
                class_ref, resolution = class_index.resolve_class(reference, owner)
                if class_ref is None:
                    unresolved.append({"name": reference, "resolution": resolution})
                    continue
                found_effects = class_index.class_effects(class_ref)
                resolved.append(
                    {
                        "name": reference,
                        "class": f"{class_ref.path}:{class_ref.node.lineno}",
                        "resolution": resolution,
                        "effects": found_effects,
                    }
                )
            for effect in found_effects:
                effects[(effect["path"], effect["line"], effect["call"])] = effect
        effect_list = sorted(
            effects.values(), key=lambda item: (item["path"], item["line"], item["call"])
        )
        high = [item for item in effect_list if item["confidence"] == "high"]
        return {
            "bound_tools": [reference for _, reference, _ in targets],
            "resolved_tools": resolved,
            "unresolved_tools": unresolved,
            "explicit_effects": effect_list,
            "effect_status": (
                "explicit_effect"
                if high
                else ("possible_effect" if effect_list else ("unknown" if unresolved else "no_effect_observed"))
            ),
        }


def empty_evidence(reference: str, reason: str) -> dict[str, Any]:
    return {
        "bound_tools": [],
        "resolved_tools": [],
        "unresolved_tools": [{"name": reference, "resolution": reason}],
        "explicit_effects": [],
        "effect_status": "unknown",
    }


def merge_evidence(existing: dict[str, Any], recovered: dict[str, Any]) -> dict[str, Any]:
    effects = {
        (item["path"], item["line"], item["call"]): item
        for item in [
            *existing.get("explicit_effects", []),
            *recovered.get("explicit_effects", []),
        ]
    }
    merged = {
        "bound_tools": list(
            dict.fromkeys([*existing.get("bound_tools", []), *recovered.get("bound_tools", [])])
        ),
        "resolved_tools": [
            *existing.get("resolved_tools", []),
            *recovered.get("resolved_tools", []),
        ],
        "unresolved_tools": [
            *existing.get("unresolved_tools", []),
            *recovered.get("unresolved_tools", []),
        ],
        "explicit_effects": sorted(
            effects.values(), key=lambda item: (item["path"], item["line"], item["call"])
        ),
        "hybrid_binding": {
            key: value
            for key, value in recovered.items()
            if key in {"agent_factory", "agent_factory_resolution", "task_config"}
        },
    }
    if any(item["confidence"] == "high" for item in merged["explicit_effects"]):
        merged["effect_status"] = "explicit_effect"
    elif merged["explicit_effects"]:
        merged["effect_status"] = "possible_effect"
    elif merged["unresolved_tools"]:
        merged["effect_status"] = "unknown"
    else:
        merged["effect_status"] = "no_effect_observed"
    return merged


def yaml_agent_binding(repo_dir: Path, task_key: str) -> tuple[str, str] | None:
    matches = []
    for path in sorted([*repo_dir.rglob("*.yaml"), *repo_dir.rglob("*.yml")]):
        if path.is_symlink() or path.stat().st_size > 1_048_576:
            continue
        try:
            payload = yaml.safe_load(path.read_bytes())
        except (yaml.YAMLError, UnicodeError, OSError):
            continue
        if not isinstance(payload, dict):
            continue
        row = payload.get(task_key)
        if isinstance(row, dict) and isinstance(row.get("agent"), str):
            matches.append((row["agent"], path.relative_to(repo_dir).as_posix()))
    return matches[0] if len(matches) == 1 else None


def task_call_at_site(
    module: core.ModuleRecord, line: int
) -> ast.Call | None:
    matches = [
        node
        for node in ast.walk(module.tree)
        if isinstance(node, ast.Call)
        and node.lineno == line
        and (module.normalize_name(core.dotted_name(node.func)) or "") == "crewai.Task"
    ]
    return matches[0] if len(matches) == 1 else None


def recover_task_evidence(
    repo_dir: Path,
    modules: list[core.ModuleRecord],
    site: dict[str, Any],
) -> dict[str, Any]:
    module = next((item for item in modules if item.path == site["path"]), None)
    if module is None:
        return empty_evidence(site["path"], "site-module-missing")
    call = task_call_at_site(module, int(site["line"]))
    if call is None:
        return empty_evidence(site["path"], "task-call-not-unique")
    repository = HybridRepositoryIndex(modules)

    direct_tools = core.call_keyword(call, "tools")
    direct_agent = core.call_keyword(call, "agent")
    if direct_tools is not None:
        return repository.evidence_from_tool_node(direct_tools, module)
    if isinstance(direct_agent, ast.Call):
        reference = core.dotted_name(direct_agent.func) or ""
        return repository.evidence_from_agent_factory(reference, module)

    task_key = subscript_string(core.call_keyword(call, "config"))
    if task_key:
        binding = yaml_agent_binding(repo_dir, task_key)
        if binding:
            agent_name, config_path = binding
            evidence = repository.evidence_from_agent_factory(agent_name, module)
            evidence["task_config"] = {
                "key": task_key,
                "path": config_path,
                "agent": agent_name,
                "resolution": "unique-yaml-task-agent",
            }
            return evidence
    return empty_evidence(site["path"], "task-agent-binding-unresolved")


def recompute_counts(result: dict[str, Any]) -> None:
    sites = [site for row in result["repositories"] for site in row["sites"]]
    result["counts"].update(
        {
            "repositories_with_explicit_effect_site": len(
                {
                    row["repository"]
                    for row in result["repositories"]
                    if any(
                        site["tool_evidence"]["effect_status"] == "explicit_effect"
                        for site in row["sites"]
                    )
                }
            ),
            "explicit_effect_sites": sum(
                site["tool_evidence"]["effect_status"] == "explicit_effect"
                for site in sites
            ),
            "repair_classes": dict(
                sorted(Counter(site["repair_class"] for site in sites).items())
            ),
            "effect_families": dict(
                sorted(
                    Counter(
                        effect["family"]
                        for site in sites
                        for effect in site["tool_evidence"]["explicit_effects"]
                        if effect["confidence"] == "high"
                    ).items()
                )
            ),
        }
    )


def analyze(config: dict[str, Any]) -> dict[str, Any]:
    result = base.analyze(config)
    frame = json.loads(Path(config["frame"]).read_text(encoding="utf-8"))
    selected = {
        row["repository"]["full_name"]: row
        for row in frame[config.get("repository_list_field", "selected")]
    }
    materialization = json.loads(Path(config["materialization"]).read_text(encoding="utf-8"))
    roots = {
        row["repository"]: Path(row["destination"])
        for row in materialization["repositories"]
        if row["status"] == "completed"
    }
    for row in result["repositories"]:
        if row["framework"] != "crewai" or not row["sites"]:
            continue
        repo_dir = roots[row["repository"]]
        modules = base.parse_repository_modules(repo_dir, selected[row["repository"]], config)
        for site in row["sites"]:
            recovered = recover_task_evidence(repo_dir, modules, site)
            site["tool_evidence"] = merge_evidence(site["tool_evidence"], recovered)
            site["repair_class"] = core.repair_class(
                site["lifecycle"],
                site["decidability"],
                site["tool_evidence"],
                False,
            )
    recompute_counts(result)
    result["analysis_scope"] = (
        "development-only i5 analysis plus hybrid Python-Task/YAML-agent/factory/tool-list binding"
    )
    result["effect_model_boundary"] = (
        "i5 exact effects plus uniquely resolved cross-file function/class tool implementations; "
        "no heuristic promotion of ambiguous SDK receiver methods"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Hybrid Python/YAML CrewAI guard-to-effect topology analyzer"
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    result = analyze(config)
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
