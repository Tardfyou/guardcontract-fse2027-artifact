from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from guardcontract.paths import project_root

import argparse
import ast
import json
import re
import sys
import tomllib
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml


PROJECT_DIR = project_root()
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from guardcontract.discovery.dependencies import analyze_guard_repositories_i3 as core
from guardcontract.discovery.dependencies import analyze_guard_repositories_i4 as base


BASE_INDEX = core.RepositoryIndex
OUTBOUND_READ_CALLS = {
    "httpx.get": "outbound-http",
    "httpx.head": "outbound-http",
    "httpx.options": "outbound-http",
    "httpx.request": "outbound-http",
    "requests.get": "outbound-http",
    "requests.head": "outbound-http",
    "requests.options": "outbound-http",
    "requests.request": "outbound-http",
    "urllib.request.urlopen": "outbound-http",
}
CONFIG_SUFFIXES = {".json", ".toml", ".yaml", ".yml"}
GUARD_KEYS = {"guardrail", "guardrails", "guardrail_type", "output_guardrails"}
GUARD_CONFIG_TEXT = re.compile(
    r"(?im)^\s*[\"']?(?:guardrail|guardrails|guardrail_type|output_guardrails)[\"']?\s*[:=]"
)


def assignment_targets(node: ast.AST) -> Iterable[ast.AST]:
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        yield from targets
    elif isinstance(node, ast.Delete):
        yield from node.targets


class ConfigAwareRepositoryIndex(BASE_INDEX):
    def same_class_target(
        self,
        function: core.FunctionRef,
        raw_name: str,
        module: core.ModuleRecord,
    ) -> core.FunctionRef | None:
        first, dot, method = raw_name.partition(".")
        if first not in {"self", "cls"} or not dot or "." not in function.qualified_name:
            return None
        owner = function.qualified_name.rsplit(".", 1)[0]
        matches = [
            candidate
            for candidate in module.functions
            if candidate.qualified_name == f"{owner}.{method}"
        ]
        return matches[0] if len(matches) == 1 else None

    def function_effects(
        self,
        function: core.FunctionRef,
        active: frozenset[core.FunctionRef] = frozenset(),
    ) -> list[dict[str, Any]]:
        cached = self._effect_cache.get(function)
        if cached is not None:
            return cached
        if function in active:
            return []
        module = next(item for item in self.modules if item.path == function.path)
        effects: dict[tuple[str, int, str], dict[str, Any]] = {}

        global_names = {
            name
            for declaration in ast.walk(function.node)
            if isinstance(declaration, ast.Global)
            for name in declaration.names
        }
        for statement in ast.walk(function.node):
            for target in assignment_targets(statement):
                names = [item.id for item in ast.walk(target) if isinstance(item, ast.Name)]
                for name in sorted(global_names.intersection(names)):
                    call = f"global-write:{name}"
                    effects[(function.path, statement.lineno, call)] = {
                        "path": function.path,
                        "line": statement.lineno,
                        "call": call,
                        "family": "process-memory",
                        "model": "explicit-global-write",
                        "confidence": "high",
                        "via": function.qualified_name,
                        "effect_semantics": "state mutation remains visible after a later output denial",
                    }

        for call in (item for item in ast.walk(function.node) if isinstance(item, ast.Call)):
            raw_name = core.dotted_name(call.func) or ""
            normalized = module.normalize_name(raw_name) or raw_name
            model = None
            family = None
            confidence = None
            if normalized == "builtins.open":
                mode: Any = None
                if len(call.args) > 1 and isinstance(call.args[1], ast.Constant):
                    mode = call.args[1].value
                mode_keyword = core.call_keyword(call, "mode")
                if isinstance(mode_keyword, ast.Constant):
                    mode = mode_keyword.value
                if isinstance(mode, str) and any(flag in mode for flag in "wax+"):
                    model, family, confidence = "exact-call", "filesystem", "high"
            elif normalized in core.EXACT_EFFECT_CALLS:
                model, family, confidence = (
                    "exact-call",
                    core.EXACT_EFFECT_CALLS[normalized],
                    "high",
                )
            elif normalized in OUTBOUND_READ_CALLS:
                model, family, confidence = (
                    "exact-outbound-call",
                    OUTBOUND_READ_CALLS[normalized],
                    "high",
                )
            else:
                method = normalized.rsplit(".", 1)[-1]
                modeled = {**core.MUTATING_METHODS, "update": ("external-state", "medium")}.get(
                    method
                )
                if modeled:
                    family, confidence = modeled
                    model = "method-name"
            if model:
                effects[(function.path, call.lineno, normalized)] = {
                    "path": function.path,
                    "line": call.lineno,
                    "call": normalized,
                    "family": family,
                    "model": model,
                    "confidence": confidence,
                    "via": function.qualified_name,
                    "effect_semantics": "non-retractable external observation, disclosure, cost, or state change",
                }

            target, resolution = self.resolve_function(raw_name, module)
            if target is None:
                target = self.same_class_target(function, raw_name, module)
                if target is not None:
                    resolution = "same-class"
            if target is not None and target != function:
                for nested in self.function_effects(target, active | {function}):
                    copied = dict(nested)
                    copied["transitive_via"] = (
                        f"{function.path}:{function.qualified_name}:{call.lineno}"
                    )
                    copied["resolution"] = resolution
                    effects[(copied["path"], copied["line"], copied["call"])] = copied

        result = sorted(
            effects.values(), key=lambda item: (item["path"], item["line"], item["call"])
        )
        self._effect_cache[function] = result
        return result


@dataclass(frozen=True)
class ClassRef:
    path: str
    qualified_name: str
    simple_name: str
    node: ast.ClassDef


def module_classes(module: core.ModuleRecord) -> list[ClassRef]:
    result: list[ClassRef] = []

    def visit(body: list[ast.stmt], scope: list[str]) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                qualified = ".".join([*scope, node.name])
                result.append(ClassRef(module.path, qualified, node.name, node))
                visit(node.body, [*scope, node.name])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(node.body, [*scope, node.name])

    visit(module.tree.body, [])
    return result


class ToolRegistryIndex:
    def __init__(
        self,
        modules: list[core.ModuleRecord],
        repository: ConfigAwareRepositoryIndex,
    ) -> None:
        self.modules = modules
        self.repository = repository
        self.classes_by_symbol: dict[str, list[ClassRef]] = defaultdict(list)
        self.classes_by_simple: dict[str, list[ClassRef]] = defaultdict(list)
        for module in modules:
            for class_ref in module_classes(module):
                self.classes_by_simple[class_ref.simple_name].append(class_ref)
                for candidate in core.module_candidates(module.path) | {module.module}:
                    self.classes_by_symbol[f"{candidate}.{class_ref.qualified_name}"].append(
                        class_ref
                    )
        self.entries = self._registry_entries()

    def resolve_class(
        self, reference: str, module: core.ModuleRecord
    ) -> tuple[ClassRef | None, str]:
        normalized = module.normalize_name(reference) or reference
        exact = self.classes_by_symbol.get(normalized, [])
        if len(exact) == 1:
            return exact[0], "import-qualified"
        simple = normalized.rsplit(".", 1)[-1]
        local = [item for item in module_classes(module) if item.simple_name == simple]
        if len(local) == 1:
            return local[0], "same-module"
        global_matches = self.classes_by_simple.get(simple, [])
        if len(global_matches) == 1:
            return global_matches[0], "repository-unique"
        return None, "ambiguous" if len(global_matches) > 1 else "not-found"

    def constructor_reference(
        self,
        node: ast.AST,
        module: core.ModuleRecord,
        seen: frozenset[str] = frozenset(),
    ) -> str | None:
        if isinstance(node, ast.Lambda):
            return self.constructor_reference(node.body, module, seen)
        if isinstance(node, ast.Call):
            raw = core.dotted_name(node.func)
            return module.normalize_name(raw) or raw
        if isinstance(node, ast.Name) and node.id in module.assignments and node.id not in seen:
            return self.constructor_reference(
                module.assignments[node.id], module, seen | {node.id}
            )
        raw = core.dotted_name(node)
        return module.normalize_name(raw) or raw

    def _registry_entries(self) -> dict[str, list[dict[str, Any]]]:
        entries: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for module in self.modules:
            for assignment in ast.walk(module.tree):
                if not isinstance(assignment, ast.Assign) or not isinstance(
                    assignment.value, ast.Dict
                ):
                    continue
                for key, value in zip(assignment.value.keys, assignment.value.values):
                    if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                        continue
                    reference = self.constructor_reference(value, module)
                    if reference:
                        entries[key.value].append(
                            {
                                "constructor": reference,
                                "module": module,
                                "path": module.path,
                                "line": getattr(value, "lineno", assignment.lineno),
                            }
                        )
        return entries

    def class_effects(self, class_ref: ClassRef) -> list[dict[str, Any]]:
        module = next(item for item in self.modules if item.path == class_ref.path)
        methods = [
            function
            for function in module.functions
            if function.qualified_name.rsplit(".", 1)[0] == class_ref.qualified_name
            and function.simple_name in {"_arun", "_run", "__call__", "run"}
        ]
        effects: dict[tuple[str, int, str], dict[str, Any]] = {}
        for method in methods:
            for effect in self.repository.function_effects(method):
                effects[(effect["path"], effect["line"], effect["call"])] = effect
        return sorted(
            effects.values(), key=lambda item: (item["path"], item["line"], item["call"])
        )

    def tool_evidence(self, tool_names: list[str], config_path: str, task_name: str) -> dict[str, Any]:
        resolved = []
        unresolved = []
        effects: dict[tuple[str, int, str], dict[str, Any]] = {}
        for tool_name in tool_names:
            candidates = self.entries.get(tool_name, [])
            if len(candidates) != 1:
                exact = [
                    (name, family, confidence)
                    for name, (family, confidence) in base.PROTECTED_TOOL_CONSTRUCTORS.items()
                    if name.rsplit(".", 1)[-1] == tool_name
                ]
                if len(exact) == 1:
                    constructor, family, confidence = exact[0]
                    effect = {
                        "path": config_path,
                        "line": 1,
                        "call": constructor,
                        "family": family,
                        "model": "exact-configured-framework-tool",
                        "confidence": confidence,
                        "via": f"{config_path}:{task_name}:{tool_name}",
                        "effect_semantics": "non-retractable external observation, disclosure, cost, or state change",
                    }
                    effects[(effect["path"], effect["line"], effect["call"])] = effect
                    resolved.append(
                        {"name": tool_name, "constructor": constructor, "effects": [effect]}
                    )
                else:
                    unresolved.append(
                        {
                            "name": tool_name,
                            "resolution": "registry-ambiguous" if candidates else "registry-missing",
                        }
                    )
                continue
            candidate = candidates[0]
            class_ref, resolution = self.resolve_class(
                candidate["constructor"], candidate["module"]
            )
            if class_ref is None:
                unresolved.append(
                    {
                        "name": tool_name,
                        "constructor": candidate["constructor"],
                        "resolution": resolution,
                    }
                )
                continue
            local_effects = self.class_effects(class_ref)
            resolved.append(
                {
                    "name": tool_name,
                    "constructor": candidate["constructor"],
                    "class": f"{class_ref.path}:{class_ref.node.lineno}",
                    "resolution": resolution,
                    "effects": local_effects,
                }
            )
            for effect in local_effects:
                copied = dict(effect)
                copied["config_via"] = f"{config_path}:{task_name}:{tool_name}"
                effects[(copied["path"], copied["line"], copied["call"])] = copied
        effect_list = sorted(
            effects.values(), key=lambda item: (item["path"], item["line"], item["call"])
        )
        high = [item for item in effect_list if item["confidence"] == "high"]
        return {
            "bound_tools": tool_names,
            "resolved_tools": resolved,
            "unresolved_tools": unresolved,
            "explicit_effects": effect_list,
            "effect_status": (
                "explicit_effect"
                if high
                else (
                    "possible_effect"
                    if effect_list
                    else ("unknown" if unresolved else "no_effect_observed")
                )
            ),
            "binding_model": "declarative-config-to-registry-to-tool-class",
        }


def config_documents(path: Path) -> tuple[list[Any], str | None]:
    try:
        raw = path.read_text(encoding="utf-8")
        if path.suffix in {".yaml", ".yml"}:
            return list(yaml.safe_load_all(raw)), None
        if path.suffix == ".json":
            return [json.loads(raw)], None
        if path.suffix == ".toml":
            return [tomllib.loads(raw)], None
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as exc:
        return [], type(exc).__name__
    return [], None


def crew_groups(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        if isinstance(value.get("agents"), dict) and isinstance(value.get("tasks"), dict):
            yield value
        for nested in value.values():
            yield from crew_groups(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from crew_groups(nested)


def tool_names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict) and isinstance(item.get("name"), str):
            result.append(item["name"])
    return result


def config_key_line(raw: str, key: str) -> int:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:")
    return next(
        (line for line, text in enumerate(raw.splitlines(), 1) if pattern.match(text)),
        1,
    )


def configuration_sites(
    repo_dir: Path,
    registry: ToolRegistryIndex,
    max_files: int,
    max_bytes: int,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
    paths = [
        path
        for path in sorted(repo_dir.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and ".git" not in path.parts
        and path.suffix.lower() in CONFIG_SUFFIXES
    ]
    truncated = len(paths) > max_files
    sites = []
    errors = []
    for path in paths[:max_files]:
        relative = path.relative_to(repo_dir).as_posix()
        if path.stat().st_size > max_bytes:
            try:
                prefix = path.read_text(encoding="utf-8", errors="ignore")[:262_144]
            except OSError:
                prefix = ""
            if GUARD_CONFIG_TEXT.search(prefix):
                errors.append({"path": relative, "error": "file_size_limit"})
            continue
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append({"path": relative, "error": type(exc).__name__})
            continue
        if not GUARD_CONFIG_TEXT.search(raw):
            continue
        documents, error = config_documents(path)
        if error:
            errors.append({"path": relative, "error": error})
            continue
        for document in documents:
            for group in crew_groups(document):
                agents = group["agents"]
                for task_name, task in group["tasks"].items():
                    if not isinstance(task, dict) or not GUARD_KEYS.intersection(task):
                        continue
                    agent_name = task.get("agent")
                    agent = agents.get(agent_name, {}) if isinstance(agent_name, str) else {}
                    names = list(
                        dict.fromkeys(
                            [
                                *tool_names(task.get("tools")),
                                *tool_names(agent.get("tools") if isinstance(agent, dict) else None),
                            ]
                        )
                    )
                    evidence = registry.tool_evidence(names, relative, str(task_name))
                    guards = [
                        f"{key}={task[key]!r}" for key in sorted(GUARD_KEYS.intersection(task))
                    ]
                    sites.append(
                        {
                            "path": relative,
                            "line": config_key_line(raw, str(task_name)),
                            "construct": "Task(config)",
                            "lifecycle": "crewai-task-output",
                            "guard": ";".join(guards),
                            "decidability": "post_effect_dependent",
                            "decidability_evidence": {
                                "reason": "declarative task guard evaluates produced task output",
                                "task": str(task_name),
                                "agent": agent_name,
                            },
                            "tool_evidence": evidence,
                            "configuration_binding_evidence": {
                                "task": str(task_name),
                                "agent": agent_name,
                                "tools": names,
                            },
                            "repair_class": core.repair_class(
                                "crewai-task-output",
                                "post_effect_dependent",
                                evidence,
                                False,
                            ),
                        }
                    )
    return sites, errors, truncated


def parse_repository_modules(
    repo_dir: Path, selected: dict[str, Any], config: dict[str, Any]
) -> list[core.ModuleRecord]:
    paths, _, _ = core.repository_sources(
        repo_dir,
        selected["matched_files"],
        int(config["max_repository_python_files"]),
    )
    modules = []
    for relative in paths:
        path = repo_dir / relative
        if path.stat().st_size > int(config["max_python_file_bytes"]):
            continue
        try:
            modules.append(core.ModuleRecord.parse(path, relative))
        except (SyntaxError, UnicodeError, OSError):
            continue
    return modules


def recompute_counts(result: dict[str, Any]) -> None:
    sites = [site for row in result["repositories"] for site in row["sites"]]
    result["counts"].update(
        {
            "repositories_with_sites": len(
                {row["repository"] for row in result["repositories"] if row["sites"]}
            ),
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
            "guard_sites": len(sites),
            "configuration_guard_sites": sum(
                site["construct"] == "Task(config)" for site in sites
            ),
            "explicit_effect_sites": sum(
                site["tool_evidence"]["effect_status"] == "explicit_effect"
                for site in sites
            ),
            "repair_classes": dict(
                sorted(Counter(site["repair_class"] for site in sites).items())
            ),
            "decidability": dict(
                sorted(Counter(site["decidability"] for site in sites).items())
            ),
            "lifecycles": dict(
                sorted(Counter(site["lifecycle"] for site in sites).items())
            ),
            "configuration_parse_errors": sum(
                len(row.get("configuration_parse_errors", []))
                for row in result["repositories"]
            ),
            "configuration_scan_truncated_repositories": sum(
                bool(row.get("configuration_scan_truncated"))
                for row in result["repositories"]
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
    original_index = core.RepositoryIndex
    core.RepositoryIndex = ConfigAwareRepositoryIndex
    try:
        result = base.analyze(config)
    finally:
        core.RepositoryIndex = original_index

    frame = json.loads(Path(config["frame"]).read_text(encoding="utf-8"))
    selected_by_name = {
        item["repository"]["full_name"]: item
        for item in frame[config.get("repository_list_field", "selected")]
    }
    materialization = json.loads(Path(config["materialization"]).read_text(encoding="utf-8"))
    roots = {
        row["repository"]: Path(row["destination"])
        for row in materialization["repositories"]
        if row["status"] == "completed"
    }
    for row in result["repositories"]:
        if row["framework"] != "crewai":
            row["configuration_parse_errors"] = []
            row["configuration_scan_truncated"] = False
            continue
        repo_dir = roots[row["repository"]]
        modules = parse_repository_modules(
            repo_dir, selected_by_name[row["repository"]], config
        )
        repository = ConfigAwareRepositoryIndex(modules)
        registry = ToolRegistryIndex(modules, repository)
        sites, errors, truncated = configuration_sites(
            repo_dir,
            registry,
            int(config.get("max_repository_config_files", 2000)),
            int(config.get("max_config_file_bytes", 1_048_576)),
        )
        existing = {
            (site["path"], site["line"], site["construct"], site["guard"])
            for site in row["sites"]
        }
        row["sites"].extend(
            site
            for site in sites
            if (site["path"], site["line"], site["construct"], site["guard"])
            not in existing
        )
        row["sites"] = sorted(
            row["sites"], key=lambda item: (item["path"], item["line"], item["guard"])
        )
        row["configuration_parse_errors"] = errors
        row["configuration_scan_truncated"] = truncated
        row["role"] = core.repository_role(
            row["repository"], row["sites"], row["excluded_matched_files"]
        )

    result["analysis_scope"] = (
        "development-only repository-wide Python and declarative configuration semantic index "
        "with config-to-task-to-agent-to-registry-to-tool binding, same-class call recovery, "
        "and exact outbound/global-state effect models"
    )
    result["effect_model_boundary"] = (
        "exact calls, explicit global writes, exact framework tool constructors, and statically "
        "resolved configuration registries; unresolved dynamic dispatch and receiver types stay unknown"
    )
    recompute_counts(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Configuration-aware development analyzer for guard/effect topology"
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
