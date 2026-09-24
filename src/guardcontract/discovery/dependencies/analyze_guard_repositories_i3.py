from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from guardcontract.paths import project_root

import argparse
import ast
import hashlib
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


PROJECT_DIR = project_root()
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from guardcontract.discovery.dependencies.analyze_guard_repositories_i2 import excluded_source, repository_sources
from guardcontract.discovery.guard_semantics import classify as classify_guard_semantics


FRAMEWORK_CONSTRUCTORS = {
    "openai-agents": {"agents.Agent"},
    "crewai": {"crewai.Agent", "crewai.Task"},
}
PRE_EFFECT_LIFECYCLES = {"openai-input", "openai-tool-input", "crewai-before-tool"}
POST_EFFECT_LIFECYCLES = {"openai-output", "openai-tool-output", "crewai-task-output"}

EXACT_EFFECT_CALLS = {
    "builtins.open": "filesystem",
    "os.remove": "filesystem",
    "os.rename": "filesystem",
    "os.replace": "filesystem",
    "os.rmdir": "filesystem",
    "os.system": "process",
    "shutil.copy": "filesystem",
    "shutil.copyfile": "filesystem",
    "shutil.move": "filesystem",
    "shutil.rmtree": "filesystem",
    "subprocess.call": "process",
    "subprocess.Popen": "process",
    "subprocess.run": "process",
    "requests.delete": "network",
    "requests.patch": "network",
    "requests.post": "network",
    "requests.put": "network",
    "httpx.delete": "network",
    "httpx.patch": "network",
    "httpx.post": "network",
    "httpx.put": "network",
}

# These methods mutate an external system for the common Python APIs in which
# they appear. They remain explicitly tagged as method-name models so the
# result does not overstate receiver-type precision.
MUTATING_METHODS = {
    "commit": ("database", "high"),
    "delete": ("external-state", "medium"),
    "delete_object": ("cloud-storage", "high"),
    "execute": ("database-or-process", "medium"),
    "executemany": ("database", "medium"),
    "invoke": ("remote-service", "medium"),
    "mkdir": ("filesystem", "high"),
    "publish": ("message-or-release", "medium"),
    "put": ("external-state", "medium"),
    "put_item": ("cloud-database", "high"),
    "put_object": ("cloud-storage", "high"),
    "remove": ("external-state", "medium"),
    "rename": ("filesystem", "medium"),
    "rmdir": ("filesystem", "high"),
    "send": ("message-or-network", "medium"),
    "send_message": ("message-or-network", "high"),
    "sendmail": ("message-or-network", "high"),
    "unlink": ("filesystem", "high"),
    "upload": ("external-state", "medium"),
    "upload_file": ("cloud-storage", "high"),
    "write": ("filesystem-or-stream", "medium"),
    "write_bytes": ("filesystem", "high"),
    "write_text": ("filesystem", "high"),
}


def dotted_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Subscript):
        return dotted_name(node.value)
    return None


def call_keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((keyword.value for keyword in call.keywords if keyword.arg == name), None)


def decorator_call(node: ast.AST) -> tuple[str | None, ast.Call | None]:
    if isinstance(node, ast.Call):
        return dotted_name(node.func), node
    return dotted_name(node), None


def module_candidates(relative: str) -> set[str]:
    parts = list(Path(relative).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    candidates = set()
    for start in range(len(parts)):
        suffix = parts[start:]
        if suffix and all(part.isidentifier() for part in suffix):
            candidates.add(".".join(suffix))
    return candidates


def primary_module(relative: str) -> str:
    candidates = module_candidates(relative)
    if not candidates:
        return Path(relative).stem
    without_prefix = [name for name in candidates if not name.startswith(("src.", "lib."))]
    return min(without_prefix or candidates, key=lambda name: (name.count("."), len(name)))


def resolve_relative_import(current: str, level: int, module: str | None) -> str:
    package = current.split(".")[:-1]
    keep = max(0, len(package) - max(0, level - 1))
    prefix = package[:keep]
    if module:
        prefix.extend(module.split("."))
    return ".".join(prefix)


@dataclass(frozen=True)
class FunctionRef:
    path: str
    qualified_name: str
    simple_name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef


@dataclass
class ModuleRecord:
    path: str
    raw: bytes
    tree: ast.Module
    module: str
    imports: dict[str, str] = field(default_factory=dict)
    assignments: dict[str, ast.AST] = field(default_factory=dict)
    functions: list[FunctionRef] = field(default_factory=list)

    @classmethod
    def parse(cls, path: Path, relative: str) -> "ModuleRecord":
        raw = path.read_bytes()
        tree = ast.parse(raw, filename=relative)
        record = cls(path=relative, raw=raw, tree=tree, module=primary_module(relative))
        record._index()
        return record

    def _index(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports[alias.asname or alias.name.split(".")[0]] = alias.name
            elif isinstance(node, ast.ImportFrom):
                current_module = (self.module + ".__init__"
                                  if Path(self.path).name == "__init__.py" else self.module)
                base = resolve_relative_import(current_module, node.level, node.module)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    target = f"{base}.{alias.name}" if base else alias.name
                    self.imports[alias.asname or alias.name] = target
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and value is not None:
                        self.assignments[target.id] = value

        def visit_body(body: list[ast.stmt], scope: list[str]) -> None:
            for node in body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualified = ".".join([*scope, node.name])
                    self.functions.append(FunctionRef(self.path, qualified, node.name, node))
                    visit_body(node.body, [*scope, node.name])
                elif isinstance(node, ast.ClassDef):
                    visit_body(node.body, [*scope, node.name])

        visit_body(self.tree.body, [])

    def normalize_name(self, name: str | None) -> str | None:
        if not name:
            return None
        first, dot, rest = name.partition(".")
        target = self.imports.get(first)
        if target:
            return f"{target}.{rest}" if dot else target
        if name == "open":
            return "builtins.open"
        return name

    def resolve_values(self, node: ast.AST | None, seen: frozenset[str] = frozenset()) -> list[str]:
        if node is None:
            return []
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return [value for item in node.elts for value in self.resolve_values(item, seen)]
        if isinstance(node, ast.Starred):
            return self.resolve_values(node.value, seen)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return [*self.resolve_values(node.left, seen), *self.resolve_values(node.right, seen)]
        if isinstance(node, ast.Name):
            if node.id in self.assignments and node.id not in seen:
                return self.resolve_values(self.assignments[node.id], seen | {node.id})
            return [self.normalize_name(node.id) or node.id]
        if isinstance(node, ast.Attribute):
            name = dotted_name(node)
            return [self.normalize_name(name) or name or "<dynamic>"]
        if isinstance(node, ast.Lambda):
            return [f"<lambda:{self.path}:{node.lineno}>"]
        if isinstance(node, ast.Call):
            name = self.normalize_name(dotted_name(node.func)) or "dynamic"
            if name.endswith("function_tool") and node.args:
                return self.resolve_values(node.args[0], seen)
            return [f"<call:{name}:{self.path}:{node.lineno}>"]
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return ["<string-guard>"]
        return ["<dynamic>"]


class RepositoryIndex:
    def __init__(self, modules: list[ModuleRecord]) -> None:
        self.modules = modules
        self.functions_by_simple: dict[str, list[FunctionRef]] = defaultdict(list)
        self.functions_by_symbol: dict[str, list[FunctionRef]] = defaultdict(list)
        self._guard_semantics_cache: dict[tuple[FunctionRef, str], dict[str, Any]] = {}
        self.modules_by_name: dict[str, list[ModuleRecord]] = defaultdict(list)
        for module in modules:
            for candidate in module_candidates(module.path) | {module.module}:
                self.modules_by_name[candidate].append(module)
            for function in module.functions:
                self.functions_by_simple[function.simple_name].append(function)
                for candidate in module_candidates(module.path) | {module.module}:
                    self.functions_by_symbol[f"{candidate}.{function.simple_name}"].append(function)
        self._effect_cache: dict[FunctionRef, list[dict[str, Any]]] = {}

    @staticmethod
    def _nearest_by_source_path(candidates, referring_path: str):
        """Select a unique definition in the nearest parallel source tree.

        Repositories often vendor several applications or release phases that
        reuse the same Python package name.  An import in one tree should bind
        to that tree's package copy when it has a uniquely longest path prefix;
        equal-distance copies remain ambiguous.
        """
        reference_parts = Path(referring_path).parts

        def score(candidate) -> int:
            count = 0
            for left, right in zip(reference_parts, Path(candidate.path).parts):
                if left != right:
                    break
                count += 1
            return count

        ranked = [(score(candidate), candidate) for candidate in candidates]
        best_score = max((item[0] for item in ranked), default=0)
        best = [candidate for value, candidate in ranked if value == best_score]
        return best[0] if best_score > 0 and len(best) == 1 else None

    def resolve_function(self, reference: str, module: ModuleRecord) -> tuple[FunctionRef | None, str]:
        if reference.startswith("<"):
            return None, "dynamic"
        normalized = module.normalize_name(reference) or reference
        exact = self.functions_by_symbol.get(normalized, [])
        if len(exact) == 1:
            return exact[0], "import-qualified"
        if len(exact) > 1:
            nearest = self._nearest_by_source_path(exact, module.path)
            if nearest is not None:
                return nearest, "import-qualified-nearest-source-root"
        if "." in normalized:
            package_name, exported_name = normalized.rsplit(".", 1)
            packages = self.modules_by_name.get(package_name, [])
            if len(packages) > 1:
                nearest_package = self._nearest_by_source_path(packages, module.path)
                packages = [nearest_package] if nearest_package is not None else packages
            if len(packages) == 1:
                reexported = packages[0].imports.get(exported_name)
                matches = self.functions_by_symbol.get(reexported or "", [])
                if len(matches) == 1:
                    return matches[0], "package-reexport"
        simple = normalized.rsplit(".", 1)[-1]
        import_roots = {target.split(".", 1)[0] for target in module.imports.values()}
        if "." in normalized and normalized.split(".", 1)[0] not in import_roots:
            return None, "receiver-type-unresolved"
        local = [function for function in module.functions if function.simple_name == simple]
        if len(local) == 1:
            return local[0], "same-module"
        global_matches = self.functions_by_simple.get(simple, [])
        return None, "ambiguous" if len(global_matches) > 1 else "not-imported"

    def function_effects(
        self,
        function: FunctionRef,
        active: frozenset[FunctionRef] = frozenset(),
    ) -> list[dict[str, Any]]:
        cached = self._effect_cache.get(function)
        if cached is not None:
            return cached
        if function in active:
            return []
        module = next(module for module in self.modules if module.path == function.path)
        effects: dict[tuple[str, int, str], dict[str, Any]] = {}
        for call in (node for node in ast.walk(function.node) if isinstance(node, ast.Call)):
            raw_name = dotted_name(call.func) or ""
            normalized = module.normalize_name(raw_name) or raw_name
            model = None
            family = None
            confidence = None
            if normalized == "builtins.open":
                mode: Any = None
                if len(call.args) > 1 and isinstance(call.args[1], ast.Constant):
                    mode = call.args[1].value
                mode_kw = call_keyword(call, "mode")
                if isinstance(mode_kw, ast.Constant):
                    mode = mode_kw.value
                if isinstance(mode, str) and any(flag in mode for flag in "wax+"):
                    model, family, confidence = "exact-call", "filesystem", "high"
            elif normalized in EXACT_EFFECT_CALLS:
                model, family, confidence = "exact-call", EXACT_EFFECT_CALLS[normalized], "high"
            else:
                method = normalized.rsplit(".", 1)[-1]
                if method in MUTATING_METHODS:
                    family, confidence = MUTATING_METHODS[method]
                    model = "method-name"
            if model:
                key = (function.path, call.lineno, normalized)
                effects[key] = {
                    "path": function.path,
                    "line": call.lineno,
                    "call": normalized,
                    "family": family,
                    "model": model,
                    "confidence": confidence,
                    "via": function.qualified_name,
                }

            target, resolution = self.resolve_function(raw_name, module)
            if target is not None and target != function:
                for nested in self.function_effects(target, active | {function}):
                    copied = dict(nested)
                    copied["transitive_via"] = f"{function.path}:{function.qualified_name}:{call.lineno}"
                    copied["resolution"] = resolution
                    key = (copied["path"], copied["line"], copied["call"])
                    effects[key] = copied
        result = sorted(effects.values(), key=lambda item: (item["path"], item["line"], item["call"]))
        self._effect_cache[function] = result
        return result

    def guard_decidability(self, reference: str, lifecycle: str, module: ModuleRecord) -> tuple[str, dict[str, Any]]:
        denial = self.guard_denial_capability(reference, lifecycle, module)
        def detail(value):
            return {**value, "deny_capability": denial["deny_capability"],
                    "deny_capability_evidence": denial.get("evidence", []),
                    "deny_capability_analysis_complete": denial.get("analysis_complete", False)}
        if lifecycle in PRE_EFFECT_LIFECYCLES:
            return "pre_effect_decidable", detail({"reason": "framework lifecycle invokes this guard before tool dispatch"})
        if reference == "<string-guard>":
            return "post_effect_dependent", detail({"reason": "framework string guard evaluates produced task output"})
        if reference.startswith("<lambda:"):
            return "post_effect_dependent", detail({"reason": "inline guard executes in a post-effect lifecycle"})
        function, resolution = self.resolve_function(reference, module)
        if function is None:
            return "unknown_dynamic", detail({"reason": "guard callable is not uniquely resolvable", "resolution": resolution})
        args = [*function.node.args.posonlyargs, *function.node.args.args, *function.node.args.kwonlyargs]
        loaded = {node.id for node in ast.walk(function.node) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
        likely_outputs = [arg.arg for arg in args if arg.arg.lower() in {"output", "result", "data", "task_output", "final_output", "value"}]
        reads_output = any(name in loaded for name in likely_outputs)
        if lifecycle in POST_EFFECT_LIFECYCLES and (reads_output or args):
            return "post_effect_dependent", detail({
                "reason": "resolved callable runs after protected tool effects and reads lifecycle data",
                "function": f"{function.path}:{function.node.lineno}",
                "resolution": resolution,
                "likely_output_parameters": likely_outputs,
            })
        return "unknown_dynamic", detail({
            "reason": "resolved post-effect guard has no recognizable output dependency",
            "function": f"{function.path}:{function.node.lineno}",
            "resolution": resolution,
        })

    def guard_denial_capability(self, reference: str, lifecycle: str, module: ModuleRecord) -> dict[str, Any]:
        function, resolution = self.resolve_function(reference, module)
        if function is None:
            return {"deny_capability": "unknown", "analysis_complete": False,
                    "evidence": [{"kind": "guard_callable_unresolved", "resolution": resolution}]}
        cache_key = (function, lifecycle)
        cached = self._guard_semantics_cache.get(cache_key)
        if cached is not None:
            return cached
        reached = []
        seen = set()
        pending = [function]
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            reached.append(current.node)
            current_module = next(item for item in self.modules if item.path == current.path)
            for call in (node for node in ast.walk(current.node) if isinstance(node, ast.Call)):
                target, _ = self.resolve_function(dotted_name(call.func) or "", current_module)
                if target is not None and target not in seen:
                    pending.append(target)
        if lifecycle.startswith("openai-"):
            framework, parameter = "openai-agents", lifecycle
        elif lifecycle.startswith("crewai-"):
            framework, parameter = "crewai", "guardrail"
        else:
            framework, parameter = "unknown", lifecycle
        result = classify_guard_semantics(reached, framework=framework, parameter=parameter)
        self._guard_semantics_cache[cache_key] = result
        return result

    def tool_evidence(self, references: Iterable[str], module: ModuleRecord) -> dict[str, Any]:
        resolved = []
        unresolved = []
        effects: dict[tuple[str, int, str], dict[str, Any]] = {}
        for reference in references:
            function, resolution = self.resolve_function(reference, module)
            if function is None:
                unresolved.append({"name": reference, "resolution": resolution})
                continue
            local_effects = self.function_effects(function)
            resolved.append(
                {
                    "name": reference,
                    "function": f"{function.path}:{function.node.lineno}",
                    "resolution": resolution,
                    "effects": local_effects,
                }
            )
            for effect in local_effects:
                effects[(effect["path"], effect["line"], effect["call"])] = effect
        effect_list = sorted(effects.values(), key=lambda item: (item["path"], item["line"], item["call"]))
        high_confidence = [effect for effect in effect_list if effect["confidence"] == "high"]
        return {
            "bound_tools": list(references),
            "resolved_tools": resolved,
            "unresolved_tools": unresolved,
            "explicit_effects": effect_list,
            "effect_status": (
                "explicit_effect"
                if high_confidence
                else ("possible_effect" if effect_list else ("unknown" if unresolved else "no_effect_observed"))
            ),
        }


def repair_class(lifecycle: str, decidability: str, tools: dict[str, Any], existing_pre: bool) -> str:
    if tools["effect_status"] != "explicit_effect":
        return "not_scored_without_explicit_effect"
    if lifecycle in PRE_EFFECT_LIFECYCLES or existing_pre:
        return "existing_pre_effect_control_observed"
    if lifecycle in POST_EFFECT_LIFECYCLES or decidability == "post_effect_dependent":
        return "requires_effect_deferral"
    if decidability == "pre_effect_decidable":
        return "placement_only_candidate"
    return "manual_review_unknown_dependency"


def decorator_names(function: FunctionRef, module: ModuleRecord) -> list[str]:
    result = []
    for decorator in function.node.decorator_list:
        name, _ = decorator_call(decorator)
        result.append(module.normalize_name(name) or name or "<dynamic>")
    return result


def analyze_module(module: ModuleRecord, repository: RepositoryIndex, framework: str) -> dict[str, Any]:
    constructors = FRAMEWORK_CONSTRUCTORS[framework]
    calls = [node for node in ast.walk(module.tree) if isinstance(node, ast.Call)]
    existing_before_hook = any((module.normalize_name(dotted_name(call.func)) or "").endswith("register_before_tool_call_hook") for call in calls)
    sites: list[dict[str, Any]] = []

    for call in calls:
        call_name = module.normalize_name(dotted_name(call.func)) or ""
        if call_name not in constructors:
            continue
        construct = call_name.rsplit(".", 1)[-1]
        if framework == "openai-agents" and construct == "Agent":
            tool_names = module.resolve_values(call_keyword(call, "tools"))
            tools = repository.tool_evidence(tool_names, module)
            for keyword, lifecycle in (("output_guardrails", "openai-output"), ("input_guardrails", "openai-input")):
                for guard in module.resolve_values(call_keyword(call, keyword)):
                    decidability, detail = repository.guard_decidability(guard, lifecycle, module)
                    sites.append(
                        {
                            "path": module.path,
                            "line": call.lineno,
                            "construct": construct,
                            "lifecycle": lifecycle,
                            "guard": guard,
                            "decidability": decidability,
                            "decidability_evidence": detail,
                            "tool_evidence": tools,
                            "repair_class": repair_class(lifecycle, decidability, tools, False),
                        }
                    )
        elif framework == "crewai" and construct == "Task":
            guard_node = call_keyword(call, "guardrail")
            if guard_node is None:
                continue
            tool_names = module.resolve_values(call_keyword(call, "tools"))
            if not tool_names:
                agent_refs = module.resolve_values(call_keyword(call, "agent"))
                # A repository-unique agent factory often carries the tools;
                # unresolved factories stay visible instead of being guessed.
                for agent_ref in agent_refs:
                    factory, _ = repository.resolve_function(agent_ref, module)
                    if factory is None:
                        continue
                    factory_module = next(item for item in repository.modules if item.path == factory.path)
                    for nested_call in (node for node in ast.walk(factory.node) if isinstance(node, ast.Call)):
                        nested_name = factory_module.normalize_name(dotted_name(nested_call.func)) or ""
                        if nested_name == "crewai.Agent":
                            tool_names.extend(factory_module.resolve_values(call_keyword(nested_call, "tools")))
            tools = repository.tool_evidence(tool_names, module)
            for guard in module.resolve_values(guard_node):
                decidability, detail = repository.guard_decidability(guard, "crewai-task-output", module)
                sites.append(
                    {
                        "path": module.path,
                        "line": call.lineno,
                        "construct": construct,
                        "lifecycle": "crewai-task-output",
                        "guard": guard,
                        "decidability": decidability,
                        "decidability_evidence": detail,
                        "tool_evidence": tools,
                        "repair_class": repair_class("crewai-task-output", decidability, tools, existing_before_hook),
                    }
                )

    if framework == "openai-agents":
        for function in module.functions:
            for decorator in function.node.decorator_list:
                raw_name, call = decorator_call(decorator)
                name = module.normalize_name(raw_name) or ""
                if name != "agents.function_tool" or call is None:
                    continue
                tool_effects = repository.tool_evidence([function.simple_name], module)
                for keyword, lifecycle in (("tool_input_guardrails", "openai-tool-input"), ("tool_output_guardrails", "openai-tool-output")):
                    for guard in module.resolve_values(call_keyword(call, keyword)):
                        decidability, detail = repository.guard_decidability(guard, lifecycle, module)
                        sites.append(
                            {
                                "path": module.path,
                                "line": function.node.lineno,
                                "construct": "function_tool",
                                "lifecycle": lifecycle,
                                "guard": guard,
                                "decidability": decidability,
                                "decidability_evidence": detail,
                                "tool_evidence": tool_effects,
                                "repair_class": repair_class(lifecycle, decidability, tool_effects, False),
                            }
                        )

    return {
        "path": module.path,
        "bytes": len(module.raw),
        "sha256": hashlib.sha256(module.raw).hexdigest(),
        "framework_symbols": sorted({value for value in module.imports.values() if value.split(".")[0] in {"agents", "crewai"}}),
        "existing_before_tool_hook": existing_before_hook,
        "sites": sites,
    }


def repository_role(repository: str, sites: list[dict[str, Any]], excluded_matches: list[str]) -> str:
    paths = [site["path"] for site in sites]
    if any("src/crewai/" in path or "lib/crewai/src/crewai/" in path for path in paths):
        return "framework_source_or_mirror"
    if paths and all("test" in Path(path).name.lower() or "tests" in Path(path).parts for path in paths):
        return "tests_only"
    if paths and all(any(part in {"example", "examples", "demo", "demos"} for part in Path(path).parts) for path in paths):
        return "examples_only"
    if paths:
        return "candidate_integration"
    if excluded_matches:
        return "vendor_environment_only"
    return "no_confirmed_framework_site"


def analyze_repository(
    repo_dir: Path,
    paths: list[str],
    framework: str,
    max_bytes: int,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    parsed: list[ModuleRecord] = []
    errors = []
    for relative in paths:
        path = repo_dir / relative
        if path.stat().st_size > max_bytes:
            errors.append({"path": relative, "error": "file_size_limit"})
            continue
        try:
            parsed.append(ModuleRecord.parse(path, relative))
        except (SyntaxError, UnicodeError, OSError) as exc:
            errors.append({"path": relative, "error": type(exc).__name__})
    index = RepositoryIndex(parsed)
    return [analyze_module(module, index, framework) for module in parsed], errors


def selected_frameworks(selected: dict[str, Any], config: dict[str, Any]) -> list[str]:
    mapping = config.get("stratum_frameworks")
    if not mapping:
        return [selected["framework"]]
    frameworks = {
        mapping[stratum]
        for stratum in selected.get("eligible_strata", [])
        if stratum in mapping
    }
    if not frameworks:
        raise ValueError(
            f"selected repository {selected['repository']['full_name']} has no mapped framework"
        )
    return sorted(frameworks)


def analyze(config: dict[str, Any]) -> dict[str, Any]:
    frame = json.loads(Path(config["frame"]).read_text(encoding="utf-8"))
    materialization = json.loads(Path(config["materialization"]).read_text(encoding="utf-8"))
    materialized = {row["repository"]: row for row in materialization["repositories"] if row["status"] == "completed"}
    frame_repositories = frame[config.get("repository_list_field", "selected")]
    rows = []
    for selected in frame_repositories:
        repository_name = selected["repository"]["full_name"]
        materialized_row = materialized[repository_name]
        repo_dir = Path(materialized_row["destination"])
        paths, truncated, excluded_matches = repository_sources(
            repo_dir,
            selected["matched_files"],
            int(config["max_repository_python_files"]),
        )
        for framework in selected_frameworks(selected, config):
            modules, parse_errors = analyze_repository(
                repo_dir,
                paths,
                framework,
                int(config["max_python_file_bytes"]),
            )
            sites = [site for module in modules for site in module["sites"]]
            rows.append(
                {
                    "framework": framework,
                    "repository": repository_name,
                    "commit": selected["pinned_commit"],
                    "matched_files": len(selected["matched_files"]),
                    "excluded_matched_files": excluded_matches,
                    "scanned_files": len(modules),
                    "source_scan_truncated": truncated,
                    "parse_errors": parse_errors,
                    "role": repository_role(repository_name, sites, excluded_matches),
                    "sites": sites,
                }
            )
    sites = [site for row in rows for site in row["sites"]]
    repositories_with_sites = {row["repository"] for row in rows if row["sites"]}
    repositories_with_explicit_effect = {
        row["repository"]
        for row in rows
        if any(
            site["tool_evidence"]["effect_status"] == "explicit_effect"
            for site in row["sites"]
        )
    }
    return {
        "schema_version": 3,
        "task_version": config["task_version"],
        "split": config["split"],
        "analysis_scope": "development-only repository-wide Python semantic index with framework API identity, nested definitions, cross-file symbols, and transitive effect summaries",
        "effect_model_boundary": "exact modeled calls plus explicitly tagged method-name models; no receiver-type proof and no arbitrary dynamic dispatch",
        "counts": {
            "planned_repositories": len(frame_repositories),
            "completed_repositories": len({row["repository"] for row in rows}),
            "planned_repository_framework_pairs": sum(
                len(selected_frameworks(selected, config)) for selected in frame_repositories
            ),
            "completed_repository_framework_pairs": len(rows),
            "repositories_with_sites": len(repositories_with_sites),
            "repositories_with_explicit_effect_site": len(repositories_with_explicit_effect),
            "source_scan_truncated_repositories": len(
                {row["repository"] for row in rows if row["source_scan_truncated"]}
            ),
            "guard_sites": len(sites),
            "explicit_effect_sites": sum(site["tool_evidence"]["effect_status"] == "explicit_effect" for site in sites),
            "parse_errors": sum(len(row["parse_errors"]) for row in rows),
            "roles": dict(sorted(Counter(row["role"] for row in rows).items())),
            "repair_classes": dict(sorted(Counter(site["repair_class"] for site in sites).items())),
            "decidability": dict(sorted(Counter(site["decidability"] for site in sites).items())),
            "lifecycles": dict(sorted(Counter(site["lifecycle"] for site in sites).items())),
        },
        "repositories": rows,
        "execution_health": "completed",
        "scientific_outcome": "undetermined",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Development semantic analyzer for framework guard/effect topology")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    result = analyze(config)
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
