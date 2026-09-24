from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import argparse
import ast
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


EXCLUDED_PARTS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "Lib",
    "site-packages",
    "dist-packages",
    "node_modules",
    "vendor",
    "_vendor",
    "third_party",
    "build",
    "dist",
    ".tox",
}
EFFECT_CALL_PREFIXES = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "os.system",
    "shutil.copy",
    "shutil.copyfile",
    "shutil.move",
    "shutil.rmtree",
}
EFFECT_METHODS = {
    "write",
    "write_text",
    "write_bytes",
    "unlink",
    "remove",
    "rename",
    "replace",
    "mkdir",
    "rmdir",
    "send",
    "sendmail",
    "upload",
    "delete",
    "execute",
    "executemany",
    "commit",
    "publish",
}


def dotted_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def call_keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def reference_names(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [name for item in node.elts for name in reference_names(item)]
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        name = dotted_name(node)
        return [name] if name else []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return ["<string-guard>"]
    if isinstance(node, ast.Call):
        if node.args:
            inner = reference_names(node.args[0])
            if inner:
                return inner
        name = dotted_name(node.func)
        return [f"<call:{name or 'dynamic'}>"]
    if isinstance(node, ast.Lambda):
        return ["<inline-lambda>"]
    return ["<dynamic>"]


def assignment_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    return None


def assignment_value(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Assign):
        return node.value
    if isinstance(node, ast.AnnAssign):
        return node.value
    return None


def loaded_names(node: ast.AST) -> set[str]:
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)}


def function_effects(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> list[str]:
    effects = set()
    for item in ast.walk(node):
        if not isinstance(item, ast.Call):
            continue
        name = dotted_name(item.func) or ""
        if name == "open":
            mode = None
            if len(item.args) > 1 and isinstance(item.args[1], ast.Constant):
                mode = item.args[1].value
            mode_node = call_keyword(item, "mode")
            if isinstance(mode_node, ast.Constant):
                mode = mode_node.value
            if isinstance(mode, str) and any(flag in mode for flag in "wax+"):
                effects.add("file-write:open")
        if name in EFFECT_CALL_PREFIXES:
            effects.add(name)
        method = name.rsplit(".", 1)[-1]
        if method in EFFECT_METHODS:
            effects.add(f"method:{method}")
    return sorted(effects)


def function_args(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> list[str]:
    return [arg.arg for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]]


def decorators(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [dotted_name(item.func if isinstance(item, ast.Call) else item) or "<dynamic>" for item in node.decorator_list]


def false_keyword_on_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef, decorator_name: str, keyword: str) -> bool:
    for item in node.decorator_list:
        if isinstance(item, ast.Call) and (dotted_name(item.func) or "").endswith(decorator_name):
            value = call_keyword(item, keyword)
            if isinstance(value, ast.Constant) and value.value is False:
                return True
    return False


class ModuleIndex:
    def __init__(self, tree: ast.Module) -> None:
        self.tree = tree
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.assignments: dict[str, ast.AST] = {}
        self.import_roots: set[str] = set()
        self.calls: list[ast.Call] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node
            name = assignment_name(node)
            value = assignment_value(node)
            if name and value is not None:
                self.assignments[name] = value
            if isinstance(node, ast.Import):
                self.import_roots.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                self.import_roots.add(node.module)
        self.calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]

    def resolves_agent_tools(self, reference: ast.AST | None) -> list[str]:
        if isinstance(reference, ast.Name):
            value = self.assignments.get(reference.id)
            if isinstance(value, ast.Call) and (dotted_name(value.func) or "").endswith("Agent"):
                return reference_names(call_keyword(value, "tools"))
        return []


def classify_guard(
    reference: str,
    lifecycle: str,
    index: ModuleIndex,
) -> tuple[str, dict[str, Any]]:
    if lifecycle in {"openai-input", "openai-tool-input", "crewai-before-tool"}:
        return "pre_effect_decidable", {"reason": "framework lifecycle supplies the predicate before tool dispatch"}
    if reference == "<string-guard>":
        return "post_effect_dependent", {"reason": "framework string guard evaluates produced task output"}
    function = index.functions.get(reference)
    if function is None:
        return "unknown_dynamic", {"reason": "guard callable is not locally resolvable"}
    args = function_args(function)
    if not args:
        return "pre_effect_decidable", {"reason": "locally resolved guard has no output parameter"}
    output_name = args[-1]
    used = output_name in loaded_names(function)
    return (
        "post_effect_dependent" if used else "pre_effect_decidable",
        {"reason": "last guard parameter is read" if used else "last guard parameter is not read", "parameter": output_name},
    )


def tool_evidence(tool_names: list[str], index: ModuleIndex) -> dict[str, Any]:
    resolved = []
    unresolved = []
    effects = set()
    for name in tool_names:
        function = index.functions.get(name)
        if function is None:
            unresolved.append(name)
            continue
        local_effects = function_effects(function)
        resolved.append({"name": name, "effects": local_effects})
        effects.update(local_effects)
    return {
        "bound_tools": tool_names,
        "resolved_tools": resolved,
        "unresolved_tools": unresolved,
        "explicit_effects": sorted(effects),
        "effect_status": "explicit_effect" if effects else ("unknown" if tool_names else "no_tools"),
    }


def repair_class(decidability: str, tools: dict[str, Any], existing_pre: bool, serialized: bool) -> str:
    if tools["effect_status"] != "explicit_effect":
        return "not_scored_without_explicit_effect"
    if existing_pre or serialized:
        return "existing_pre_effect_control_observed"
    if decidability == "pre_effect_decidable":
        return "placement_only_candidate"
    if decidability == "post_effect_dependent":
        return "requires_effect_deferral"
    return "manual_review_unknown_dependency"


def analyze_module(path: Path, relative: str, framework: str) -> dict[str, Any]:
    raw = path.read_bytes()
    tree = ast.parse(raw, filename=relative)
    index = ModuleIndex(tree)
    imports_openai = any(root == "agents" or root.startswith("agents.") for root in index.import_roots)
    imports_crewai = any(root == "crewai" or root.startswith("crewai.") for root in index.import_roots)
    existing_before_hook = any((dotted_name(call.func) or "").endswith("register_before_tool_call_hook") for call in index.calls)
    existing_tool_guard = any(
        "tool_input_guardrail" in decorators(function) or any(name.endswith("tool_input_guardrail") for name in decorators(function))
        for function in index.functions.values()
    ) or any(call_keyword(call, "tool_input_guardrails") is not None for call in index.calls)
    sites = []
    for call in index.calls:
        call_name = dotted_name(call.func) or ""
        if framework == "openai-agents" and imports_openai and call_name.endswith("Agent"):
            tool_names = reference_names(call_keyword(call, "tools"))
            tools = tool_evidence(tool_names, index)
            for keyword, lifecycle in (("output_guardrails", "openai-output"), ("input_guardrails", "openai-input")):
                for guard in reference_names(call_keyword(call, keyword)):
                    decidability, detail = classify_guard(guard, lifecycle, index)
                    serialized = False
                    function = index.functions.get(guard)
                    if lifecycle == "openai-input" and function is not None:
                        serialized = false_keyword_on_decorator(function, "input_guardrail", "run_in_parallel")
                    sites.append(
                        {
                            "line": call.lineno,
                            "construct": "Agent",
                            "lifecycle": lifecycle,
                            "guard": guard,
                            "decidability": decidability,
                            "decidability_evidence": detail,
                            "serialized_input_guard": serialized,
                            "tool_evidence": tools,
                            "repair_class": repair_class(decidability, tools, existing_tool_guard, serialized),
                        }
                    )
        if framework == "crewai" and imports_crewai and call_name.endswith("Task"):
            guard_node = call_keyword(call, "guardrail")
            if guard_node is None:
                continue
            guard_names = reference_names(guard_node)
            tool_names = reference_names(call_keyword(call, "tools"))
            if not tool_names:
                tool_names = index.resolves_agent_tools(call_keyword(call, "agent"))
            tools = tool_evidence(tool_names, index)
            for guard in guard_names:
                decidability, detail = classify_guard(guard, "crewai-task-output", index)
                sites.append(
                    {
                        "line": call.lineno,
                        "construct": "Task",
                        "lifecycle": "crewai-task-output",
                        "guard": guard,
                        "decidability": decidability,
                        "decidability_evidence": detail,
                        "serialized_input_guard": False,
                        "tool_evidence": tools,
                        "repair_class": repair_class(decidability, tools, existing_before_hook, False),
                    }
                )
    return {
        "path": relative,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "framework_import": imports_openai if framework == "openai-agents" else imports_crewai,
        "existing_before_tool_hook": existing_before_hook,
        "existing_tool_input_guard": existing_tool_guard,
        "sites": sites,
    }


def excluded_path(path: str) -> bool:
    return any(part in EXCLUDED_PARTS for part in Path(path).parts)


def candidate_paths(repo_dir: Path, matched: Iterable[dict[str, Any]], max_siblings: int) -> tuple[list[str], list[str]]:
    included = set()
    excluded = set()
    for item in matched:
        relative = item["path"]
        if excluded_path(relative):
            excluded.add(relative)
            continue
        path = repo_dir / relative
        if path.suffix == ".py" and path.is_file() and not path.is_symlink():
            included.add(relative)
            siblings = [candidate for candidate in sorted(path.parent.glob("*.py")) if candidate.is_file() and not candidate.is_symlink()]
            for sibling in siblings[:max_siblings]:
                included.add(sibling.relative_to(repo_dir).as_posix())
    return sorted(included), sorted(excluded)


def repository_role(repository: str, modules: list[dict[str, Any]], excluded_matches: list[str]) -> str:
    paths = [module["path"] for module in modules if module["sites"]]
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


def analyze(config: dict[str, Any]) -> dict[str, Any]:
    frame = json.loads(Path(config["frame"]).read_text(encoding="utf-8"))
    materialization = json.loads(Path(config["materialization"]).read_text(encoding="utf-8"))
    materialized = {row["repository"]: row for row in materialization["repositories"] if row["status"] == "completed"}
    rows = []
    for selected in frame["selected"]:
        repository = selected["repository"]["full_name"]
        materialized_row = materialized[repository]
        repo_dir = Path(materialized_row["destination"])
        paths, excluded_matches = candidate_paths(repo_dir, selected["matched_files"], int(config["max_sibling_files_per_directory"]))
        modules = []
        parse_errors = []
        for relative in paths:
            path = repo_dir / relative
            if path.stat().st_size > int(config["max_python_file_bytes"]):
                parse_errors.append({"path": relative, "error": "file_size_limit"})
                continue
            try:
                modules.append(analyze_module(path, relative, selected["framework"]))
            except (SyntaxError, UnicodeError, OSError) as exc:
                parse_errors.append({"path": relative, "error": type(exc).__name__})
        sites = [{"path": module["path"], **site} for module in modules for site in module["sites"]]
        rows.append(
            {
                "framework": selected["framework"],
                "repository": repository,
                "commit": selected["pinned_commit"],
                "matched_files": len(selected["matched_files"]),
                "excluded_matched_files": excluded_matches,
                "scanned_files": len(modules),
                "parse_errors": parse_errors,
                "role": repository_role(repository, modules, excluded_matches),
                "sites": sites,
            }
        )
    roles = Counter(row["role"] for row in rows)
    sites = [site for row in rows for site in row["sites"]]
    repair_classes = Counter(site["repair_class"] for site in sites)
    decidability = Counter(site["decidability"] for site in sites)
    return {
        "schema_version": 1,
        "task_version": config["task_version"],
        "split": config["split"],
        "analysis_scope": "GitHub-matched Python files plus bounded same-directory siblings; vendor/environment paths excluded",
        "counts": {
            "planned_repositories": len(frame["selected"]),
            "completed_repositories": len(rows),
            "repositories_with_sites": sum(bool(row["sites"]) for row in rows),
            "guard_sites": len(sites),
            "parse_errors": sum(len(row["parse_errors"]) for row in rows),
            "roles": dict(sorted(roles.items())),
            "repair_classes": dict(sorted(repair_classes.items())),
            "decidability": dict(sorted(decidability.items())),
        },
        "repositories": rows,
        "execution_health": "completed",
        "scientific_outcome": "success",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Statically classify guard/effect placement in frozen repositories")
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
