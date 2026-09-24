from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import argparse
import ast
import json
from pathlib import Path
from typing import Any, Iterable


TASK_VERSION = "26-1"
SUPPORTED_EFFECTS = {
    "mkdir": "filesystem_mkdir",
    "write_text": "filesystem_text_write",
    "write_bytes": "filesystem_bytes_write",
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


def python_sources(repo: Path) -> Iterable[Path]:
    excluded = {".git", ".venv", "venv", "site-packages", "dist-packages", "node_modules", "vendor"}
    for path in repo.rglob("*.py"):
        if path.is_file() and not path.is_symlink() and not any(part in excluded for part in path.parts):
            yield path


def parsed_sources(repo: Path) -> dict[str, ast.Module]:
    result = {}
    for path in python_sources(repo):
        relative = path.relative_to(repo).as_posix()
        try:
            result[relative] = ast.parse(path.read_bytes(), filename=relative)
        except (SyntaxError, UnicodeError, OSError):
            continue
    return result


def enclosing_function(tree: ast.Module, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef:
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= line <= (node.end_lineno or node.lineno)
    ]
    if not matches:
        raise ValueError(f"no function encloses line {line}")
    return max(matches, key=lambda node: node.lineno)


def agent_context_name(tree: ast.Module, line: int) -> str:
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and node.lineno == line and (dotted_name(node.func) or "").endswith("Agent")
    ]
    if len(calls) != 1:
        raise ValueError(f"expected one Agent constructor at reported site, found {len(calls)}")
    function = calls[0].func
    if isinstance(function, ast.Subscript):
        name = dotted_name(function.slice)
        if name:
            return name.rsplit(".", 1)[-1]
    raise ValueError("Agent context type is not explicit")


def assignment_calls(tree: ast.Module, function_name: str) -> set[str]:
    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Call) or (dotted_name(value.func) or "").rsplit(".", 1)[-1] != function_name:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names.update(target.id for target in targets if isinstance(target, ast.Name))
    return names


def wrapper_calls(tree: ast.Module, agent_variables: set[str]) -> list[str]:
    wrappers = []
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        for keyword in call.keywords:
            if keyword.arg == "agent" and isinstance(keyword.value, ast.Name) and keyword.value.id in agent_variables:
                name = dotted_name(call.func)
                if name:
                    wrappers.append(name.rsplit(".", 1)[-1])
    return wrappers


def unique_definition(
    trees: dict[str, ast.Module], name: str, kind: type[ast.AST] | tuple[type[ast.AST], ...]
) -> tuple[str, ast.AST]:
    matches = [
        (path, node)
        for path, tree in trees.items()
        for node in ast.walk(tree)
        if isinstance(node, kind) and getattr(node, "name", None) == name
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one definition of {name}, found {len(matches)}")
    return matches[0]


def effect_backend(call_name: str) -> str | None:
    return SUPPORTED_EFFECTS.get(call_name.rsplit(".", 1)[-1])


def exact_effect_call(tree: ast.Module, line: int, call_name: str) -> ast.Call:
    method = call_name.rsplit(".", 1)[-1]
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and node.lineno == line
        and (dotted_name(node.func) or "").rsplit(".", 1)[-1] == method
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one {method} call at line {line}, found {len(matches)}")
    if not isinstance(matches[0].func, ast.Attribute):
        raise ValueError(f"effect {method} at line {line} has no recoverable receiver")
    parent = next(
        (
            node
            for node in ast.walk(tree)
            if any(child is matches[0] for child in ast.iter_child_nodes(node))
        ),
        None,
    )
    if not isinstance(parent, ast.Expr):
        raise ValueError(f"effect {method} at line {line} has an observed return value")
    return matches[0]


def context_expression(function: ast.FunctionDef | ast.AsyncFunctionDef, context_class: str) -> str:
    parameters = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
    matches = []
    for parameter in parameters:
        annotation = ast.unparse(parameter.annotation) if parameter.annotation is not None else ""
        wrapper = (dotted_name(parameter.annotation) or "").rsplit(".", 1)[-1]
        if context_class in annotation and wrapper in {"ToolContext", "RunContextWrapper"}:
            matches.append(parameter.arg)
    if len(matches) != 1:
        raise ValueError(
            f"expected one ToolContext/RunContextWrapper parameter for {context_class}, found {matches}"
        )
    return f"{matches[0]}.context"


def is_dataclass(node: ast.ClassDef) -> bool:
    return any(
        (dotted_name(item.func if isinstance(item, ast.Call) else item) or "").rsplit(".", 1)[-1]
        == "dataclass"
        for item in node.decorator_list
    )


def runner_context_attribute(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    positional = [*node.args.posonlyargs, *node.args.args]
    if not positional:
        raise ValueError("runner wrapper has no owner parameter")
    owner = positional[0].arg
    calls = [
        call
        for call in ast.walk(node)
        if isinstance(call, ast.Call) and (dotted_name(call.func) or "").endswith("Runner.run")
    ]
    if not calls:
        raise ValueError("selected wrapper does not call framework Runner.run")
    values = []
    for call in calls:
        value = next((keyword.value for keyword in call.keywords if keyword.arg == "context"), None)
        if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name) and value.value.id == owner:
            values.append(value.attr)
    if len(set(values)) != 1:
        raise ValueError("Runner.run context is not a unique direct owner attribute")
    return values[0]


def site_record(site: dict[str, Any], site_index: int) -> dict[str, Any]:
    return {
        "index": site_index,
        "path": site.get("path"),
        "line": site.get("line"),
        "construct": site.get("construct"),
        "lifecycle": site.get("lifecycle"),
        "guard": site.get("guard"),
        "analyzer_repair_class": site.get("repair_class"),
    }


def unsupported(site: dict[str, Any], site_index: int, code: str, message: str) -> dict[str, Any]:
    return {
        "obligation_id": f"site-{site_index}:{site.get('path')}:{site.get('line')}:{site.get('guard')}",
        "status": "unsupported",
        "repair_kind": None,
        "site": site_record(site, site_index),
        "unsupported_reason": {"code": code, "message": message},
    }


def not_required(site: dict[str, Any], site_index: int, code: str, message: str) -> dict[str, Any]:
    return {
        "obligation_id": f"site-{site_index}:{site.get('path')}:{site.get('line')}:{site.get('guard')}",
        "status": "not_required",
        "repair_kind": None,
        "site": site_record(site, site_index),
        "reason": {"code": code, "message": message},
    }


def plan_deferral_site(
    repo: Path,
    repository: str,
    site: dict[str, Any],
    site_index: int,
    trees: dict[str, ast.Module],
) -> dict[str, Any]:
    if site.get("construct") != "Agent":
        return unsupported(
            site,
            site_index,
            "framework_adapter_missing",
            f"effect deferral is not implemented for construct {site.get('construct')!r}",
        )
    effects = list(site.get("tool_evidence", {}).get("explicit_effects", []))
    if not effects:
        return unsupported(site, site_index, "no_explicit_effect", "no explicit effect was reported")
    non_high = [effect for effect in effects if effect.get("confidence") != "high"]
    if non_high:
        return unsupported(
            site,
            site_index,
            "effect_confidence_insufficient",
            "all effects on a patched path must be high confidence",
        )
    unsupported_calls = sorted({effect.get("call", "") for effect in effects if effect_backend(effect.get("call", "")) is None})
    if unsupported_calls:
        return unsupported(
            site,
            site_index,
            "effect_backend_missing",
            f"no semantics-preserving deferral backend for {unsupported_calls}",
        )
    try:
        site_path = str(site["path"])
        agent_factory = enclosing_function(trees[site_path], int(site["line"]))
        context_class = agent_context_name(trees[site_path], int(site["line"]))
        context_path, context_node = unique_definition(trees, context_class, ast.ClassDef)
        assert isinstance(context_node, ast.ClassDef)
        if not is_dataclass(context_node):
            raise ValueError(f"context class {context_class} is not a dataclass")
        if any(
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and any(
                isinstance(target, ast.Name) and target.id == "deferred_effects"
                for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            )
            for node in context_node.body
        ):
            raise ValueError(f"context class {context_class} already defines deferred_effects")
        if not (repo / Path(context_path).parent / "__init__.py").exists():
            raise ValueError("context module is not inside an importable package")

        planned_effects = []
        for effect in sorted(effects, key=lambda item: (item["path"], int(item["line"]), item["call"])):
            effect_path = str(effect["path"])
            effect_line = int(effect["line"])
            exact_effect_call(trees[effect_path], effect_line, str(effect["call"]))
            function = enclosing_function(trees[effect_path], effect_line)
            planned_effects.append(
                {
                    "path": effect_path,
                    "line": effect_line,
                    "call": effect["call"],
                    "family": effect.get("family"),
                    "function": function.name,
                    "backend": effect_backend(str(effect["call"])),
                    "ledger_expression": f"{context_expression(function, context_class)}.deferred_effects",
                }
            )

        agent_variables = set()
        for tree in trees.values():
            agent_variables.update(assignment_calls(tree, agent_factory.name))
        wrappers = [wrapper for tree in trees.values() for wrapper in wrapper_calls(tree, agent_variables)]
        if len(set(wrappers)) != 1:
            raise ValueError(f"expected one runner wrapper, found {sorted(set(wrappers))}")
        runner_path, runner_node = unique_definition(
            trees, wrappers[0], (ast.FunctionDef, ast.AsyncFunctionDef)
        )
        assert isinstance(runner_node, (ast.FunctionDef, ast.AsyncFunctionDef))
        if not isinstance(runner_node, ast.AsyncFunctionDef):
            raise ValueError("runner wrapper is not async")
        if any(
            (dotted_name(item.func if isinstance(item, ast.Call) else item) or "").rsplit(".", 1)[-1]
            == "deferred_effect_scope"
            for item in runner_node.decorator_list
        ):
            raise ValueError("runner wrapper already has deferred_effect_scope")
        owner_context_attribute = runner_context_attribute(runner_node)
        if owner_context_attribute != "context":
            raise ValueError(
                f"runner owner context attribute {owner_context_attribute!r} is unsupported by the scope backend"
            )
        if Path(runner_path).parent != Path(context_path).parent:
            raise ValueError("runner and context modules are not in the same import package")
    except (KeyError, TypeError, ValueError) as exc:
        return unsupported(site, site_index, "topology_not_proven", str(exc))

    result = {
        "obligation_id": f"site-{site_index}:{site['path']}:{site['line']}:{site['guard']}",
        "status": "supported",
        "repair_kind": "ordered_filesystem_deferral",
        "site": site_record(site, site_index),
        "agent_factory": {"path": site_path, "function": agent_factory.name},
        "effects": planned_effects,
        "runner": {
            "path": runner_path,
            "function": runner_node.name,
            "owner_context_attribute": owner_context_attribute,
        },
        "context": {"path": context_path, "class": context_node.name},
        "capability_contract": {
            "supported_effect_backends": sorted({effect["backend"] for effect in planned_effects}),
            "ordered_commit": True,
            "async_scope_isolation": True,
            "cross_backend_atomicity": False,
            "process_crash_recovery": False,
            "resource_boundary_required_for_release": True,
            "pending_memory_budget_required_for_release": True,
        },
    }
    if len(planned_effects) == 1:
        result["effect"] = planned_effects[0]
    return result


def plan_repository(repo: Path, analysis: dict[str, Any], repository: str) -> dict[str, Any]:
    rows = [item for item in analysis.get("repositories", []) if item.get("repository") == repository]
    if len(rows) != 1:
        raise ValueError(f"expected one analyzer row for {repository}, found {len(rows)}")
    trees = parsed_sources(repo)
    obligations = []
    for site_index, site in enumerate(rows[0].get("sites", [])):
        repair_class = site.get("repair_class")
        if repair_class == "requires_effect_deferral":
            obligations.append(plan_deferral_site(repo, repository, site, site_index, trees))
        elif repair_class in {"placement_only_candidate", "placement_repairable"}:
            obligations.append(
                unsupported(
                    site,
                    site_index,
                    "placement_codegen_missing",
                    "the placement classifier is available but this source-patch backend is not yet implemented",
                )
            )
        elif repair_class in {"existing_pre_effect_control_observed", "existing_pre_effect_control"}:
            obligations.append(
                not_required(site, site_index, "already_controlled", "an equivalent pre-effect control was observed")
            )
        else:
            obligations.append(
                unsupported(
                    site,
                    site_index,
                    "analyzer_class_not_repairable",
                    f"analyzer class {repair_class!r} does not establish a repair obligation",
                )
            )
    sites = rows[0].get("sites", [])
    for index, obligation in enumerate(obligations):
        if (
            obligation["status"] != "unsupported"
            or obligation.get("unsupported_reason", {}).get("code") != "framework_adapter_missing"
            or obligation["site"]["construct"] != "function_tool"
            or obligation["site"]["analyzer_repair_class"] != "requires_effect_deferral"
        ):
            continue
        site = sites[index]
        try:
            function = enclosing_function(trees[str(site["path"])], int(site["line"]))
        except (KeyError, TypeError, ValueError):
            continue
        site_effects = {
            (item.get("path"), int(item.get("line", 0)), item.get("call"))
            for item in site.get("tool_evidence", {}).get("explicit_effects", [])
        }
        covering = []
        for candidate in obligations:
            if candidate["status"] != "supported" or candidate["site"]["construct"] != "Agent":
                continue
            candidate_site = sites[candidate["site"]["index"]]
            bound_tools = {
                name.rsplit(".", 1)[-1]
                for name in candidate_site.get("tool_evidence", {}).get("bound_tools", [])
            }
            candidate_effects = {
                (item["path"], int(item["line"]), item["call"]) for item in candidate["effects"]
            }
            if function.name in bound_tools and site_effects and site_effects <= candidate_effects:
                covering.append(candidate)
        if len(covering) == 1:
            obligations[index] = {
                "obligation_id": obligation["obligation_id"],
                "status": "covered",
                "repair_kind": "shared_ordered_filesystem_deferral",
                "site": obligation["site"],
                "covered_by": covering[0]["obligation_id"],
                "coverage_reason": {
                    "code": "same_bound_tool_and_effect_set",
                    "message": "the enclosing Runner scope commits only after both tool-output and agent-output guards return",
                },
            }
    counts = {
        "sites": len(obligations),
        "supported": sum(item["status"] == "supported" for item in obligations),
        "covered": sum(item["status"] == "covered" for item in obligations),
        "unsupported": sum(item["status"] == "unsupported" for item in obligations),
        "not_required": sum(item["status"] == "not_required" for item in obligations),
    }
    return {
        "schema_version": 2,
        "task_version": TASK_VERSION,
        "repository": repository,
        "counts": counts,
        "obligations": obligations,
    }


def plan(repo: Path, analysis: dict[str, Any], repository: str) -> dict[str, Any]:
    """Compatibility entry point returning the first supported deferral plan."""
    result = plan_repository(repo, analysis, repository)
    candidates = [
        item
        for item in result["obligations"]
        if item["site"]["analyzer_repair_class"] == "requires_effect_deferral"
    ]
    if not candidates:
        raise ValueError("repository has no requires_effect_deferral site")
    preferred = next((item for item in candidates if item["site"]["construct"] == "Agent"), candidates[0])
    if preferred["status"] != "supported":
        reason = preferred["unsupported_reason"]
        raise ValueError(f"{reason['code']}: {reason['message']}")
    return {
        "schema_version": 2,
        "task_version": TASK_VERSION,
        "repository": repository,
        **preferred,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Recover bounded repair obligations from analyzer output")
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--analysis", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--all-sites", action="store_true", help="emit supported, unsupported, and not-required sites")
    args = parser.parse_args()
    analysis = json.loads(args.analysis.read_text(encoding="utf-8"))
    result = plan_repository(args.repo, analysis, args.repository) if args.all_sites else plan(args.repo, analysis, args.repository)
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
