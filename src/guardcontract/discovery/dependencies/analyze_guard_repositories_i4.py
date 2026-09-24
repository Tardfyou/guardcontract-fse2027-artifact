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
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_DIR = project_root()
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from guardcontract.discovery.dependencies import analyze_guard_repositories_i3 as base


CALL_REFERENCE = re.compile(r"^<call:(?P<name>.+):(?P<path>.+):(?P<line>[0-9]+)>$")
BASE_ANALYZE_MODULE = base.analyze_module

# These constructors have framework-defined external execution semantics. The
# effect is the already-issued request, disclosure, or paid operation, not a
# claim that the remote resource was mutated.
PROTECTED_TOOL_CONSTRUCTORS = {
    "agents.FileSearchTool": ("outbound-retrieval", "high"),
    "agents.WebSearchTool": ("outbound-search", "high"),
    "crewai_tools.BrowserbaseLoadTool": ("outbound-browser", "high"),
    "crewai_tools.EXASearchTool": ("outbound-search", "high"),
    "crewai_tools.FirecrawlScrapeWebsiteTool": ("outbound-browser", "high"),
    "crewai_tools.FirecrawlSearchTool": ("outbound-search", "high"),
    "crewai_tools.FileWriterTool": ("filesystem", "high"),
    "crewai_tools.ScrapeElementFromWebsiteTool": ("outbound-browser", "high"),
    "crewai_tools.ScrapeWebsiteTool": ("outbound-browser", "high"),
    "crewai_tools.SeleniumScrapingTool": ("outbound-browser", "high"),
    "crewai_tools.SerperDevTool": ("outbound-search", "high"),
    "crewai_tools.WebsiteSearchTool": ("outbound-search", "high"),
}


def framework_tool_effect(reference: str) -> dict[str, Any] | None:
    match = CALL_REFERENCE.fullmatch(reference)
    if not match:
        return None
    constructor = match.group("name")
    modeled = PROTECTED_TOOL_CONSTRUCTORS.get(constructor)
    if modeled is None:
        return None
    family, confidence = modeled
    return {
        "path": match.group("path"),
        "line": int(match.group("line")),
        "call": constructor,
        "family": family,
        "model": "framework-tool-constructor",
        "confidence": confidence,
        "via": reference,
        "effect_semantics": "non-retractable external observation, disclosure, cost, or state change",
    }


def extend_tool_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    updated = dict(evidence)
    effects = {
        (item["path"], item["line"], item["call"]): item
        for item in evidence.get("explicit_effects", [])
    }
    recognized = []
    for reference in evidence.get("bound_tools", []):
        effect = framework_tool_effect(reference)
        if effect is None:
            continue
        effects[(effect["path"], effect["line"], effect["call"])] = effect
        recognized.append(reference)
    updated["explicit_effects"] = sorted(
        effects.values(), key=lambda item: (item["path"], item["line"], item["call"])
    )
    updated["framework_tool_effects"] = recognized
    if any(item["confidence"] == "high" for item in updated["explicit_effects"]):
        updated["effect_status"] = "explicit_effect"
    elif updated["explicit_effects"]:
        updated["effect_status"] = "possible_effect"
    return updated


def local_factory(
    reference: str,
    module: base.ModuleRecord,
    repository: base.RepositoryIndex,
) -> base.FunctionRef | None:
    function, _ = repository.resolve_function(reference, module)
    if function is not None:
        return function
    simple = reference.rsplit(".", 1)[-1]
    matches = [item for item in module.functions if item.simple_name == simple]
    return matches[0] if len(matches) == 1 else None


def agent_tool_references(
    node: ast.AST | None,
    module: base.ModuleRecord,
    repository: base.RepositoryIndex,
    seen: frozenset[str] = frozenset(),
) -> tuple[list[str], list[dict[str, Any]]]:
    if node is None:
        return [], []
    if isinstance(node, ast.Name) and node.id in module.assignments and node.id not in seen:
        tools, trace = agent_tool_references(
            module.assignments[node.id], module, repository, seen | {node.id}
        )
        return tools, [{"kind": "assignment", "symbol": node.id}, *trace]
    if isinstance(node, ast.Call):
        raw_name = base.dotted_name(node.func) or ""
        normalized = module.normalize_name(raw_name) or raw_name
        if normalized == "crewai.Agent":
            tools = module.resolve_values(base.call_keyword(node, "tools"))
            return tools, [{"kind": "agent-constructor", "path": module.path, "line": node.lineno}]
        factory = local_factory(raw_name, module, repository)
        if factory is not None:
            factory_module = next(item for item in repository.modules if item.path == factory.path)
            tools = []
            trace = [{"kind": "agent-factory", "path": factory.path, "line": factory.node.lineno}]
            for nested in (item for item in ast.walk(factory.node) if isinstance(item, ast.Call)):
                nested_name = factory_module.normalize_name(base.dotted_name(nested.func)) or ""
                if nested_name == "crewai.Agent":
                    tools.extend(factory_module.resolve_values(base.call_keyword(nested, "tools")))
                    trace.append({"kind": "agent-constructor", "path": factory.path, "line": nested.lineno})
            return tools, trace
    return [], [{"kind": "unresolved-agent-binding", "value": base.dotted_name(node) or type(node).__name__}]


def analyze_module(
    module: base.ModuleRecord,
    repository: base.RepositoryIndex,
    framework: str,
) -> dict[str, Any]:
    result = BASE_ANALYZE_MODULE(module, repository, framework)
    if framework == "crewai":
        calls = [item for item in ast.walk(module.tree) if isinstance(item, ast.Call)]
        existing_before_hook = result["existing_before_tool_hook"]
        for call in calls:
            call_name = module.normalize_name(base.dotted_name(call.func)) or ""
            if call_name != "crewai.Task":
                continue
            direct_tools = module.resolve_values(base.call_keyword(call, "tools"))
            inherited_tools, binding = agent_tool_references(
                base.call_keyword(call, "agent"), module, repository
            )
            references = list(dict.fromkeys([*direct_tools, *inherited_tools]))
            tools = extend_tool_evidence(repository.tool_evidence(references, module))
            guard_nodes = []
            singular = base.call_keyword(call, "guardrail")
            plural = base.call_keyword(call, "guardrails")
            if singular is not None:
                guard_nodes.append(singular)
            if plural is not None:
                guard_nodes.append(plural)
            guards = [guard for node in guard_nodes for guard in module.resolve_values(node)]
            existing = {
                (site["line"], site["guard"])
                for site in result["sites"]
                if site["construct"] == "Task"
            }
            for guard in guards:
                decidability, detail = repository.guard_decidability(
                    guard, "crewai-task-output", module
                )
                replacement = {
                    "path": module.path,
                    "line": call.lineno,
                    "construct": "Task",
                    "lifecycle": "crewai-task-output",
                    "guard": guard,
                    "decidability": decidability,
                    "decidability_evidence": detail,
                    "tool_evidence": tools,
                    "tool_binding_evidence": binding,
                    "repair_class": base.repair_class(
                        "crewai-task-output", decidability, tools, existing_before_hook
                    ),
                }
                if (call.lineno, guard) in existing:
                    index = next(
                        index
                        for index, site in enumerate(result["sites"])
                        if site["construct"] == "Task"
                        and site["line"] == call.lineno
                        and site["guard"] == guard
                    )
                    result["sites"][index] = replacement
                else:
                    result["sites"].append(replacement)

    for site in result["sites"]:
        tools = extend_tool_evidence(site["tool_evidence"])
        site["tool_evidence"] = tools
        site["repair_class"] = base.repair_class(
            site["lifecycle"],
            site["decidability"],
            tools,
            result["existing_before_tool_hook"],
        )
    result["sites"] = sorted(
        result["sites"], key=lambda item: (item["line"], item["lifecycle"], item["guard"])
    )
    return result


def analyze(config: dict[str, Any]) -> dict[str, Any]:
    base.analyze_module = analyze_module
    try:
        result = base.analyze(config)
    finally:
        base.analyze_module = BASE_ANALYZE_MODULE
    result["analysis_scope"] = (
        "development-only repository-wide Python semantic index with direct Task-to-Agent tool binding "
        "and exact framework-tool outbound-effect models"
    )
    result["effect_model_boundary"] = (
        "exact calls, explicitly tagged method names, and exact framework tool constructors; "
        "no arbitrary MCP inventory, receiver inference, or implicit CrewBase YAML binding"
    )
    result["counts"]["effect_families"] = dict(
        sorted(
            Counter(
                effect["family"]
                for row in result["repositories"]
                for site in row["sites"]
                for effect in site["tool_evidence"]["explicit_effects"]
                if effect["confidence"] == "high"
            ).items()
        )
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Development analyzer with Task-Agent and outbound effect recovery")
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
