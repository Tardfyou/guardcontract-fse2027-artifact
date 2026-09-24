from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from guardcontract.paths import project_root

import argparse
import ast
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_DIR = project_root()
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from guardcontract.discovery.dependencies import analyze_guard_repositories_i3 as core
from guardcontract.discovery.dependencies import analyze_guard_repositories_i6 as base


MCP_CAPABILITIES = {
    "@modelcontextprotocol/server-filesystem": "filesystem",
    "@modelcontextprotocol/server-fetch": "outbound-http",
    "@modelcontextprotocol/server-postgres": "database-or-process",
    "@modelcontextprotocol/server-sqlite": "database-or-process",
    "@modelcontextprotocol/server-github": "outbound-http",
    "@modelcontextprotocol/server-slack": "outbound-http",
    "@playwright/mcp": "browser-or-network",
}


def constant_strings(node: ast.AST) -> list[str]:
    return [
        item.value
        for item in ast.walk(node)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    ]


def indexed_aliases(module: core.ModuleRecord) -> dict[str, tuple[str, int]]:
    aliases: dict[str, tuple[str, int]] = {}
    for node in ast.walk(module.tree):
        if not isinstance(node, (ast.With, ast.AsyncWith)):
            continue
        for item in node.items:
            expr = item.context_expr
            if not isinstance(expr, ast.Subscript) or not isinstance(expr.value, ast.Name):
                continue
            index = expr.slice
            if not isinstance(index, ast.Constant) or not isinstance(index.value, int):
                continue
            if isinstance(item.optional_vars, ast.Name):
                aliases[item.optional_vars.id] = (expr.value.id, index.value)
    return aliases


def expand_server_nodes(
    node: ast.AST | None,
    module: core.ModuleRecord,
    aliases: dict[str, tuple[str, int]],
    seen: frozenset[str] = frozenset(),
) -> list[ast.AST]:
    if node is None:
        return []
    if isinstance(node, (ast.List, ast.Tuple)):
        return [child for element in node.elts for child in expand_server_nodes(element, module, aliases, seen)]
    if isinstance(node, ast.Name):
        if node.id in seen:
            return []
        if node.id in aliases:
            owner, index = aliases[node.id]
            assigned = module.assignments.get(owner)
            if isinstance(assigned, (ast.List, ast.Tuple)) and 0 <= index < len(assigned.elts):
                return expand_server_nodes(assigned.elts[index], module, aliases, seen | {node.id})
        assigned = module.assignments.get(node.id)
        if assigned is not None:
            return expand_server_nodes(assigned, module, aliases, seen | {node.id})
    if isinstance(node, ast.Call):
        return [node]
    return []


def mcp_evidence(call: ast.Call, module: core.ModuleRecord) -> dict[str, Any]:
    server_nodes = expand_server_nodes(
        core.call_keyword(call, "mcp_servers"), module, indexed_aliases(module)
    )
    effects = []
    unresolved = []
    for server in server_nodes:
        strings = constant_strings(server)
        matched = [(token, family) for token, family in MCP_CAPABILITIES.items() if token in strings]
        if not matched:
            unresolved.append({"name": strings[0] if strings else "<dynamic-mcp>", "resolution": "mcp-capability-unmodeled"})
            continue
        for token, family in matched:
            effects.append(
                {
                    "path": module.path,
                    "line": server.lineno,
                    "call": f"mcp-capability:{token}",
                    "family": family,
                    "model": "exact-mcp-package-capability",
                    "confidence": "high",
                    "via": f"Agent.mcp_servers:{call.lineno}",
                    "effect_semantics": "MCP tool activity can create a non-retractable observation or state change before an output verdict",
                }
            )
    return {
        "bound_tools": [item["call"] for item in effects],
        "resolved_tools": [],
        "unresolved_tools": unresolved,
        "explicit_effects": effects,
        "effect_status": "explicit_effect" if effects else ("unknown" if unresolved else "no_effect_observed"),
    }


def agent_call_at_site(module: core.ModuleRecord, line: int) -> ast.Call | None:
    matches = [
        node
        for node in ast.walk(module.tree)
        if isinstance(node, ast.Call)
        and node.lineno == line
        and (module.normalize_name(core.dotted_name(node.func)) or "") == "agents.Agent"
    ]
    return matches[0] if len(matches) == 1 else None


def post_construction_guard_sites(module: core.ModuleRecord) -> list[dict[str, Any]]:
    sites = []
    agent_assignments: dict[str, list[ast.Call]] = {}
    for node in ast.walk(module.tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        if (module.normalize_name(core.dotted_name(value.func)) or "") != "agents.Agent":
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                agent_assignments.setdefault(target.id, []).append(value)

    lifecycle_by_attribute = {
        "input_guardrails": "openai-input",
        "output_guardrails": "openai-output",
    }
    for node in ast.walk(module.tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if not isinstance(target, ast.Attribute) or target.attr not in lifecycle_by_attribute:
                continue
            if not isinstance(target.value, ast.Name):
                continue
            candidates = [
                call for call in agent_assignments.get(target.value.id, []) if call.lineno < node.lineno
            ]
            if not candidates:
                continue
            constructor = max(candidates, key=lambda call: call.lineno)
            lifecycle = lifecycle_by_attribute[target.attr]
            tool_names = module.resolve_values(core.call_keyword(constructor, "tools"))
            repository = core.RepositoryIndex([module])
            tools = repository.tool_evidence(tool_names, module)
            for guard in module.resolve_values(node.value):
                decidability, detail = repository.guard_decidability(guard, lifecycle, module)
                sites.append(
                    {
                        "path": module.path,
                        "line": node.lineno,
                        "construct": "Agent.attribute-assignment",
                        "lifecycle": lifecycle,
                        "guard": guard,
                        "decidability": decidability,
                        "decidability_evidence": detail,
                        "tool_evidence": tools,
                        "repair_class": core.repair_class(lifecycle, decidability, tools, False),
                        "binding_evidence": {
                            "receiver": target.value.id,
                            "constructor_line": constructor.lineno,
                            "assignment_line": node.lineno,
                            "resolution": "nearest-preceding-same-file-agent-assignment",
                        },
                    }
                )
    return sites


def guard_assignment_modules(repo_dir: Path) -> list[core.ModuleRecord]:
    modules = []
    skipped = {".git", ".venv", "venv", "env", "node_modules", "site-packages", "__pycache__"}
    for path in sorted(repo_dir.rglob("*.py")):
        relative = path.relative_to(repo_dir)
        if skipped.intersection(relative.parts) or path.stat().st_size > 1_048_576:
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b".input_guardrails" not in raw and b".output_guardrails" not in raw:
            continue
        try:
            modules.append(core.ModuleRecord.parse(path, relative.as_posix()))
        except (SyntaxError, UnicodeError, OSError):
            continue
    return modules


def analyze(config: dict[str, Any]) -> dict[str, Any]:
    baseline_result = config.get("baseline_result")
    result = (
        json.loads(Path(baseline_result).read_text(encoding="utf-8"))
        if baseline_result
        else base.analyze(config)
    )
    frame = json.loads(Path(config["frame"]).read_text(encoding="utf-8"))
    del frame
    materialization = json.loads(Path(config["materialization"]).read_text(encoding="utf-8"))
    roots = {
        row["repository"]: Path(row["destination"])
        for row in materialization["repositories"]
        if row["status"] == "completed"
    }
    for row in result["repositories"]:
        if row["framework"] != "openai-agents":
            continue
        repo_dir = roots[row["repository"]]
        existing = {
            (site["path"], site["line"], site["lifecycle"], site["guard"])
            for site in row["sites"]
        }
        for module in guard_assignment_modules(repo_dir):
            for recovered_site in post_construction_guard_sites(module):
                identity = (
                    recovered_site["path"], recovered_site["line"],
                    recovered_site["lifecycle"], recovered_site["guard"],
                )
                if identity not in existing:
                    row["sites"].append(recovered_site)
                    existing.add(identity)
        if row["sites"] and row["role"] == "no_confirmed_framework_site":
            row["role"] = core.repository_role(row["repository"], row["sites"], row["excluded_matched_files"])
        by_path = {}
        for relative in sorted({site["path"] for site in row["sites"]}):
            path = repo_dir / relative
            if path.is_file() and path.stat().st_size <= int(config["max_python_file_bytes"]):
                try:
                    by_path[relative] = core.ModuleRecord.parse(path, relative)
                except (SyntaxError, UnicodeError, OSError):
                    continue
        for site in row["sites"]:
            module = by_path.get(site["path"])
            call = agent_call_at_site(module, int(site["line"])) if module else None
            if call is None:
                continue
            recovered = mcp_evidence(call, module)
            site["tool_evidence"] = base.merge_evidence(site["tool_evidence"], recovered)
            site["repair_class"] = core.repair_class(
                site["lifecycle"], site["decidability"], site["tool_evidence"], False
            )
    base.recompute_counts(result)
    all_sites = [site for row in result["repositories"] for site in row["sites"]]
    for site in all_sites:
        if "deny_capability" in site:
            continue
        detail = site.get("decidability_evidence", {})
        site["deny_capability"] = detail.get("deny_capability", "unknown")
        site["deny_capability_evidence"] = detail.get("deny_capability_evidence", [])
    result["counts"].update(
        {
            "guard_sites": len(all_sites),
            "repositories_with_sites": len({row["repository"] for row in result["repositories"] if row["sites"]}),
            "decidability": dict(sorted(Counter(site["decidability"] for site in all_sites).items())),
            "lifecycles": dict(sorted(Counter(site["lifecycle"] for site in all_sites).items())),
            "roles": dict(sorted(Counter(row["role"] for row in result["repositories"]).items())),
        }
    )
    result["task_version"] = config["task_version"]
    result["split"] = config["split"]
    result["analysis_scope"] += "; exact MCP capability recovery and post-construction guard assignment recovery"
    result["effect_model_boundary"] += "; unknown custom MCP servers remain unresolved"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Guard/effect analyzer with exact MCP capability recovery")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    result = analyze(json.loads(args.config.read_text(encoding="utf-8")))
    args.result.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
