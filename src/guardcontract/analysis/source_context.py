"""Select authenticated local import components without removing corpus units.

This is context construction, not a claim that Python dynamic dependencies are
closed. Omitted paths, parse failures and dynamic loading remain explicit.
"""
import ast
from collections import defaultdict
from pathlib import PurePosixPath


SDK_ROOTS = {"langchain": {"langchain", "langgraph"}, "crewai": {"crewai", "crewai_tools"},
             "google-adk": {"google.adk"}, "openai-agents": {"agents"}, "pydantic-ai": {"pydantic_ai"}}
ENVIRONMENTS = {"site-packages", ".venv", "venv", "node_modules", "__pycache__"}
NONPRODUCTION = {"tests", "test", "examples", "example", "demo", "demos", "docs", "doc"}


def _module_names(path):
    parts = list(PurePosixPath(path).with_suffix("").parts)
    if parts[-1] == "__init__": parts.pop()
    return {".".join(parts[i:]) for i in range(len(parts))}


def select(sources, *, framework, required_paths, discover_repository=True):
    required = set(required_paths)
    modules = defaultdict(set)
    eligible = {p for p in sources if p in required or not set(PurePosixPath(p).parts) & ENVIRONMENTS}
    for path in eligible:
        for name in _module_names(path): modules[name].add(path)
    edges = {p: set() for p in eligible}
    seeds = required & eligible
    parse_failures, dynamic, sdk_seeds, imports = [], [], [], {}
    for path in sorted(eligible):
        try: tree = ast.parse(sources[path])
        except (SyntaxError, ValueError):
            parse_failures.append(path); continue
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    prefix = list(PurePosixPath(path).parent.parts)
                    prefix = prefix[:max(0, len(prefix) - node.level + 1)]
                    base = ".".join(prefix + ([base] if base else []))
                names.add(base)
                names.update(base + "." + a.name for a in node.names)
            elif isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
                if name in {"__import__", "import_module", "exec", "eval", "run_path", "run_module"}:
                    dynamic.append(path)
        imports[path] = sorted(names)
        production = not set(PurePosixPath(path).parts) & NONPRODUCTION and not PurePosixPath(path).name.startswith("test_")
        if production and any(name == sdk or name.startswith(sdk + ".") for name in names for sdk in SDK_ROOTS[framework]):
            sdk_seeds.append(path)
            if discover_repository: seeds.add(path)
        for name in names:
            for target in modules.get(name, ()):
                edges[path].add(target)
                # Tests are not production callers; explicitly selected tests
                # still follow their own imports, preserving original anchors.
                if production or path in required: edges[target].add(path)
    selected, pending = set(seeds), list(seeds)
    while pending:
        path = pending.pop()
        for target in edges[path] - selected:
            selected.add(target); pending.append(target)
    linked = {p: set(edges[p] & selected) for p in selected}
    for path in selected:
        for target in edges[path] & selected: linked[target].add(path)
    components, remaining = [], set(selected)
    while remaining:
        first = min(remaining); component, pending = {first}, [first]; remaining.remove(first)
        while pending:
            path = pending.pop()
            for target in linked[path] & remaining:
                remaining.remove(target); component.add(target); pending.append(target)
        components.append(sorted(component))
    return {"selected_python": sorted(selected), "omitted_python": sorted(set(sources) - selected),
            "components": components, "repository_discovery_requested": discover_repository,
            "required_paths": sorted(required), "sdk_seed_paths": sorted(sdk_seeds),
            "missing_required_paths": sorted(required - set(sources)),
            "parse_failures": parse_failures, "dynamic_loading_paths": sorted(set(dynamic)),
            "selected_dynamic_loading_paths": sorted(set(dynamic) & selected),
            "local_import_edges": sum(len(targets) for targets in edges.values()),
            "application_dependency_closure_proven": False,
            "claim_boundary": "Static context selector only. Unread or dynamic code does not become negative evidence."}
