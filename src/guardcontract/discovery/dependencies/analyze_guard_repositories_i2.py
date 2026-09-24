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

PROJECT_DIR = project_root()
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from guardcontract.discovery.dependencies.analyze_guard_repositories import EXCLUDED_PARTS, analyze_module, function_effects, repair_class, repository_role


EXCLUDED_LOWER = {part.lower() for part in EXCLUDED_PARTS} | {"__pycache__", ".mypy_cache", ".pytest_cache"}


def excluded_source(path: Path) -> bool:
    lowered = [part.lower() for part in path.parts]
    return any(
        part in EXCLUDED_LOWER
        or part.endswith("site-packages")
        or part.endswith("dist-packages")
        or part.endswith("-env")
        for part in lowered
    )


def repository_sources(repo_dir: Path, matched_files: list[dict[str, Any]], cap: int) -> tuple[list[str], bool, list[str]]:
    matched = {
        item["path"]
        for item in matched_files
        if item["path"].endswith(".py") and not excluded_source(Path(item["path"]))
    }
    excluded_matches = sorted(
        {item["path"] for item in matched_files if excluded_source(Path(item["path"]))}
    )
    all_sources = []
    for path in repo_dir.rglob("*.py"):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(repo_dir)
        if excluded_source(relative):
            continue
        all_sources.append(relative.as_posix())
    ordered = sorted(set(all_sources), key=lambda path: (path not in matched, path))
    truncated = len(ordered) > cap
    selected = ordered[:cap]
    for path in sorted(matched):
        if path not in selected and (repo_dir / path).is_file():
            selected.append(path)
    return sorted(set(selected)), truncated, excluded_matches


def global_function_effects(repo_dir: Path, paths: list[str], max_bytes: int) -> dict[str, list[str]]:
    definitions: dict[str, list[list[str]]] = defaultdict(list)
    for relative in paths:
        path = repo_dir / relative
        if path.stat().st_size > max_bytes:
            continue
        try:
            tree = ast.parse(path.read_bytes(), filename=relative)
        except (SyntaxError, UnicodeError, OSError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                definitions[node.name].append(function_effects(node))
    result = {}
    for name, alternatives in definitions.items():
        nonempty = sorted({effect for effects in alternatives for effect in effects})
        if nonempty:
            result[name] = nonempty
    return result


def resolve_cross_file_tools(site: dict[str, Any], effects_by_name: dict[str, list[str]]) -> None:
    evidence = site["tool_evidence"]
    resolved = list(evidence["resolved_tools"])
    unresolved = []
    effects = set(evidence["explicit_effects"])
    for reference in evidence["unresolved_tools"]:
        name = reference.rsplit(".", 1)[-1]
        found = effects_by_name.get(name)
        if found:
            resolved.append({"name": reference, "effects": found, "resolution": "repository-name-match"})
            effects.update(found)
        else:
            unresolved.append(reference)
    evidence["resolved_tools"] = resolved
    evidence["unresolved_tools"] = unresolved
    evidence["explicit_effects"] = sorted(effects)
    evidence["effect_status"] = "explicit_effect" if effects else ("unknown" if evidence["bound_tools"] else "no_tools")
    same_module_pre = site.pop("_same_module_pre", False)
    site["repair_class"] = repair_class(
        site["decidability"], evidence, same_module_pre, site["serialized_input_guard"]
    )


def analyze(config: dict[str, Any]) -> dict[str, Any]:
    frame = json.loads(Path(config["frame"]).read_text(encoding="utf-8"))
    materialization = json.loads(Path(config["materialization"]).read_text(encoding="utf-8"))
    materialized = {row["repository"]: row for row in materialization["repositories"] if row["status"] == "completed"}
    frame_repositories = frame[config.get("repository_list_field", "selected")]
    rows = []
    for selected in frame_repositories:
        repository = selected["repository"]["full_name"]
        materialized_row = materialized[repository]
        repo_dir = Path(materialized_row["destination"])
        paths, truncated, excluded_matches = repository_sources(
            repo_dir, selected["matched_files"], int(config["max_repository_python_files"])
        )
        modules = []
        parse_errors = []
        for relative in paths:
            path = repo_dir / relative
            if path.stat().st_size > int(config["max_python_file_bytes"]):
                parse_errors.append({"path": relative, "error": "file_size_limit"})
                continue
            try:
                module = analyze_module(path, relative, selected["framework"])
                for site in module["sites"]:
                    site["_same_module_pre"] = (
                        module["existing_before_tool_hook"] if selected["framework"] == "crewai" else module["existing_tool_input_guard"]
                    )
                modules.append(module)
            except (SyntaxError, UnicodeError, OSError) as exc:
                parse_errors.append({"path": relative, "error": type(exc).__name__})
        effects_by_name = global_function_effects(repo_dir, paths, int(config["max_python_file_bytes"]))
        sites = []
        for module in modules:
            for site in module["sites"]:
                resolve_cross_file_tools(site, effects_by_name)
                sites.append({"path": module["path"], **site})
        rows.append(
            {
                "framework": selected["framework"],
                "repository": repository,
                "commit": selected["pinned_commit"],
                "matched_files": len(selected["matched_files"]),
                "excluded_matched_files": excluded_matches,
                "scanned_files": len(modules),
                "source_scan_truncated": truncated,
                "parse_errors": parse_errors,
                "role": repository_role(repository, modules, excluded_matches),
                "sites": sites,
            }
        )
    sites = [site for row in rows for site in row["sites"]]
    return {
        "schema_version": 2,
        "task_version": config["task_version"],
        "split": config["split"],
        "analysis_scope": "bounded repository-wide first-party Python AST; vendor/environment paths excluded",
        "counts": {
            "planned_repositories": len(frame_repositories),
            "completed_repositories": len(rows),
            "repositories_with_sites": sum(bool(row["sites"]) for row in rows),
            "repositories_with_explicit_effect_site": sum(
                any(site["tool_evidence"]["effect_status"] == "explicit_effect" for site in row["sites"]) for row in rows
            ),
            "source_scan_truncated_repositories": sum(row["source_scan_truncated"] for row in rows),
            "guard_sites": len(sites),
            "parse_errors": sum(len(row["parse_errors"]) for row in rows),
            "roles": dict(sorted(Counter(row["role"] for row in rows).items())),
            "repair_classes": dict(sorted(Counter(site["repair_class"] for site in sites).items())),
            "decidability": dict(sorted(Counter(site["decidability"] for site in sites).items())),
        },
        "repositories": rows,
        "execution_health": "completed",
        "scientific_outcome": "success",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Repository-wide bounded guard/effect placement analyzer")
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
