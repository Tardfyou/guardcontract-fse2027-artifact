from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import argparse
import ast
import collections
import hashlib
import json
import os
import re
import warnings
from pathlib import Path
from typing import Any, Iterable, Mapping


def validate_config(config: Mapping[str, Any]) -> None:
    required = {"schema_version", "task_version", "frameworks", "excluded_owners", "context_lines", "max_file_bytes"}
    missing = sorted(required - config.keys())
    if missing:
        raise ValueError(f"missing config fields: {', '.join(missing)}")
    if config["schema_version"] != 1 or not isinstance(config["frameworks"], dict) or not config["frameworks"]:
        raise ValueError("invalid scanner config")
    for framework, row in config["frameworks"].items():
        if not row.get("import_roots") or not row.get("markers"):
            raise ValueError(f"framework {framework} lacks imports or markers")
        for marker in row["markers"]:
            if not all(marker.get(key) for key in ("literal", "surface", "timing")):
                raise ValueError(f"framework {framework} has incomplete marker")


EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "env", ".env", "site-packages", "node_modules", "vendor", "__pycache__",
    "test", "tests", "testing", "example", "examples", "docs", "doc", "build", "dist", "target",
    ".tox", ".nox", ".cache", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "reference", "references", "third_party", "third-party", "external_dependencies", "external-dependencies",
}


def _excluded_directory(name: str) -> bool:
    lowered = name.casefold()
    return lowered in EXCLUDED_DIRS or "virtualenv" in lowered or "conda_env" in lowered or lowered.startswith(".conda")


def _excluded_path(path: str) -> bool:
    lowered = path.lower()
    parts = tuple(part.lower() for part in Path(path).parts)
    return any(_excluded_directory(part) for part in parts) or any(
        part.startswith(("test_", "example_")) or part.endswith(("_test.py", "_example.py"))
        for part in parts
    )


def _module_matches(module: str, roots: Iterable[str]) -> bool:
    return any(module == root or module.startswith(root + ".") for root in roots)


def imported_frameworks(source: str, frameworks: Mapping[str, Any]) -> tuple[set[str], str]:
    modules = []
    mode = "ast"
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(source)
    except SyntaxError:
        mode = "regex-fallback"
        pattern = re.compile(r"(?m)^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*))")
        modules = [left or right for left, right in pattern.findall(source)]
    else:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
    detected = {
        framework
        for framework, row in frameworks.items()
        if any(_module_matches(module, row["import_roots"]) for module in modules)
    }
    return detected, mode


def _marker_pattern(literal: str) -> re.Pattern[str]:
    prefix = r"(?<![A-Za-z0-9_])" if literal[0].isalnum() or literal[0] == "_" else ""
    suffix = r"(?![A-Za-z0-9_])" if literal[-1].isalnum() or literal[-1] == "_" else ""
    return re.compile(prefix + re.escape(literal) + suffix)


def _code_units(path: Path, relative: str, max_file_bytes: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    errors = []
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > max_file_bytes:
            return [], errors
        raw = path.read_bytes()
    except OSError:
        return [], [{"path": relative, "error": "read-error"}]
    if path.suffix == ".py":
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError:
            return [], [{"path": relative, "error": "non-utf8"}]
        return [{"path": relative, "source_kind": "python", "cell": None, "source": source}], errors
    try:
        notebook = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return [], [{"path": relative, "error": "invalid-notebook-json"}]
    units = []
    for cell_index, cell in enumerate(notebook.get("cells", [])):
        if cell.get("cell_type") != "code":
            continue
        value = cell.get("source", "")
        source = "".join(value) if isinstance(value, list) else value
        if isinstance(source, str):
            units.append(
                {
                    "path": relative,
                    "source_kind": "notebook-code-cell",
                    "cell": cell_index,
                    "source": source,
                }
            )
    return units, errors


def _source_paths(root: Path) -> Iterable[Path]:
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            directory
            for directory in directories
            if not _excluded_directory(directory) and not (Path(current) / directory).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.startswith("~$") and filename.endswith((".py", ".ipynb")):
                yield Path(current) / filename


def scan(materialization: Mapping[str, Any], config: Mapping[str, Any]) -> dict[str, Any]:
    validate_config(config)
    frameworks = config["frameworks"]
    excluded_owners = {value.casefold() for value in config["excluded_owners"]}
    context_lines = int(config["context_lines"])
    max_file_bytes = int(config["max_file_bytes"])
    sites = []
    source_errors = []
    parse_modes = collections.Counter()
    imported_repositories: dict[str, set[str]] = {}
    excluded_official = []
    import_literals = sorted(
        {root for row in frameworks.values() for root in row["import_roots"]},
        key=len,
        reverse=True,
    )

    for row in materialization.get("repositories", []):
        if row.get("status") != "completed" or not isinstance(row.get("repository"), str):
            continue
        repository = row["repository"]
        owner = repository.split("/", 1)[0].casefold()
        if owner in excluded_owners:
            excluded_official.append(repository)
            continue
        root = Path(row["destination"]).resolve()
        repo_frameworks: set[str] = set()
        units = []
        for target in _source_paths(root):
            relative = target.relative_to(root).as_posix()
            if _excluded_path(relative) or not target.resolve().is_relative_to(root):
                continue
            current_units, errors = _code_units(target, relative, max_file_bytes)
            for error in errors:
                source_errors.append({"repository": repository, **error})
            units.extend(current_units)

        for unit in units:
            source = unit["source"]
            if not any(root in source for root in import_literals):
                continue
            possible_frameworks = {
                framework: row
                for framework, row in frameworks.items()
                if any(root in source for root in row["import_roots"])
                and any(marker["literal"] in source for marker in row["markers"])
            }
            if not possible_frameworks:
                continue
            detected, parse_mode = imported_frameworks(source, possible_frameworks)
            parse_modes[parse_mode] += 1
            repo_frameworks.update(detected)
            if not detected:
                continue
            lines = source.splitlines()
            for framework in sorted(detected):
                for marker in frameworks[framework]["markers"]:
                    pattern = _marker_pattern(marker["literal"])
                    for index, line in enumerate(lines):
                        stripped = line.strip()
                        if stripped.startswith(("from ", "import ", "#")) or not pattern.search(line):
                            continue
                        low = max(0, index - context_lines)
                        high = min(len(lines), index + context_lines + 1)
                        normalized = "\n".join(value.strip() for value in lines[low:high] if value.strip()).encode()
                        source_parts = {part.casefold() for part in Path(unit["path"]).parts[:-1]}
                        sites.append(
                            {
                                "repository": repository,
                                "framework": framework,
                                "path": unit["path"],
                                "source_kind": unit["source_kind"],
                                "cell": unit["cell"],
                                "line": index + 1,
                                "marker": marker["literal"],
                                "surface": marker["surface"],
                                "timing": marker["timing"],
                                "snippet_sha256": hashlib.sha256(normalized).hexdigest(),
                                "source_copy_path": bool(source_parts & {part.casefold() for part in frameworks[framework].get("source_path_parts", [])}),
                                "import_parse_mode": parse_mode,
                            }
                        )
        imported_repositories[repository] = repo_frameworks

    sites.sort(key=lambda site: (site["repository"], site["path"], site["cell"] if site["cell"] is not None else -1, site["line"], site["framework"], site["marker"]))
    direct_repositories = {site["repository"] for site in sites}
    framework_sites = collections.Counter(site["framework"] for site in sites)
    framework_repositories = {
        framework: len({site["repository"] for site in sites if site["framework"] == framework})
        for framework in frameworks
    }
    timing = collections.Counter(site["timing"] for site in sites)
    return {
        "schema_version": 1,
        "task_version": config["task_version"],
        "execution_health": "partial" if source_errors else "completed",
        "scientific_outcome": "unscored",
        "measurement_status": "same-unit-exact-import-and-control-api-candidates",
        "counts": {
            "materialized_repositories": sum(row.get("status") == "completed" for row in materialization.get("repositories", [])),
            "official_owner_repositories_excluded": len(set(excluded_official)),
            "application_repositories_scanned": len(imported_repositories),
            "import_confirmed_repositories": sum(bool(value) for value in imported_repositories.values()),
            "direct_guard_repositories": len(direct_repositories),
            "guard_site_observations": len(sites),
            "unique_guard_site_windows": len({site["snippet_sha256"] for site in sites}),
            "source_copy_path_sites": sum(site["source_copy_path"] for site in sites),
            "source_error_files": len(source_errors),
            "repositories_with_source_errors": len({item["repository"] for item in source_errors}),
        },
        "framework_repository_counts": {key: value for key, value in sorted(framework_repositories.items()) if value},
        "framework_site_counts": dict(sorted(framework_sites.items())),
        "timing_site_counts": dict(sorted(timing.items())),
        "parse_mode_counts": dict(sorted(parse_modes.items())),
        "sites": sites,
        "source_errors": source_errors,
        "excluded_official_repositories": sorted(set(excluded_official)),
        "claim_boundary": "Same Python file or notebook code cell contains an exact target import and non-import control API use outside test/example/docs paths; candidates still require framework-semantic and protected-effect adjudication before vulnerability or prevalence use.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan exact same-unit imports and framework control APIs")
    parser.add_argument("--materialization", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    if args.result.exists():
        raise FileExistsError(f"refusing to overwrite artifact: {args.result}")
    result = scan(
        json.loads(args.materialization.read_text(encoding="utf-8")),
        json.loads(args.config.read_text(encoding="utf-8")),
    )
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], sort_keys=True))
    return 0 if result["execution_health"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
