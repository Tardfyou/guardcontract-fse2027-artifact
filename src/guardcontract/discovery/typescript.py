from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from guardcontract.paths import project_root

import argparse
import collections
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

PROJECT_DIR = project_root()
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from guardcontract.discovery.dependencies.scan_framework_guard_sites_i2 import _excluded_directory, _excluded_path, _marker_pattern


IMPORT_PATTERNS = (
    re.compile(r"(?m)^\s*import\s+(?:type\s+)?(?:[^'\"\n]+?\s+from\s+)?['\"]([^'\"]+)['\"]"),
    re.compile(r"\brequire\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"),
    re.compile(r"\bimport\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"),
)


def validate_config(config: Mapping[str, Any]) -> None:
    required = {"schema_version", "task_version", "frameworks", "excluded_owners", "context_lines", "max_file_bytes", "extensions"}
    missing = sorted(required - config.keys())
    if missing:
        raise ValueError(f"missing config fields: {', '.join(missing)}")
    if config["schema_version"] != 1 or not config["frameworks"] or not config["extensions"]:
        raise ValueError("invalid TypeScript scanner config")
    for framework, row in config["frameworks"].items():
        if not row.get("import_roots") or not row.get("markers"):
            raise ValueError(f"framework {framework} lacks imports or markers")


def _module_matches(module: str, roots: Iterable[str]) -> bool:
    return any(module == root or module.startswith(root + "/") for root in roots)


def imported_frameworks(source: str, frameworks: Mapping[str, Any]) -> set[str]:
    modules = {module for pattern in IMPORT_PATTERNS for module in pattern.findall(source)}
    return {
        framework
        for framework, row in frameworks.items()
        if any(_module_matches(module, row["import_roots"]) for module in modules)
    }


def _source_paths(root: Path, extensions: set[str]) -> Iterable[Path]:
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            directory for directory in directories
            if not _excluded_directory(directory) and not (Path(current) / directory).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.startswith("~$") and Path(filename).suffix in extensions:
                yield Path(current) / filename


def scan(materialization: Mapping[str, Any], config: Mapping[str, Any]) -> dict[str, Any]:
    validate_config(config)
    frameworks = config["frameworks"]
    extensions = set(config["extensions"])
    excluded_owners = {value.casefold() for value in config["excluded_owners"]}
    context_lines = int(config["context_lines"])
    max_file_bytes = int(config["max_file_bytes"])
    import_literals = {root for row in frameworks.values() for root in row["import_roots"]}
    sites = []
    source_errors = []
    imported_repositories: dict[str, set[str]] = {}
    excluded_official = []

    for row in materialization.get("repositories", []):
        if row.get("status") != "completed" or not isinstance(row.get("repository"), str):
            continue
        repository = row["repository"]
        if repository.split("/", 1)[0].casefold() in excluded_owners:
            excluded_official.append(repository)
            continue
        root = Path(row["destination"]).resolve()
        repo_frameworks: set[str] = set()
        for target in _source_paths(root, extensions):
            relative = target.relative_to(root).as_posix()
            if _excluded_path(relative) or not target.resolve().is_relative_to(root):
                continue
            try:
                if target.stat().st_size > max_file_bytes:
                    continue
                source = target.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                source_errors.append({"repository": repository, "path": relative, "error": "non-utf8"})
                continue
            except OSError:
                source_errors.append({"repository": repository, "path": relative, "error": "read-error"})
                continue
            if not any(root_literal in source for root_literal in import_literals):
                continue
            possible = {
                framework: specification
                for framework, specification in frameworks.items()
                if any(root_literal in source for root_literal in specification["import_roots"])
                and any(marker["literal"] in source for marker in specification["markers"])
            }
            if not possible:
                continue
            detected = imported_frameworks(source, possible)
            repo_frameworks.update(detected)
            if not detected:
                continue
            lines = source.splitlines()
            for framework in sorted(detected):
                for marker in frameworks[framework]["markers"]:
                    pattern = _marker_pattern(marker["literal"])
                    for index, line in enumerate(lines):
                        stripped = line.strip()
                        if stripped.startswith(("import ", "export ", "//", "/*", "*")) or not pattern.search(line):
                            continue
                        low, high = max(0, index - context_lines), min(len(lines), index + context_lines + 1)
                        normalized = "\n".join(value.strip() for value in lines[low:high] if value.strip()).encode()
                        source_parts = {part.casefold() for part in Path(relative).parts[:-1]}
                        sites.append(
                            {
                                "repository": repository,
                                "framework": framework,
                                "language": "TypeScript",
                                "path": relative,
                                "line": index + 1,
                                "marker": marker["literal"],
                                "surface": marker["surface"],
                                "timing": marker["timing"],
                                "snippet_sha256": hashlib.sha256(normalized).hexdigest(),
                                "source_copy_path": bool(source_parts & {part.casefold() for part in frameworks[framework].get("source_path_parts", [])}),
                                "import_parse_mode": "typescript-import-regex",
                            }
                        )
        imported_repositories[repository] = repo_frameworks

    sites.sort(key=lambda site: (site["repository"], site["path"], site["line"], site["framework"], site["marker"]))
    direct_repositories = {site["repository"] for site in sites}
    framework_sites = collections.Counter(site["framework"] for site in sites)
    timing = collections.Counter(site["timing"] for site in sites)
    return {
        "schema_version": 1,
        "task_version": config["task_version"],
        "execution_health": "partial" if source_errors else "completed",
        "scientific_outcome": "unscored",
        "measurement_status": "same-file-typescript-import-and-control-api-candidates",
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
        "framework_repository_counts": {
            framework: len({site["repository"] for site in sites if site["framework"] == framework})
            for framework in sorted(framework_sites)
        },
        "framework_site_counts": dict(sorted(framework_sites.items())),
        "timing_site_counts": dict(sorted(timing.items())),
        "sites": sites,
        "source_errors": source_errors,
        "excluded_official_repositories": sorted(set(excluded_official)),
        "claim_boundary": "Same TypeScript-family source file contains an exact package import and non-import control API use outside official/test/example/docs/build/dependency paths; candidates require framework-semantic and protected-effect adjudication before vulnerability or prevalence use.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan TypeScript repositories for same-file framework control APIs")
    parser.add_argument("--materialization", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    if args.result.exists():
        raise FileExistsError(f"refusing to overwrite artifact: {args.result}")
    result = scan(json.loads(args.materialization.read_text()), json.loads(args.config.read_text()))
    args.result.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], sort_keys=True))
    return 0 if result["execution_health"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
