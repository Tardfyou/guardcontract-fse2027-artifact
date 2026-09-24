"""Read static packaging declarations without importing or building the project."""
import hashlib
from pathlib import Path, PurePosixPath
import tomllib

from guardcontract.discovery.repository_calls import validate_module_roots


def read_project_layout(root, python_paths, *, max_configs=128, max_config_bytes=65536):
    if any(type(n) is not int or n < 1 for n in (max_configs, max_config_bytes)):
        raise ValueError("positive_project_layout_budgets_required")
    root = Path(root).resolve()
    candidates = {"pyproject.toml"}
    for path in python_paths:
        for parent in PurePosixPath(path).parents:
            candidates.add((parent / "pyproject.toml").as_posix())
    files, declarations, gaps = [], [], []
    complete = True
    for relative in sorted(candidates):
        target = root / relative
        if not target.exists() and not target.is_symlink():
            continue
        if len(files) >= max_configs:
            complete = False
            gaps.append({"path": relative, "reason": "project_config_count_budget"})
            break
        row = {"path": relative}
        local = []
        try:
            if target.is_symlink() or not target.resolve().is_relative_to(root):
                raise ValueError("unsafe_project_config")
            with target.open("rb") as handle:
                raw = handle.read(max_config_bytes + 1)
            if len(raw) > max_config_bytes:
                raise ValueError("project_config_byte_budget")
            config = tomllib.loads(raw.decode("utf-8"))
            tools = config.get("tool", {})
            def declare(directory, field):
                validate_module_roots([directory])
                source_root = (PurePosixPath(relative).parent / directory).as_posix()
                local.append({"root": source_root, "source": relative, "field": field,
                              "scope": "packaging_declaration", "runtime_verified": False,
                              "source_sha256": hashlib.sha256(raw).hexdigest(),
                              "start_line": 1, "end_line": len(raw.splitlines())})
            hatch = tools.get("hatch", {}).get("build", {}).get("targets", {}).get("wheel", {})
            packages = hatch.get("packages", [])
            if not isinstance(packages, list):
                raise ValueError("dynamic_hatch_packages")
            # Rewritten wheel paths need a separate mapping contract.
            if packages and (hatch.get("sources") or tools.get("hatch", {}).get("build", {}).get("sources")):
                gaps.append({"path": relative, "reason": "hatch_source_remapping_unresolved"})
            else:
                for package in packages:
                    validate_module_roots([package])
                    if any(char in package for char in "*?[]"):
                        raise ValueError("dynamic_hatch_package_path")
                    declare(PurePosixPath(package).parent.as_posix(), "tool.hatch.build.targets.wheel.packages")
            setuptools = tools.get("setuptools", {})
            package_dir = setuptools.get("package-dir", {})
            if not isinstance(package_dir, dict):
                raise ValueError("setuptools_package_dir_shape")
            if set(package_dir) - {""}:
                gaps.append({"path": relative, "reason": "named_package_mapping_unresolved"})
            elif "" in package_dir:
                declare(package_dir[""], 'tool.setuptools.package-dir.""')
            row.update(status="parsed", bytes=len(raw), source_sha256=hashlib.sha256(raw).hexdigest())
            declarations.extend(local)
        except (OSError, ValueError, UnicodeError, TypeError, AttributeError) as exc:
            row.update(status="unavailable", error_kind=type(exc).__name__)
            complete = False
        files.append(row)
    unique = {(d["source"], d["root"], d["field"]): d for d in declarations}
    return {"files": files, "declarations": [unique[k] for k in sorted(unique)],
            "gaps": gaps, "complete": complete,
            "claim_boundary": "Packaging declarations describe candidate import roots, not installed runtime paths. Test-only Python paths are not applied to application analysis."}
