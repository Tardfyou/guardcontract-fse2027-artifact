"""Framework-independent effect inventory for repositories without registration support."""
import ast
import hashlib
from pathlib import Path
from guardcontract.discovery.scout import effect_sites_from_tree
from guardcontract.evidence.slicing import EXCLUDED_PARTS


def verify_source_hash(root, candidate):
    """Verify a candidate's source identity before downstream binding."""
    if not isinstance(candidate, dict) or not isinstance(candidate.get('path'), str) or not isinstance(candidate.get('source_sha256'), str):
        raise ValueError('generic_effect_candidate_identity')
    target = Path(root).resolve() / candidate['path']
    if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(Path(root).resolve()):
        return False
    return hashlib.sha256(target.read_bytes()).hexdigest() == candidate['source_sha256']


def inventory(root, *, max_files=2000, max_file_bytes=512000, include_non_production=False):
    root = Path(root).resolve()
    if type(max_files) is not int or max_files < 1 or type(max_file_bytes) is not int or max_file_bytes < 1:
        raise ValueError("generic_effect_inventory_budget")
    rows, errors, seen = [], [], 0
    for path in sorted(root.rglob("*.py")):
        if seen >= max_files: break
        relative = path.relative_to(root)
        non_production = any(part.lower() in {"tests", "test", "examples", "example", "demo"}
                             for part in relative.parts)
        if (not include_non_production and non_production):
            continue
        if (path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root)
                or any(part in EXCLUDED_PARTS or part.lower().startswith('.env') for part in relative.parts)):
            continue
        seen += 1
        try:
            raw = path.read_bytes()
            source_sha256 = __import__('hashlib').sha256(raw).hexdigest()
            if len(raw) > max_file_bytes: raise ValueError("source_byte_budget")
            tree = ast.parse(raw.decode("utf-8-sig"), filename=str(path))
            for site in effect_sites_from_tree(tree, relative.as_posix()):
                rows.append({"path":site.path,"line":site.line,"family":site.family,"call":site.call,
                             "source_sha256":source_sha256,
                             "binding_status":"unbound_generic_sink","path_status":"unknown"})
        except (OSError, UnicodeError, SyntaxError, ValueError) as exc:
            errors.append({"path":path.relative_to(root).as_posix(),
                           "error_kind":type(exc).__name__,
                           "evaluation_relevance":"non_production" if non_production else "production_candidate"})
    return {"schema_version":"generic-effect-catalog-1","effects":rows,"errors":errors,
            "scanned_files":seen,"claim_boundary":"Unbound generic sink candidates only; no framework registration, guard/effect path, runtime or issue claim."}
