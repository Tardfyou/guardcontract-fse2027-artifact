"""Conservative source-family overlap signals for holdout sampling."""
import hashlib
from pathlib import Path
from guardcontract.evidence.slicing import EXCLUDED_PARTS


def inventory(root):
    root = Path(root).resolve()
    rows = {}
    for path in root.rglob("*.py"):
        rel = path.relative_to(root)
        if path.is_symlink() or not path.is_file() or any(part in EXCLUDED_PARTS for part in rel.parts):
            continue
        rows[rel.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return rows


def compare(left, right):
    left_inventory, right_inventory = inventory(left), inventory(right)
    common = set(left_inventory) & set(right_inventory)
    identical = {path for path in common if left_inventory[path] == right_inventory[path]}
    ratio = len(identical) / len(common) if common else None
    return {"left_files": len(left_inventory), "right_files": len(right_inventory),
            "common_paths": len(common), "identical_common": len(identical),
            "identical_ratio": ratio, "identical_paths": sorted(identical),
            "status": "needs_manual_family_decision" if identical else "no_identical_common_files",
            "claim_boundary": "Path/content overlap signal; no authorship or family identity conclusion."}
