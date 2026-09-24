"""Conservative LangChain registration adapter.

It exposes registration candidates while keeping path semantics explicitly
unverified. Dynamic middleware and effect binding remain unknown.
"""
from pathlib import Path
from guardcontract.discovery.registration import discover_registrations

def scan(root: Path, max_files: int = 2000, max_file_bytes: int = 1_048_576) -> dict:
    result = discover_registrations(root, max_files=max_files, max_file_bytes=max_file_bytes)
    groups = []
    for group in result["groups"]:
        if group["kind"] != "middleware_registration":
            continue
        # Registration and syntactic sink association do not prove execution.
        groups.append({**group,
                       "path_status": "path_unverified",
                       "semantic_status": "unknown"})
    return {"groups": groups, "unresolved_registrations": result["unresolved_registrations"],
            "files": result.get("files", []),
            "groups_budget_deferred": result.get("groups_budget_deferred", 0),
            "source_enumeration_complete": result["source_enumeration_complete"],
            "execution_health": result["execution_health"],
            "claim_boundary": "LangChain registration candidates only; independent path and behavior validation required."}
