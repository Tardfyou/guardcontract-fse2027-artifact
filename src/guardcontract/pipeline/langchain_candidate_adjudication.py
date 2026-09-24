"""Deterministically separate LangChain registration candidates from audit sites."""
import json
from collections import Counter
from pathlib import Path

def adjudicate(payload):
    rows = []
    for repo in payload.get("repositories", []):
        for site in repo.get("sites", []):
            effects = site.get("tool_evidence", {}).get("explicit_effects", [])
            if site.get("path_status") != "path_verified":
                status = "unknown_path"
            elif effects:
                status = "auditable_candidate"
            else:
                status = "no_explicit_effect"
            rows.append({"repository": repo["repository"], "framework": repo["framework"],
                         "path": site["path"], "line": site["line"], "status": status,
                         "effect_count": len(effects)})
    return {"schema_version": "langchain-candidate-adjudication-1", "rows": rows,
            "counts": dict(Counter(row["status"] for row in rows)),
            "claim_boundary": "Static registration/effect evidence only; no issue or prevalence claim."}

def main():
    source = Path("experiments/prospective-batch-materialization-n301/DISCOVERY_RESULT_V2.json")
    output = source.with_name("LANGCHAIN_CANDIDATE_ADJUDICATION.json")
    result = adjudicate(json.loads(source.read_text()))
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result["counts"], sort_keys=True))

if __name__ == "__main__": main()
