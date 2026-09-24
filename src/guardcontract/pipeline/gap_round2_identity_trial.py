"""Freeze a second, disjoint identity pool from the expanded public code search."""
import hashlib
import json
from pathlib import Path

from guardcontract.corpus.family_first_identity import select
from guardcontract.paths import project_root

ROOT = project_root()
DIRECTORY = ROOT / "experiments/prospective-gap-round2-identity-n313"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def main():
    if DIRECTORY.exists():
        raise ValueError("gap_round2_identity_existing")
    raw = ROOT / "experiments/prospective-gap-search-round2-n312/RAW_RESULT.json"
    old = ROOT / "experiments/holdout-readiness-n240/RESULT.json"
    first = ROOT / "experiments/prospective-identity-freeze-n265/RESULT.json"
    second = ROOT / "experiments/prospective-guard-identity-freeze-n273/RESULT.json"
    session = ROOT / "experiments/session-exposure-n262/RESULT.json"
    binding = ROOT / "experiments/binding-evidence-n160/RESULT_I2.json"
    pilot = ROOT / "experiments/prospective-guard-effect-materialization-n282/FRAME.json"
    base = ROOT / "experiments/prospective-family-first-identity-n286/RESULT.json"
    prior = ROOT / "experiments/prospective-gap-round1-identity-n288/RESULT.json"
    excluded = ({r["repository"] for r in read(old)["rows"]}
                | {r["repository"]["full_name"] for r in read(first)["selected"]}
                | {r["full_name"] for r in read(second)["selected"]}
                | {r["full_name"] for r in read(base)["selected"]}
                | {r["full_name"] for r in read(prior)["selected"]}
                | set(read(session)["mentioned_repositories"])
                | {r["full_name"] for r in read(ROOT / "experiments/prospective-gap-round1-identity-n288/RESULT.json")["selected"]})
    excluded_blobs = ({r["integrity"].get("git_blob") for r in read(binding)["records"] if r["integrity"].get("git_blob")}
                      | {loc["blob_sha"] for r in read(pilot)["selected"] for loc in r["matched_files"] if loc.get("blob_sha")}
                      | {loc["blob_sha"] for r in read(base)["selected"] for loc in r["locations"] if loc.get("blob_sha")}
                      | {loc["blob_sha"] for r in read(prior)["selected"] for loc in r["locations"] if loc.get("blob_sha")})
    strata = [f + "-" + p for f in ("langchain", "google-adk", "pydantic-ai", "openai-agents", "crewai") for p in ("post", "pre")]
    result = select(read(raw), excluded, excluded_blobs,
                    {"langchain-ai/langchain", "google/adk-python", "pydantic/pydantic-ai",
                     "openai/openai-agents-python", "crewaiinc/crewai"},
                    strata=strata, target=40, seed="guardcontract-gap-round2-v1-20260912")
    inputs = (raw, old, first, second, session, binding, pilot, base, prior, Path(__file__),
              ROOT / "src/guardcontract/corpus/family_first_identity.py")
    result.update(schema_version="prospective-gap-round2-identity-freeze-1",
                  inputs_sha256={str(p.relative_to(ROOT)): sha(p) for p in inputs},
                  round=2, prior_round="prospective-gap-round1-identity-n288",
                  source_content_read=False, holdout_admission_authorized=False,
                  goal_completion_proven=False)
    write_new(DIRECTORY / "RESULT.json", result)
    print(json.dumps(result["counts"], ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
