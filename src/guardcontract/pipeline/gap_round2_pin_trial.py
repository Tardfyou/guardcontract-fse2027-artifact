"""Pin public repository identities for the second gap-search sample pool."""
import hashlib
import json
import subprocess
import time
from pathlib import Path

from guardcontract.corpus.guard_code_pin import pin
from guardcontract.paths import project_root

ROOT = project_root()
SOURCE = ROOT / "experiments/prospective-gap-round2-identity-n313/RESULT.json"
DIRECTORY = ROOT / "experiments/prospective-gap-round2-commit-n314"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def request(query):
    completed = subprocess.run(["gh", "api", "graphql", "-f", "query=" + query],
                               capture_output=True, text=True, timeout=90, check=False)
    if completed.returncode:
        raise RuntimeError("github_graphql_error")
    return json.loads(completed.stdout)


def main():
    if DIRECTORY.exists():
        raise ValueError("gap_round2_pin_existing")
    identity = json.loads(SOURCE.read_bytes())
    started = time.perf_counter()
    result = pin(identity["selected"], request)
    result.update(schema_version="prospective-gap-round2-commit-freeze-1",
                  duration_seconds=time.perf_counter() - started,
                  identity_sha256=identity["identity_sha256"], round=2,
                  inputs_sha256={str(path.relative_to(ROOT)): sha(path)
                                 for path in (SOURCE, Path(__file__), ROOT / "src/guardcontract/corpus/guard_code_pin.py")},
                  execution_health="completed" if result["counts"]["errors"] == 0 else "partial",
                  holdout_admission_authorized=False, source_content_read=False,
                  repository_code_executed=False, goal_completion_proven=False)
    DIRECTORY.mkdir()
    (DIRECTORY / "RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"execution_health": result["execution_health"], **result["counts"]}, sort_keys=True))


if __name__ == "__main__":
    main()
