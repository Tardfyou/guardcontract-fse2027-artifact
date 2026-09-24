from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from guardcontract.paths import project_root

import argparse
import json
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Mapping

PROJECT_DIR = project_root()
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from guardcontract.corpus.dependencies.fetch_github_repository_queries_i2 import FetchFailure, collect


class AuthorizationFailure(RuntimeError):
    pass


def gh_get_json(url: str, retries: int) -> tuple[dict[str, Any], dict[str, str]]:
    params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    command = [
        "gh", "api", "-X", "GET", "search/repositories",
        "-f", f"q={params['q'][0]}",
        "-f", f"per_page={params['per_page'][0]}",
        "-f", f"page={params['page'][0]}",
    ]
    last: FetchFailure | None = None
    for attempt in range(retries + 1):
        completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        if completed.returncode == 0:
            try:
                body = json.loads(completed.stdout)
            except json.JSONDecodeError:
                last = FetchFailure("decode-error", "GitHub CLI returned invalid JSON")
            else:
                if isinstance(body.get("items"), list) and isinstance(body.get("total_count"), int):
                    return body, {}
                last = FetchFailure("schema-error", "GitHub repository search response lacks items or total_count")
        else:
            lowered = completed.stderr.lower()
            if "http 401" in lowered or ("http 403" in lowered and "rate limit" not in lowered):
                raise AuthorizationFailure("GitHub authentication lacks repository-search access")
            if "rate limit" in lowered or "http 429" in lowered:
                last = FetchFailure("rate-limited", "GitHub repository-search rate limit", 429)
            else:
                last = FetchFailure("gh-error", f"GitHub CLI exited {completed.returncode}")
        if attempt < retries:
            time.sleep(min(2**attempt, 8))
    raise last or FetchFailure("unknown", "GitHub repository search failed")


def fetch(
    config: Mapping[str, Any],
    *,
    getter: Callable[[str, int], tuple[dict[str, Any], dict[str, str]]] = gh_get_json,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    result = collect(config, getter=getter, sleeper=sleeper)
    result["source"] = "GitHub REST repository search via authenticated gh CLI"
    result["credentials_used"] = True
    result["credential_handling"] = "gh credential store; collector neither reads nor serializes the token"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect authenticated paginated GitHub repository searches")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    if args.result.exists():
        raise FileExistsError(f"refusing to overwrite artifact: {args.result}")
    try:
        result = fetch(json.loads(args.config.read_text(encoding="utf-8")))
    except AuthorizationFailure as exc:
        print(json.dumps({"authorization_required": True, "error": str(exc)}, sort_keys=True))
        return 3
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], sort_keys=True))
    return 0 if result["execution_health"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
