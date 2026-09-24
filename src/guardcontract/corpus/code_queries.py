from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from guardcontract.paths import project_root

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Mapping

PROJECT_DIR = project_root()
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from guardcontract.corpus.dependencies.fetch_github_code_queries import collect, gh_request


class PublicOnlyRequester:
    def __init__(self, requester: Callable[[str, int, int, int], dict[str, Any]] = gh_request):
        self.requester = requester
        self.stats: dict[str, dict[str, int]] = defaultdict(lambda: {"raw": 0, "public": 0, "private": 0, "unknown": 0})

    def __call__(self, query: str, per_page: int, page: int, retries: int) -> dict[str, Any]:
        body = self.requester(query, per_page, page, retries)
        public_items = []
        stats = self.stats[query]
        for item in body["items"]:
            stats["raw"] += 1
            private = (item.get("repository") or {}).get("private")
            if private is False:
                public_items.append(item)
                stats["public"] += 1
            elif private is True:
                stats["private"] += 1
            else:
                stats["unknown"] += 1
        return {**body, "items": public_items}


def fetch_public(
    config: Mapping[str, Any],
    *,
    requester: Callable[[str, int, int, int], dict[str, Any]] = gh_request,
) -> dict[str, Any]:
    public_requester = PublicOnlyRequester(requester)
    result = collect(config, requester=public_requester)
    private_count = sum(row["private"] for row in public_requester.stats.values())
    unknown_count = sum(row["unknown"] for row in public_requester.stats.values())
    raw_count = sum(row["raw"] for row in public_requester.stats.values())
    result["task_version"] = config["task_version"]
    result["source"] = "GitHub REST code search via authenticated gh CLI with pre-persistence public filtering"
    result["public_scope_enforced"] = True
    result["privacy_filter"] = {
        "raw_items": raw_count,
        "public_items_retained": result["counts"]["files_retrieved"],
        "private_items_excluded_without_identity_persistence": private_count,
        "unknown_visibility_items_excluded_without_identity_persistence": unknown_count,
    }
    for query_run in result["query_runs"]:
        stats = public_requester.stats[query_run["query"]]
        query_run["privacy_filter_counts"] = stats
        if query_run["total_count"] is not None and stats["raw"] < min(query_run["total_count"], 1000):
            query_run["complete_within_github_cap"] = False
            query_run["truncated_by_page_cap"] = not query_run["errors"]
    result["inference_boundary"] = (
        "First-page exact API code-search candidates after pre-persistence public filtering; "
        "not exhaustive framework use, guard placement, vulnerability evidence, or a random population."
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect public-only GitHub code-search candidates")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    if args.result.exists():
        raise FileExistsError(f"refusing to overwrite artifact: {args.result}")
    result = fetch_public(json.loads(args.config.read_text(encoding="utf-8")))
    args.result.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({**result["counts"], **result["privacy_filter"]}, sort_keys=True))
    if result["authorization_required"]:
        return 3
    return 0 if result["execution_health"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
