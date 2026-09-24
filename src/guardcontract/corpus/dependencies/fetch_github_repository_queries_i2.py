from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import argparse
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


API = "https://api.github.com/search/repositories"


class FetchFailure(RuntimeError):
    def __init__(self, error_type: str, detail: str, status: int | None = None):
        super().__init__(detail)
        self.error_type = error_type
        self.detail = detail
        self.status = status


def _sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def validate_config(config: Mapping[str, Any]) -> None:
    required = {"schema_version", "task_version", "per_page", "request_interval_seconds", "request_retries", "queries"}
    missing = sorted(required - config.keys())
    if missing:
        raise ValueError(f"missing config fields: {', '.join(missing)}")
    if config["schema_version"] != 1:
        raise ValueError("unsupported config schema")
    if not 1 <= int(config["per_page"]) <= 100:
        raise ValueError("per_page must be between 1 and 100")
    if float(config["request_interval_seconds"]) < 0 or int(config["request_retries"]) < 0:
        raise ValueError("invalid request policy")
    queries = config["queries"]
    if not isinstance(queries, list) or not queries:
        raise ValueError("queries must be a non-empty list")
    ids = [row.get("id") for row in queries]
    if any(not isinstance(value, str) or not value for value in ids) or len(ids) != len(set(ids)):
        raise ValueError("query IDs must be non-empty and unique")
    for row in queries:
        if not all(isinstance(row.get(key), str) and row[key] for key in ("framework", "language", "query")):
            raise ValueError(f"query {row.get('id')} has incomplete identity")
        if not 1 <= int(row.get("max_pages", 1)) <= 10:
            raise ValueError(f"query {row['id']} max_pages must be between 1 and 10")


def _headers(response: Any) -> dict[str, str]:
    allowed = {"etag", "last-modified", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "x-ratelimit-resource"}
    return {key.lower(): value for key, value in response.headers.items() if key.lower() in allowed}


def http_get_json(url: str, retries: int) -> tuple[dict[str, Any], dict[str, str]]:
    last_error: FetchFailure | None = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "GuardContract-research/2.0",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response), _headers(response)
        except urllib.error.HTTPError as exc:
            rate_remaining = exc.headers.get("X-RateLimit-Remaining")
            reset = exc.headers.get("X-RateLimit-Reset")
            retry_after = exc.headers.get("Retry-After")
            wait = 0.0
            if retry_after and retry_after.isdigit():
                wait = float(retry_after)
            elif rate_remaining == "0" and reset and reset.isdigit():
                wait = max(0.0, float(reset) - time.time() + 1.0)
            last_error = FetchFailure("http-error", f"HTTP {exc.code}", exc.code)
            if attempt < retries and exc.code in {403, 429} and wait <= 90:
                time.sleep(wait)
                continue
            raise last_error from exc
        except (OSError, urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
            last_error = FetchFailure(type(exc).__name__, "request-or-decode-failure")
            if attempt < retries:
                time.sleep(min(2**attempt, 8))
                continue
            raise last_error from exc
    raise last_error or FetchFailure("unknown", "request failed")


def _repository(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": int(item["id"]),
        "full_name": item["full_name"],
        "html_url": item["html_url"],
        "clone_url": item["clone_url"],
        "default_branch": item.get("default_branch"),
        "fork": bool(item.get("fork", False)),
        "archived": bool(item.get("archived", False)),
        "language": item.get("language"),
        "stargazers_count": int(item.get("stargazers_count") or 0),
        "pushed_at": item.get("pushed_at"),
    }


def collect(
    config: Mapping[str, Any],
    *,
    getter: Callable[[str, int], tuple[dict[str, Any], dict[str, str]]] = http_get_json,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    validate_config(config)
    per_page = int(config["per_page"])
    interval = float(config["request_interval_seconds"])
    retries = int(config["request_retries"])
    merged: dict[int, dict[str, Any]] = {}
    query_runs = []
    retrieved_rows = 0
    request_count = 0

    for specification in config["queries"]:
        pages = []
        errors = []
        total_count: int | None = None
        complete = False
        for page in range(1, int(specification.get("max_pages", 1)) + 1):
            if request_count and interval:
                sleeper(interval)
            url = API + "?" + urllib.parse.urlencode(
                {"q": specification["query"], "per_page": per_page, "page": page}
            )
            try:
                body, headers = getter(url, retries)
                request_count += 1
                if not isinstance(body.get("items"), list) or not isinstance(body.get("total_count"), int):
                    raise FetchFailure("schema-error", "GitHub response lacks items or total_count")
                total_count = int(body["total_count"])
                items = body["items"]
                retrieved_rows += len(items)
                pages.append(
                    {
                        "page": page,
                        "retrieved": len(items),
                        "incomplete_results": bool(body.get("incomplete_results")),
                        "identity_sha256": _sha256([[item["id"], item["full_name"]] for item in items]),
                        "headers": headers,
                    }
                )
                for item in items:
                    repository = _repository(item)
                    row = merged.setdefault(
                        repository["id"],
                        {
                            "repository": repository,
                            "matched_frameworks": [],
                            "matched_query_ids": [],
                            "source_state": "github-repository-search-unpinned",
                        },
                    )
                    row["matched_frameworks"].append(specification["framework"])
                    row["matched_query_ids"].append(specification["id"])
                accessible_total = min(total_count, 1000)
                if len(items) < per_page or page * per_page >= accessible_total:
                    complete = True
                    break
            except FetchFailure as exc:
                errors.append({"page": page, "error_type": exc.error_type, "status": exc.status, "detail": exc.detail})
                break
        max_pages = int(specification.get("max_pages", 1))
        query_runs.append(
            {
                "id": specification["id"],
                "framework": specification["framework"],
                "language": specification["language"],
                "query": specification["query"],
                "total_count": total_count,
                "pages": pages,
                "errors": errors,
                "complete_within_github_cap": complete and not errors,
                "truncated_by_page_cap": bool(not complete and not errors and len(pages) == max_pages),
                "github_result_cap_applies": bool(total_count is not None and total_count > 1000),
            }
        )

    candidates = sorted(merged.values(), key=lambda row: row["repository"]["id"])
    for row in candidates:
        row["matched_frameworks"] = sorted(set(row["matched_frameworks"]))
        row["matched_query_ids"] = sorted(set(row["matched_query_ids"]))
    failures = sum(bool(row["errors"]) for row in query_runs)
    identity = [[row["repository"]["id"], row["repository"]["full_name"], row["matched_frameworks"]] for row in candidates]
    return {
        "schema_version": 1,
        "task_version": config["task_version"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": "GitHub REST repository search API",
        "execution_health": "completed" if failures == 0 else "partial",
        "scientific_outcome": "unscored",
        "selection_unit": "repository_id",
        "inference_boundary": "Lexical README discovery only; not exact framework use, an exhaustive population, a random sample, or vulnerability evidence.",
        "query_runs": query_runs,
        "counts": {
            "queries_planned": len(config["queries"]),
            "queries_completed_without_error": len(config["queries"]) - failures,
            "queries_with_errors": failures,
            "requests_completed": request_count,
            "retrieved_rows": retrieved_rows,
            "unique_repositories": len(candidates),
            "framework_repository_pairs": sum(len(row["matched_frameworks"]) for row in candidates),
        },
        "identity_sha256": _sha256(identity),
        "candidates": candidates,
        "credentials_used": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect paginated GitHub repository discovery queries")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    if args.result.exists():
        raise FileExistsError(f"refusing to overwrite artifact: {args.result}")
    config = json.loads(args.config.read_text(encoding="utf-8"))
    result = collect(config)
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], sort_keys=True))
    return 0 if result["execution_health"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
