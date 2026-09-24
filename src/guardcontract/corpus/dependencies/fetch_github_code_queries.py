from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import argparse
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


class SearchFailure(RuntimeError):
    def __init__(self, error_type: str, detail: str):
        super().__init__(detail)
        self.error_type = error_type
        self.detail = detail


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


def gh_request(query: str, per_page: int, page: int, retries: int) -> dict[str, Any]:
    command = [
        "gh", "api", "-X", "GET", "search/code",
        "-f", f"q={query}", "-f", f"per_page={per_page}", "-f", f"page={page}",
    ]
    last: SearchFailure | None = None
    for attempt in range(retries + 1):
        completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        if completed.returncode == 0:
            try:
                body = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                last = SearchFailure("decode-error", "GitHub CLI returned invalid JSON")
            else:
                if isinstance(body.get("total_count"), int) and isinstance(body.get("items"), list):
                    return body
                last = SearchFailure("schema-error", "GitHub code search response lacks total_count or items")
        else:
            lowered = completed.stderr.lower()
            if "http 401" in lowered or ("http 403" in lowered and "rate limit" not in lowered):
                raise SearchFailure("authorization", "GitHub authentication lacks code-search access")
            if "rate limit" in lowered or "http 429" in lowered:
                last = SearchFailure("rate-limited", "GitHub code-search rate limit")
            else:
                last = SearchFailure("gh-error", f"GitHub CLI exited {completed.returncode}")
        if attempt < retries:
            time.sleep(min(2**attempt, 8))
    raise last or SearchFailure("unknown", "GitHub code search failed")


def _repository(item: Mapping[str, Any]) -> dict[str, Any]:
    repository = item["repository"]
    full_name = repository["full_name"]
    return {
        "id": int(repository["id"]),
        "full_name": full_name,
        "html_url": repository["html_url"],
        "clone_url": repository.get("clone_url") or f"https://github.com/{full_name}.git",
        "default_branch": repository.get("default_branch"),
        "fork": repository.get("fork"),
        "archived": repository.get("archived"),
        "language": repository.get("language"),
        "stargazers_count": (
            int(repository["stargazers_count"])
            if repository.get("stargazers_count") is not None
            else None
        ),
        "pushed_at": repository.get("pushed_at"),
        "metadata_state": (
            "complete"
            if all(key in repository for key in ("default_branch", "fork", "archived", "language", "stargazers_count", "pushed_at"))
            else "code-search-summary-only"
        ),
    }


def collect(
    config: Mapping[str, Any],
    *,
    requester: Callable[[str, int, int, int], dict[str, Any]] = gh_request,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    validate_config(config)
    per_page = int(config["per_page"])
    retries = int(config["request_retries"])
    interval = float(config["request_interval_seconds"])
    merged: dict[int, dict[str, Any]] = {}
    query_runs = []
    requests_completed = 0
    files_retrieved = 0
    authorization_required = False

    for specification in config["queries"]:
        if authorization_required:
            query_runs.append(
                {
                    "id": specification["id"], "framework": specification["framework"],
                    "language": specification["language"], "query": specification["query"],
                    "total_count": None, "pages": [],
                    "errors": [{"error_type": "not-run-after-authorization-failure", "detail": "collection stopped"}],
                    "complete_within_github_cap": False, "truncated_by_page_cap": False,
                    "github_result_cap_applies": False,
                }
            )
            continue
        pages = []
        errors = []
        total_count: int | None = None
        complete = False
        for page in range(1, int(specification.get("max_pages", 1)) + 1):
            if requests_completed and interval:
                sleeper(interval)
            try:
                body = requester(specification["query"], per_page, page, retries)
                requests_completed += 1
                total_count = int(body["total_count"])
                items = body["items"]
                files_retrieved += len(items)
                pages.append(
                    {
                        "page": page,
                        "retrieved": len(items),
                        "incomplete_results": bool(body.get("incomplete_results")),
                        "identity_sha256": _sha256(
                            [[item["repository"]["id"], item["path"], item.get("sha")] for item in items]
                        ),
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
                            "locations": [],
                            "source_state": "github-code-search-unpinned",
                        },
                    )
                    row["matched_frameworks"].append(specification["framework"])
                    row["matched_query_ids"].append(specification["id"])
                    row["locations"].append(
                        {"query_id": specification["id"], "path": item["path"], "blob_sha": item.get("sha")}
                    )
                accessible_total = min(total_count, 1000)
                if len(items) < per_page or page * per_page >= accessible_total:
                    complete = True
                    break
            except SearchFailure as exc:
                errors.append({"page": page, "error_type": exc.error_type, "detail": exc.detail})
                if exc.error_type == "authorization":
                    authorization_required = True
                break
        max_pages = int(specification.get("max_pages", 1))
        query_runs.append(
            {
                "id": specification["id"], "framework": specification["framework"],
                "language": specification["language"], "query": specification["query"],
                "total_count": total_count, "pages": pages, "errors": errors,
                "complete_within_github_cap": complete and not errors,
                "truncated_by_page_cap": bool(not complete and not errors and len(pages) == max_pages),
                "github_result_cap_applies": bool(total_count is not None and total_count > 1000),
            }
        )

    candidates = sorted(merged.values(), key=lambda row: row["repository"]["id"])
    for row in candidates:
        row["matched_frameworks"] = sorted(set(row["matched_frameworks"]))
        row["matched_query_ids"] = sorted(set(row["matched_query_ids"]))
        row["locations"] = sorted(
            {(_["query_id"], _["path"], _["blob_sha"] or "") for _ in row["locations"]}
        )
        row["locations"] = [
            {"query_id": query_id, "path": path, "blob_sha": blob_sha}
            for query_id, path, blob_sha in row["locations"]
        ]
    failed_queries = sum(bool(row["errors"]) for row in query_runs)
    if authorization_required:
        execution_health = "error"
    elif failed_queries:
        execution_health = "partial"
    else:
        execution_health = "completed"
    identity = [[row["repository"]["id"], row["repository"]["full_name"], row["matched_query_ids"]] for row in candidates]
    return {
        "schema_version": 1,
        "task_version": config["task_version"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": "GitHub REST code search via authenticated gh CLI",
        "execution_health": execution_health,
        "scientific_outcome": "unscored",
        "authorization_required": authorization_required,
        "credentials_used": True,
        "credential_handling": "gh credential store; collector neither reads nor serializes the token",
        "selection_unit": "repository_id",
        "inference_boundary": "Exact API code-search candidates; file matches are not pinned framework use, guard placement, vulnerability evidence, or an exhaustive population.",
        "query_runs": query_runs,
        "counts": {
            "queries_planned": len(config["queries"]),
            "queries_completed_without_error": len(config["queries"]) - failed_queries,
            "queries_with_errors": failed_queries,
            "requests_completed": requests_completed,
            "files_retrieved": files_retrieved,
            "unique_repositories": len(candidates),
            "framework_repository_pairs": sum(len(row["matched_frameworks"]) for row in candidates),
        },
        "identity_sha256": _sha256(identity),
        "candidates": candidates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect authenticated GitHub code-search candidates")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    if args.result.exists():
        raise FileExistsError(f"refusing to overwrite artifact: {args.result}")
    result = collect(json.loads(args.config.read_text(encoding="utf-8")))
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], sort_keys=True))
    if result["authorization_required"]:
        return 3
    return 0 if result["execution_health"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
