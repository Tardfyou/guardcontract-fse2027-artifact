"""LLM arm for the matrix four-arm comparison.

For each matrix sample, sends the program sources plus the declared contract
to GLM-5.3-Flash (no wiring facts, no GT) and asks for the four predicate
facts + label. Mirrors the protection_obligation schema loosely: the model
answers {label, guard_position, effect_commits_under_deny, rationale}.
Blind to ground truth; answers recorded verbatim for offline scoring.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from guardcontract.backends.scoped_review_transport import ScopedReviewTransport  # noqa: E402
from guardcontract.backends.provider_endpoint import CHAT_COMPLETIONS_ENDPOINT, REQUIRED_THINKING  # noqa: E402
from guardcontract.pipeline.shared_review_budget import SharedReviewBudget  # noqa: E402
from guardcontract.protocols.protection_obligation_v3 import SYSTEM  # noqa: E402

MATRIX_SYSTEM = """You are auditing a small deterministic agent program. The declared protection contract is given. Decide:
1. guard_position: where the DENY-capable guard acts relative to the effect commit: "before" | "after" | "racing_after" | "none"
2. effect_commits_under_deny: whether the protected effect would still commit when the guard outputs DENY: true | false | unknown
3. label: "present" (effect escapes despite DENY) | "absent" (DENY prevents the effect) | "unknown"
Rules: base this only on the code shown; a guard that renders its verdict before the tool handler runs is "before"; after the tool body ran is "after"; a parallel/agent-level guard is "racing_after". If the guard is an in-tool check that returns before the commit call, that is "before". Answer as JSON: {"label": ..., "guard_position": ..., "effect_commits_under_deny": ..., "rationale": "one sentence"}. No prose outside JSON."""


def run_one(row: dict, sources: dict, out_dir: Path, key: str, budget: SharedReviewBudget) -> dict:
    sid = row["sample_id"]
    directory = out_dir / sid
    payload = {
        "contract": row["contract"],
        "sources": {name: content[:20000] for name, content in sources.items()},
        "framework": row["framework"],
    }
    request = {"model": "GLM-5.3-Flash", "temperature": 0, "thinking": REQUIRED_THINKING,
               "max_tokens": 8000, "response_format": {"type": "json_object"},
               "messages": [{"role": "system", "content": MATRIX_SYSTEM},
                            {"role": "user", "content": json.dumps(payload, sort_keys=True)}]}
    record = {"sample_id": sid, "framework": row["framework"], "binding": row["binding"],
              "guard_position_declared": row["position"]}
    if not budget.start():
        record["state"] = "budget_exhausted"
        return record
    transport = ScopedReviewTransport(directory / "calls", model="GLM-5.3-Flash")
    used, known = 0, False
    try:
        raw = transport(CHAT_COMPLETIONS_ENDPOINT,
                        {"Content-Type": "application/json", "Authorization": "Bearer " + key},
                        json.dumps(request, separators=(",", ":")).encode(), 600)
        answer = json.loads(json.loads(raw)["choices"][0]["message"]["content"])
        record.update(answer=answer, state="completed")
        usage = json.loads(raw).get("usage") or {}
        used, known = usage.get("total_tokens", 0), True
    except Exception as exc:
        record.update(state="error", error=f"{type(exc).__name__}: {str(exc)[:200]}")
    finally:
        budget.finish(used, known)
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--split", type=Path, required=True)
    parser.add_argument("--side", choices=("dev", "test", "all"), default="dev")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    queue = json.loads(args.queue.read_text(encoding="utf-8"))
    split = json.loads(args.split.read_text(encoding="utf-8"))
    side_ids = set(split[args.side]["samples"]) if args.side != "all" else None
    key = (Path.home() / ".config/guardcontract/paratera.key").read_text().strip()
    args.out.mkdir(parents=True, exist_ok=False)
    budget = SharedReviewBudget(max_calls=200, stop_before_tokens=30000000)
    rows = []
    for row in queue["rows"]:
        if side_ids is not None and row["sample_id"] not in side_ids:
            continue
        root = ROOT / "experiments/p0-clean-matrix-generate-round157-n1922/sources" / row["root"]
        sources = {p.name: p.read_text(encoding="utf-8") for p in root.glob("*.py") if p.name != "matrix_effects.py"}
        rows.append((row, sources))
    def work(item):
        row, sources = item
        return run_one(row, sources, args.out, key, budget)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(work, rows))
    result = {"schema_version": "p0-matrix-llm-arm-1", "side": args.side,
              "rows": results,
              "counts": {"n": len(results),
                         "completed": sum(1 for r in results if r.get("state") == "completed"),
                         "errors": sum(1 for r in results if r.get("state") == "error")},
              "created_time_ns": time.time_ns(),
              "blind": "ground truth not included in any payload"}
    (args.out / "LLM_ARM.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"]))


if __name__ == "__main__":
    main()
