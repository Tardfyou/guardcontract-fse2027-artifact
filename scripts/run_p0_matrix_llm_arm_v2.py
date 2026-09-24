"""Run a resumable, prediction-blind GLM baseline on the frozen matrix test split."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import hashlib
import json
from pathlib import Path
from threading import Condition, Lock
import time
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from guardcontract.backends.provider_endpoint import CHAT_COMPLETIONS_ENDPOINT, REQUIRED_THINKING, model_identity_matches
from guardcontract.backends.scoped_review_transport import ScopedReviewTransport
from run_p0_matrix_llm_arm import MATRIX_SYSTEM

MODEL = "GLM-5.3-Flash"
BUDGETS = [16000, 32000, 64000]


def read(path): return json.loads(Path(path).read_bytes())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def digest(value): return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                                     separators=(",", ":")).encode()).hexdigest()
def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True); handle.write("\n")


class RateGate:
    def __init__(self, maximum=6):
        self.condition, self.maximum, self.limit, self.active = Condition(), maximum, 1, 0
        self.next_allowed, self.consecutive_429 = 0.0, 0
    def acquire(self):
        with self.condition:
            while self.active >= self.limit or time.monotonic() < self.next_allowed:
                self.condition.wait(timeout=max(0.1, self.next_allowed - time.monotonic()))
            self.active += 1
    def release(self, status, success):
        with self.condition:
            self.active -= 1
            if status == 429:
                self.consecutive_429 += 1; self.limit = 1
                self.next_allowed = time.monotonic() + min(3600, 300 * 2 ** min(self.consecutive_429 - 1, 4))
            elif success:
                self.consecutive_429 = 0; self.limit = min(self.maximum, self.limit + 1)
            self.condition.notify_all()


def validate_answer(value):
    if not isinstance(value, dict) or value.get("label") not in {"present", "absent", "unknown"}:
        raise ValueError("llm_arm_label")
    if value.get("guard_position") not in {"before", "after", "racing_after", "none"}:
        raise ValueError("llm_arm_position")
    if value.get("effect_commits_under_deny") not in {True, False, "unknown"}:
        raise ValueError("llm_arm_effect")
    if not isinstance(value.get("rationale"), str) or not value["rationale"].strip():
        raise ValueError("llm_arm_rationale")
    return {key: value[key] for key in ("label", "guard_position", "effect_commits_under_deny", "rationale")}


def prepare(queue_path, split_path, out):
    queue, split = read(queue_path), read(split_path); ids = set(split["test"]["samples"])
    tasks, inputs = {}, {str(queue_path.relative_to(ROOT)): sha(queue_path),
                         str(split_path.relative_to(ROOT)): sha(split_path),
                         str(Path(__file__).resolve().relative_to(ROOT)): sha(Path(__file__).resolve()),
                         "tools/run_p0_matrix_llm_arm.py": sha(ROOT / "tools/run_p0_matrix_llm_arm.py")}
    for row in queue["rows"]:
        if row["sample_id"] not in ids: continue
        root = ROOT / "experiments/p0-clean-matrix-generate-round157-n1922/sources" / row["root"]
        sources = {}
        for path in sorted(root.glob("*.py")):
            if path.name == "matrix_effects.py": continue
            sources[path.name] = path.read_text(encoding="utf-8")[:20000]
            inputs[str(path.relative_to(ROOT))] = sha(path)
        payload = {"contract": row["contract"], "sources": sources, "framework": row["framework"]}
        tasks[row["sample_id"]] = {"payload": payload, "payload_sha256": digest(payload),
                                   "framework": row["framework"], "binding": row["binding"],
                                   "guard_position_declared": row["position"]}
    if set(tasks) != ids:
        raise ValueError("test_task_inventory")
    plan = {"schema_version": "p0-matrix-llm-arm-plan-2", "task_version": "matrix-llm-baseline-2-1",
            "created_time_ns": time.time_ns(), "side": "test", "model": MODEL,
            "prompt_sha256": digest(MATRIX_SYSTEM), "tasks": tasks, "inputs": inputs,
            "workers": 6, "completion_budgets": BUDGETS, "request_timeout_seconds": 1800,
            "temperature": 0, "max_calls": 3 * len(tasks),
            "ground_truth_read": False, "test_feedback_for_tuning": False,
            "claim_boundary": "LLM-only predictions; no GT, static wiring facts, or prior predictions in payloads."}
    out.mkdir(parents=True)
    write_new(out / "RUN_PLAN.json", plan)
    return plan


def run(out):
    plan = read(out / "RUN_PLAN.json")
    for path, expected in plan["inputs"].items():
        if sha(ROOT / path) != expected: raise ValueError("planned_input_drift:" + path)
    key = (Path.home() / ".config/guardcontract/paratera.key").read_text().strip()
    gate, counter, counter_lock = RateGate(plan["workers"]), {"calls": 0, "known_tokens": 0, "unknown": 0}, Lock()
    def one(sample_id):
        result_path = out / "results" / (sample_id + ".json")
        if result_path.is_file(): return read(result_path)
        task = plan["tasks"][sample_id]; payload = task["payload"]
        if digest(payload) != task["payload_sha256"]: raise ValueError("task_drift")
        for attempt, max_tokens in enumerate(plan["completion_budgets"]):
            directory = out / "attempts" / sample_id / f"a{attempt:03d}" / "calls"
            call = directory / "call-000"
            if not call.exists():
                request = {"model": MODEL, "temperature": 0, "thinking": REQUIRED_THINKING,
                           "max_tokens": max_tokens, "response_format": {"type": "json_object"},
                           "messages": [{"role": "system", "content": MATRIX_SYSTEM},
                                        {"role": "user", "content": json.dumps(payload, sort_keys=True)}]}
                gate.acquire(); success = False
                try:
                    transport = ScopedReviewTransport(directory, model=MODEL)
                    transport(CHAT_COMPLETIONS_ENDPOINT,
                              {"Content-Type": "application/json", "Authorization": "Bearer " + key},
                              json.dumps(request, separators=(",", ":")).encode(), plan["request_timeout_seconds"])
                    success = True
                except Exception:
                    pass
                finally:
                    error = directory / "HTTP_ERROR.json"
                    status = read(error).get("status") if error.is_file() else None
                    gate.release(status, success)
                    metadata = read(call / "CALL.json") if (call / "CALL.json").is_file() else {}
                    tokens = (metadata.get("usage") or {}).get("total_tokens")
                    with counter_lock:
                        counter["calls"] += 1
                        if type(tokens) is int: counter["known_tokens"] += tokens
                        else: counter["unknown"] += 1
            try:
                metadata, request, response = read(call / "CALL.json"), read(call / "REQUEST.raw"), read(call / "RESPONSE.raw")
                if metadata["status"] != "completed" or sha(call / "REQUEST.raw") != metadata["request_sha256"] or sha(call / "RESPONSE.raw") != metadata["response_sha256"]:
                    raise ValueError("wire_integrity")
                if digest(json.loads(request["messages"][-1]["content"])) != task["payload_sha256"] or not model_identity_matches(MODEL, response.get("model")):
                    raise ValueError("wire_identity")
                answer = validate_answer(json.loads(response["choices"][0]["message"]["content"]))
                row = {"sample_id": sample_id, "state": "completed", "answer": answer, "attempt": attempt,
                       "framework": task["framework"], "binding": task["binding"],
                       "guard_position_declared": task["guard_position_declared"],
                       "request_sha256": metadata["request_sha256"], "response_sha256": metadata["response_sha256"],
                       "tokens": (metadata.get("usage") or {}).get("total_tokens")}
                write_new(result_path, row); return row
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                continue
        return {"sample_id": sample_id, "state": "error", "reason": "bounded_attempts"}
    rows=[]
    with ThreadPoolExecutor(max_workers=plan["workers"]) as pool:
        futures={pool.submit(one,sid):sid for sid in sorted(plan["tasks"])}
        for future in as_completed(futures):
            rows.append(future.result())
            checkpoint={"seen":len(rows),"planned":len(plan["tasks"]),
                        "completed":sum(r["state"]=="completed" for r in rows),
                        "errors":sum(r["state"]!="completed" for r in rows),"budget":dict(counter)}
            temp=out/"CHECKPOINT.tmp.json";temp.write_text(json.dumps(checkpoint)+"\n");temp.replace(out/"CHECKPOINT.json")
            print(json.dumps(checkpoint),flush=True)
    result={"schema_version":"p0-matrix-llm-arm-2","side":"test","model":MODEL,
            "rows":sorted(rows,key=lambda r:r["sample_id"]),
            "counts":{"planned":len(rows),"completed":sum(r["state"]=="completed" for r in rows),
                      "errors":sum(r["state"]!="completed" for r in rows)},
            "budget":dict(counter),"prediction_blind":True,"test_feedback_for_tuning":False}
    write_new(out/"RESULT.json",result)
    write_new(out/"RUN_MANIFEST.json",{"schema_version":"p0-matrix-llm-arm-manifest-2",
        "plan_sha256":sha(out/"RUN_PLAN.json"),"result_sha256":sha(out/"RESULT.json"),
        "execution_health":"completed" if not result["counts"]["errors"] else "partial",
        "scientific_outcome":"llm_only_predictions","budget":dict(counter),"finished_time_ns":time.time_ns()})
    print(json.dumps(result["counts"],sort_keys=True))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("stage",choices=("prepare","run"))
    parser.add_argument("--queue",type=Path);parser.add_argument("--split",type=Path);parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args();out=args.out.resolve()
    if not out.is_relative_to(ROOT/"experiments"):parser.error("output must be under experiments")
    if args.stage=="prepare":
        if not args.queue or not args.split or out.exists():parser.error("prepare requires queue/split and new output")
        plan=prepare(args.queue.resolve(),args.split.resolve(),out);print(json.dumps({"tasks":len(plan["tasks"])}))
    else:run(out)


if __name__=="__main__":main()
