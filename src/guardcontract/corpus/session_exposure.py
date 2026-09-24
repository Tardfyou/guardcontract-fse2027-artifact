"""Privacy-preserving exact repository mention scan over session byte prefixes."""
from collections import deque
import hashlib
import json


def review_events(patterns, snapshot, root):
    """Locate matching events in authenticated prefixes without copying content."""
    from collections import Counter, defaultdict
    from pathlib import Path

    machine = automaton(patterns)
    channels = defaultdict(Counter)
    events = []
    root = Path(root).resolve()
    for row in snapshot["session_prefixes"]:
        path = (root / row["path"]).resolve()
        if not path.is_relative_to(root):
            raise ValueError("session_prefix_path")
        with path.open("rb") as handle:
            data = handle.read(row["prefix_bytes"])
        if len(data) != row["prefix_bytes"] or hashlib.sha256(data).hexdigest() != row["prefix_sha256"]:
            raise ValueError("session_prefix_changed")
        for line_number, line in enumerate(data.splitlines(keepends=True), 1):
            hits = scan(line, machine)
            if not hits:
                continue
            try:
                event = json.loads(line)
                payload = event.get("payload", {})
                kind = payload.get("type") if isinstance(payload, dict) else None
                role = payload.get("role") if isinstance(payload, dict) else None
                if event.get("type") == "response_item":
                    if kind in {"function_call", "custom_tool_call"}:
                        channel = "tool_call"
                    elif kind in {"function_call_output", "custom_tool_call_output"}:
                        channel = "tool_output"
                    elif kind == "message" and role in {"user", "assistant", "developer", "system"}:
                        channel = role + "_message"
                    elif kind == "reasoning":
                        channel = "reasoning"
                    else:
                        channel = "other_response"
                else:
                    channel = "other_event"
            except (ValueError, AttributeError):
                channel = "unparsed_matching_event"
            for name in hits:
                channels[name][channel] += 1
            events.append({"session_path": row["path"], "line": line_number,
                           "event_sha256": hashlib.sha256(line).hexdigest(),
                           "channel": channel, "repositories": sorted(hits)})
    return {"schema_version": "session-event-review-1", "events": events,
            "repository_channels": {name: dict(sorted(channels[name].items())) for name in sorted(patterns)},
            "counts": {"matching_events": len(events), "channels": dict(Counter(e["channel"] for e in events)),
                       "repositories_with_tool_call_mentions": sum(bool(channels[name]["tool_call"]) for name in patterns)},
            "content_persisted": False, "mention_interpretation": "review_candidates_only",
            "holdout_admission_authorized": False, "goal_completion_proven": False,
            "claim_boundary": "Event locations for semantic review only. A tool call can inspect metadata or create a plan; a tool output can contain a candidate list. Neither proves source exposure. Unmatched names and path aliases remain unaudited."}
def automaton(patterns):
    goto=[{}];fail=[0];outputs=[set()]
    for pattern in sorted(set(patterns)):
        node=0
        for byte in pattern.encode():
            if byte not in goto[node]:goto[node][byte]=len(goto);goto.append({});fail.append(0);outputs.append(set())
            node=goto[node][byte]
        outputs[node].add(pattern)
    queue=deque(goto[0].values())
    while queue:
        parent=queue.popleft()
        for byte,child in goto[parent].items():
            queue.append(child);fallback=fail[parent]
            while fallback and byte not in goto[fallback]:fallback=fail[fallback]
            fail[child]=goto[fallback].get(byte,0);outputs[child].update(outputs[fail[child]])
    return goto,fail,outputs
def scan(data,machine):
    goto,fail,outputs=machine;node=0;found=set()
    for byte in data:
        while node and byte not in goto[node]:node=fail[node]
        node=goto[node].get(byte,0)
        if outputs[node]:found.update(outputs[node])
    return found
def build(patterns,files,root):
    machine=automaton(patterns);rows=[];mentioned=set()
    for path in sorted(files):
        size=path.stat().st_size
        with path.open("rb") as handle:data=handle.read(size)
        hits=scan(data,machine);mentioned.update(hits);rows.append({"path":str(path.relative_to(root)),"prefix_bytes":len(data),"prefix_sha256":hashlib.sha256(data).hexdigest(),"mentioned_repositories":len(hits)})
    return {"schema_version":"session-exposure-prefix-scan-1","session_prefixes":rows,"mentioned_repositories":sorted(mentioned),"counts":{"session_files":len(rows),"prefix_bytes":sum(r["prefix_bytes"] for r in rows),"mentioned_repositories":len(mentioned)},"content_persisted":False,"session_prefix_inventory_complete":True,"claim_boundary":"Exact repository-name mentions in immutable byte prefixes are conservatively treated as exposure. No session content is copied. Bytes appended after each prefix are outside this snapshot."}


def main():
    """Recheck pending identities without admitting or discarding a holdout."""
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--session-root", type=Path, default=Path.home() / ".codex")
    parser.add_argument("--review-snapshot", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("session_audit_output_exists")
    raw = args.ledger.read_bytes()
    ledger = json.loads(raw)
    names = [row["full_name"] for row in ledger["pending_representatives"]]
    if not names or len(names) != len(set(names)) or any(not isinstance(name, str) or "/" not in name for name in names):
        raise ValueError("pending_repository_inventory")
    if args.review_snapshot is not None:
        snapshot_raw = args.review_snapshot.read_bytes()
        snapshot = json.loads(snapshot_raw)
        if snapshot.get("source_ledger_sha256") != hashlib.sha256(raw).hexdigest():
            raise ValueError("session_review_ledger_mismatch")
        result = review_events(names, snapshot, args.session_root)
        result.update(source_ledger_sha256=hashlib.sha256(raw).hexdigest(),
                      snapshot_sha256=hashlib.sha256(snapshot_raw).hexdigest(),
                      implementation_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(json.dumps(result["counts"]))
        return
    if not (args.session_root / "sessions").is_dir():
        raise ValueError("session_inventory_missing")
    files = sorted([*args.session_root.glob("sessions/**/*.jsonl"),
                    *args.session_root.glob("archived_sessions/**/*.jsonl")])
    if not files:
        raise ValueError("session_inventory_empty")
    result = build(names, files, args.session_root)
    mentioned = set(result["mentioned_repositories"])
    result.update(
        source_ledger=str(args.ledger),
        source_ledger_sha256=hashlib.sha256(raw).hexdigest(),
        implementation_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        potential_exposure_review_queue=sorted(mentioned),
        mention_interpretation="review_candidates_only",
        no_exact_name_mention=sorted(set(names) - mentioned),
        input_repositories=len(names),
        holdout_admission_authorized=False,
        goal_completion_proven=False,
        claim_boundary="Name mentions are review candidates, not proof of source exposure. Absence does not exclude path aliases, omitted sessions, or near-copy exposure. Local byte prefixes only; no holdout admission or source-level exclusion is authorized.",
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({**result["counts"], "input_repositories": len(names),
                      "without_exact_name_mention": len(names) - len(mentioned)}))


if __name__ == "__main__":
    main()
