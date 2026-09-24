"""Recover bounded lexical call context from explicitly registered Python files."""
import ast
from collections import defaultdict
import hashlib


def call_context(sources, edges, padding=3, header_lines=25, max_lines=500):
    indexes, lines = defaultdict(list), {}
    for path, raw in sources.items():
        text = raw.decode("utf-8-sig")
        lines[path] = text.splitlines(keepends=True)
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                indexes[node.name].append((path, node))
    ranges, records = defaultdict(list), []
    for caller, callee in edges:
        candidates = indexes.get(caller, [])
        if len(candidates) != 1:
            records.append({"caller": caller, "callee": callee, "status": "missing_or_ambiguous_caller"})
            continue
        path, node = candidates[0]
        calls = [n for n in ast.walk(node) if isinstance(n, ast.Call)
                 and (isinstance(n.func, ast.Name) and n.func.id == callee
                      or isinstance(n.func, ast.Attribute) and n.func.attr == callee)]
        if not calls:
            records.append({"caller": caller, "callee": callee, "status": "call_not_found"})
            continue
        ranges[path].append((node.lineno, min(node.end_lineno, node.lineno + header_lines - 1)))
        for call in calls:
            ranges[path].append((max(node.lineno, call.lineno - padding), min(node.end_lineno, call.end_lineno + padding)))
        records.append({"caller": caller, "callee": callee, "status": "lexical_call_found", "path": path,
                        "call_lines": [c.lineno for c in calls], "reachable_call_proven": False})
    excerpts, count = [], 0
    for path, intervals in sorted(ranges.items()):
        merged = []
        for start, end in sorted(intervals):
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        for start, end in merged:
            if count + end - start + 1 > max_lines:
                return {"status": "budget_exceeded", "records": records, "evidence": excerpts, "lines": count}
            count += end - start + 1
            excerpts.append({"path": path, "start_line": start, "end_line": end,
                             "file_sha256": hashlib.sha256(sources[path]).hexdigest(),
                             "content": "".join(lines[path][start - 1:end])})
    return {"status": "completed" if all(r["status"] == "lexical_call_found" for r in records) else "partial",
            "records": records, "evidence": excerpts, "lines": count}
