"""Move only DENY enforcement before an ADK tool while preserving ALLOW order."""
import ast, hashlib

from guardcontract.analysis.adk_paths import analyze
from guardcontract.analysis.langchain_paths import dotted, function


def sha(source): return hashlib.sha256(source.encode()).hexdigest()


def propose(source, certificate, sdk_contract):
    if certificate.get("status") != "supported" or certificate.get("mode") != "after_tool" or certificate.get("issue_prediction") is not True or certificate.get("source_sha256") != sha(source):
        raise ValueError("adk_repair_requires_verified_after_tool_issue")
    tree = ast.parse(source); run = function(tree, "_run_cell")
    before = function(run, "before_tool_callback"); after = function(run, "after_tool_callback")
    before_returns = [row for row in before.body if isinstance(row, ast.Return) and isinstance(row.value, ast.Constant) and row.value.value is None]
    after_returns = [row for row in after.body if isinstance(row, ast.Return) and isinstance(row.value, ast.Call) and dotted(row.value.func) == "decide"]
    if len(before_returns) != 1 or len(after_returns) != 1:
        raise ValueError("adk_repair_callback_shape")
    lines = source.splitlines(keepends=True)
    edits = [
        {"kind": "deny_before_tool", "line": before_returns[0].lineno,
         "replacement": "        return decide(args) if verdict == 'DENY' else None\n"},
        {"kind": "allow_after_tool", "line": after_returns[0].lineno,
         "replacement": "        return decide(args) if verdict == 'ALLOW' else None\n"},
    ]
    for edit in edits: lines[edit["line"] - 1] = edit["replacement"]
    patched = "".join(lines); ast.parse(patched)
    post = analyze(patched, sdk_contract, repository_id="adk-repair@" + sha(patched))
    if post.get("status") != "supported" or post.get("mode") != "split_guard" or post.get("issue_prediction") is not False:
        raise ValueError("adk_repair_static_validation")
    return {"schema_version": "adk-placement-repair-1", "strategy": "deny_before_allow_after",
        "original_sha256": sha(source), "patched_sha256": sha(patched), "edits": edits,
        "patched_source": patched, "static_postcondition": post, "generated_patch": True, "runtime_verified": False}
