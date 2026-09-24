"""Audit authenticated snippets for omitted decorators of included definitions."""
import ast
import hashlib


def audit(source, evidence, path="app.py"):
    lines = source.splitlines(keepends=True)
    source_hash = hashlib.sha256(source.encode()).hexdigest()
    covered = set()
    for item in evidence.values():
        if item.get("path") != path:
            continue
        start, end = item["start_line"], item["end_line"]
        if not 1 <= start <= end <= len(lines):
            raise ValueError("snippet_span")
        content = "".join(lines[start - 1:end])
        if (item["content"] != content or item["source_sha256"] != source_hash
                or item["content_sha256"] != hashlib.sha256(content.encode()).hexdigest()):
            raise ValueError("snippet_identity")
        covered.update(range(start, end + 1))
    omissions = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if node.lineno not in covered:
            continue
        for decorator in node.decorator_list:
            missing = sorted(set(range(decorator.lineno, decorator.end_lineno + 1)) - covered)
            if missing:
                omissions.append({"definition": node.name, "definition_line": node.lineno,
                                  "decorator_start": decorator.lineno,
                                  "decorator_end": decorator.end_lineno,
                                  "missing_lines": missing})
    return {"path": path, "source_sha256": source_hash,
            "authenticated_covered_lines": sorted(covered), "omitted_decorators": omissions,
            "decorator_coverage_complete": not omissions,
            "semantic_evidence_completeness_proven": False,
            "boundary": "Decorator coverage only. Imports, receiver assignments, control flow and SDK applicability still require validation."}
