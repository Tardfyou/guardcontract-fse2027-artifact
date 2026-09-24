"""Measure exact target-framework imports without retaining source content."""
import ast
from collections import Counter
from pathlib import Path
ROOTS={"langchain":{"langchain","langgraph"},"google-adk":{"google.adk"},"pydantic-ai":{"pydantic_ai"},"openai-agents":{"agents"},"crewai":{"crewai"}}
def imported(tree):
    names=set()
    for node in ast.walk(tree):
        if isinstance(node,ast.Import):names.update(a.name for a in node.names)
        elif isinstance(node,ast.ImportFrom) and node.module:names.add(node.module)
    return names
def matches(names,roots):return any(name==root or name.startswith(root+".") for name in names for root in roots)
def scan(frame,materialization,max_files=5000,max_bytes=1048576):
    roots={r["repository"]:Path(r["destination"]) for r in materialization["repositories"] if r["status"]=="completed"};rows=[]
    for selected in frame["selected"]:
        repo=selected["repository"]["full_name"];framework=selected["framework"];files=sorted(p for p in roots[repo].rglob("*.py") if p.is_file() and not p.is_symlink() and ".git" not in p.parts);truncated=len(files)>max_files;files=files[:max_files];matched=parsed=errors=0
        for path in files:
            if path.stat().st_size>max_bytes:errors+=1;continue
            try:tree=ast.parse(path.read_bytes())
            except (SyntaxError,UnicodeError,OSError):errors+=1;continue
            parsed+=1;matched+=matches(imported(tree),ROOTS[framework])
        rows.append({"repository":repo,"framework":framework,"python_files":len(files),"parsed_files":parsed,"parse_or_size_errors":errors,"matching_import_files":matched,"framework_import_present":matched>0,"scan_truncated":truncated})
    return {"schema_version":"framework-import-yield-1","rows":rows,"counts":{"repositories":len(rows),"framework_import_present":sum(r["framework_import_present"] for r in rows),"by_framework":{f:{"repositories":sum(r["framework"]==f for r in rows),"import_present":sum(r["framework"]==f and r["framework_import_present"] for r in rows)} for f in ROOTS},"parse_or_size_errors":sum(r["parse_or_size_errors"] for r in rows),"truncated_repositories":sum(r["scan_truncated"] for r in rows)},"source_content_persisted":False,"repository_code_executed":False}
