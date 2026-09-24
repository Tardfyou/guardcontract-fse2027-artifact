"""Inventory candidate side-effect call signatures without source excerpts."""
import ast
from collections import Counter,defaultdict
from pathlib import Path
TERMINALS={"open","write","write_text","write_bytes","unlink","remove","rename","replace","mkdir","rmdir","copy","move","get","post","put","patch","delete","request","send","send_message","sendmail","publish","execute","executemany","commit","add","insert","update","upload","upload_file","put_object","put_item","save","run","invoke","query","search","scrape","browse","navigate","click"}
MODELED={"open","remove","rename","replace","rmdir","copy","move","post","put","patch","delete","send","send_message","sendmail","publish","execute","executemany","commit","upload","upload_file","put_object","put_item","unlink","mkdir"}
def dotted(node):
    if isinstance(node,ast.Name):return node.id
    if isinstance(node,ast.Attribute):
        base=dotted(node.value);return base+"."+node.attr if base else node.attr
    return None
def scan(frame,materialization,max_files=5000,max_bytes=1048576):
    roots={r["repository"]:Path(r["destination"]) for r in materialization["repositories"] if r["status"]=="completed"};counts=Counter();repositories=defaultdict(set);errors=Counter()
    for selected in frame["selected"]:
        name=selected["repository"]["full_name"];framework=selected["framework"];files=sorted(p for p in roots[name].rglob("*.py") if p.is_file() and not p.is_symlink() and ".git" not in p.parts)[:max_files]
        for path in files:
            if path.stat().st_size>max_bytes:errors["size"]+=1;continue
            try:tree=ast.parse(path.read_bytes())
            except (SyntaxError,UnicodeError,OSError):errors["parse"]+=1;continue
            for call in (n for n in ast.walk(tree) if isinstance(n,ast.Call)):
                name_call=dotted(call.func);terminal=name_call.rsplit(".",1)[-1] if name_call else ""
                if terminal in TERMINALS:
                    key=(framework,name_call);counts[key]+=1;repositories[key].add(name)
    signatures=[{"framework":f,"call":call,"terminal":call.rsplit(".",1)[-1],"occurrences":count,"repositories":len(repositories[(f,call)]),"current_terminal_model":call.rsplit(".",1)[-1] in MODELED} for (f,call),count in counts.items()]
    signatures.sort(key=lambda r:(not r["current_terminal_model"],-r["repositories"],-r["occurrences"],r["framework"],r["call"]));return {"schema_version":"effect-gap-inventory-1","signatures":signatures,"counts":{"candidate_signatures":len(signatures),"candidate_calls":sum(r["occurrences"] for r in signatures),"repositories_with_candidates":len(set().union(*repositories.values())) if repositories else 0,"modeled_signatures":sum(r["current_terminal_model"] for r in signatures),"unmodeled_signatures":sum(not r["current_terminal_model"] for r in signatures),"errors":dict(errors)},"candidate_terminals":sorted(TERMINALS),"modeled_terminals":sorted(MODELED),"source_content_persisted":False,"repository_code_executed":False}
