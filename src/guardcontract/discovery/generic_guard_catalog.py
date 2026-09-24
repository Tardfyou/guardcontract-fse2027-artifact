"""Framework-independent lexical guard marker inventory."""
import ast
import hashlib
from pathlib import Path
from guardcontract.evidence.slicing import EXCLUDED_PARTS

MARKERS = {"guard", "guardrail", "guardrails", "validator", "approval", "authorize", "authorization",
           "before_tool", "after_tool", "policy", "deny", "allow", "permission", "safety"}


def inventory(root, *, max_files=2000, max_file_bytes=512000):
    root=Path(root).resolve()
    if type(max_files) is not int or max_files<1 or type(max_file_bytes) is not int or max_file_bytes<1:
        raise ValueError('generic_guard_inventory_budget')
    rows=[];errors=[];seen=0
    for path in sorted(root.rglob('*.py')):
        relative=path.relative_to(root)
        if seen>=max_files:break
        if path.is_symlink() or not path.is_file() or any(p in EXCLUDED_PARTS for p in relative.parts):continue
        seen+=1
        try:
            raw=path.read_bytes()
            if len(raw)>max_file_bytes:raise ValueError('source_byte_budget')
            tree=ast.parse(raw.decode('utf-8-sig'),filename=str(path)); digest=hashlib.sha256(raw).hexdigest()
            for node in ast.walk(tree):
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                    names=[node.name.lower(),*(getattr(d,'id','').lower() for d in getattr(node,'decorator_list',[]))]
                    matched=sorted({marker for marker in MARKERS if any(marker in name for name in names)})
                    if matched: rows.append({'path':relative.as_posix(),'line':node.lineno,'symbol':node.name,'markers':matched,'source_sha256':digest,'binding_status':'unbound_guard_marker','scope_status':'unknown'})
        except (OSError,UnicodeError,SyntaxError,ValueError) as exc:errors.append({'path':relative.as_posix(),'error_kind':type(exc).__name__})
    return {'schema_version':'generic-guard-catalog-1','guards':rows,'errors':errors,'scanned_files':seen,'claim_boundary':'Lexical guard marker candidates only; no framework registration, policy obligation, effect relation, runtime or issue claim.'}
