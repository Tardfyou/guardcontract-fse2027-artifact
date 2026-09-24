"""Development-only Python redaction that never emits broken source syntax.

Secret-bearing literal values become opaque strings. Calls, environment-variable
lookups, operators and identifiers remain intact. Masked values cannot support
semantic proofs. Invalid input is withheld, never returned unredacted.
"""
import ast
import copy
import re


SENSITIVE = re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|password|passwd|secret|authorization)")
TOKEN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9+/=_-]{32,}(?![A-Za-z0-9])|(?i:Bearer)\s+[A-Za-z0-9._~+/=-]{8,}")
EMBEDDED = re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|password|passwd|secret|authorization)\s*[:=]\s*\S+")


def redact_python(source):
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return {"source": "# SOURCE_WITHHELD: input is not a complete Python syntax unit\n",
                "status": "withheld", "redactions": 0, "reason": "input_parse_failed"}
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    masked = {}
    partial = {}
    metadata_literals = set()
    field_names={a.asname or a.name for n in tree.body if isinstance(n,ast.ImportFrom)
                 and n.module in {'pydantic','pydantic.v1'} for a in n.names if a.name=='Field'}
    field_names.update((a.asname or a.name)+'.Field' for n in tree.body if isinstance(n,ast.Import)
                       for a in n.names if a.name=='pydantic')
    field_names.update({'pydantic.Field','pydantic.v1.Field'})
    fstrings={}

    def name(n):
        if isinstance(n, ast.Name):
            return n.id
        if isinstance(n, ast.Attribute):
            return name(n.value) + "." + n.attr
        if isinstance(n, ast.Subscript):
            return n.slice.value if isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str) else ""
        return ""

    def is_environment_lookup(n):
        return isinstance(n, ast.Call) and name(n.func) in {"os.getenv", "os.environ.get"}

    def is_field_label(n):
        return (isinstance(n, ast.Constant) and isinstance(n.value, str) and
                re.fullmatch(r"(?i)(?:[a-z_][a-z0-9_-]*[_-])?(?:api[_-]?key|access[_-]?key(?:[_-]?id)?|password|passwd|secret|authorization)", n.value) is not None)

    def is_field_lookup(n):
        return (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and
                n.func.attr in {"get", "pop", "setdefault"} and n.args and is_field_label(n.args[0]))

    def mask_values(expr):
        if isinstance(expr, ast.Constant) and (expr.value is None or type(expr.value) is bool):
            return  # Boolean policy flags are not credential material.
        if is_environment_lookup(expr) or is_field_lookup(expr):
            # The key names the environment variable; a literal fallback may
            # itself be a secret, so only the lookup's first argument is exempt.
            for arg in expr.args[1:]:
                mask_values(arg)
            for kw in expr.keywords:
                if kw.arg != "key":
                    mask_values(kw.value)
            return
        if isinstance(expr, ast.Subscript) and (name(expr.value) == "os.environ" or is_field_label(expr.slice)):
            return
        if isinstance(expr,ast.Call) and name(expr.func) in field_names:
            for arg in expr.args:mask_values(arg)
            for kw in expr.keywords:
                if kw.arg in {'alias','validation_alias','serialization_alias'} and isinstance(kw.value,ast.Constant) and isinstance(kw.value.value,str):
                    metadata_literals.add(id(kw.value))
                else:mask_values(kw.value)
            return
        if isinstance(expr, ast.JoinedStr):
            masked[id(expr)] = expr
            fstrings[id(expr)]='sensitive'
            return
        if isinstance(expr, ast.Constant) and expr.value is not None:
            masked[id(expr)] = expr
            return
        for child in ast.iter_child_nodes(expr):
            mask_values(child)

    for n in ast.walk(tree):
        if is_environment_lookup(n) and n.args and isinstance(n.args[0], ast.Constant): metadata_literals.add(id(n.args[0]))
        if is_field_lookup(n): metadata_literals.add(id(n.args[0]))
        if isinstance(n, ast.Subscript) and (name(n.value) == "os.environ" or is_field_label(n.slice)): metadata_literals.add(id(n.slice))
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            parent = parents.get(id(n))
            labels = []
            if isinstance(parent, ast.keyword): labels = [parent.arg or ""]
            elif isinstance(parent, (ast.Assign, ast.AnnAssign)):
                labels = [name(t) for t in (parent.targets if isinstance(parent, ast.Assign) else [parent.target])]
            # Public model names are metadata only in a model-identity position;
            # the same literal in an api_key/password position stays secret.
            if (any(re.search(r"(?i)(?:^|_)model(?:_name|_id)?$", label) for label in labels) and
                    re.fullmatch(r"(?:gemini-|gpt-|claude-|ollama[:/])[A-Za-z0-9._:/-]+", n.value)):
                metadata_literals.add(id(n))

    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            if n.value and any(SENSITIVE.search(name(t)) for t in targets):
                mask_values(n.value)
        elif isinstance(n, ast.keyword) and n.arg and SENSITIVE.search(n.arg):
            mask_values(n.value)
        elif isinstance(n, ast.Dict):
            for key, value in zip(n.keys, n.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str) and SENSITIVE.search(key.value):
                    mask_values(value)
        elif isinstance(n, ast.Constant) and isinstance(n.value, (str, bytes)):
            value = n.value.decode("ascii", "ignore") if isinstance(n.value, bytes) else n.value
            if id(n) not in metadata_literals and (TOKEN.search(value) or EMBEDDED.search(value)):
                parent = parents.get(id(n))
                if isinstance(parent, ast.JoinedStr):
                    masked[id(parent)] = parent
                    fstrings.setdefault(id(parent),'partial')
                else:
                    partial[id(n)] = n
    # Redact secret-bearing comments without deleting ordinary policy prose.
    import io
    import tokenize
    raw = source.encode("utf-8")
    lines = raw.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    spans = []
    for node_id, n in {**partial, **masked}.items():
        start = offsets[n.lineno-1] + n.col_offset
        end = offsets[n.end_lineno-1] + n.end_col_offset
        replacement = b"('<REDACTED>'" + b"\n" * (n.end_lineno-n.lineno) + b")"
        if node_id in fstrings:
            # Preserve only passive symbol interpolation. Calls, format-spec
            # expressions and arbitrary subscripts remain opaque.
            def passive(expr):
                return isinstance(expr,ast.Name) or (isinstance(expr,ast.Attribute) and passive(expr.value))
            values=[v for v in n.values if isinstance(v,ast.FormattedValue)]
            if all(passive(v.value) and v.format_spec is None for v in values):
                clean=copy.deepcopy(n)
                for value in clean.values:
                    if not isinstance(value,ast.Constant) or not isinstance(value.value,str):continue
                    if fstrings[node_id]=='sensitive':
                        value.value=value.value if value.value in {'','Bearer ','Basic '} else '<REDACTED>'
                    else:value.value=EMBEDDED.sub('<REDACTED>',TOKEN.sub('<REDACTED>',value.value))
                rendered=ast.unparse(clean)
                if '\n' not in rendered:
                    replacement=('('+rendered+'\n'*(n.end_lineno-n.lineno)+')').encode('utf-8')
        if node_id not in masked:
            # Keep surrounding policy prose and original source line locations.
            fragment = raw[start:end].decode("utf-8")
            def replace_match(match):
                value = match[0]
                suffix = value[len(value.rstrip("'\"")):]
                return "<REDACTED>" + "\n" * value.count("\n") + suffix
            cleaned = EMBEDDED.sub(replace_match, TOKEN.sub(replace_match, fragment))
            try:
                value = ast.literal_eval(cleaned)
                checked = value.decode("ascii", "ignore") if isinstance(value, bytes) else value
                checked = checked.replace("<REDACTED>", "")
                if (type(value) is type(n.value) and cleaned.count("\n") == fragment.count("\n") and
                        not TOKEN.search(checked) and not EMBEDDED.search(checked)):
                    replacement = cleaned.encode("utf-8")
            except (ValueError, SyntaxError, TypeError, AttributeError):
                pass  # Escaped/concatenated secrets remain fully opaque.
        spans.append((start, end, replacement))
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT and (TOKEN.search(token.string) or EMBEDDED.search(token.string)):
            row, col = token.start
            endrow, endcol = token.end
            start = offsets[row-1] + len(lines[row-1].decode().splitlines()[0][:col].encode())
            end = offsets[endrow-1] + len(lines[endrow-1].decode().splitlines()[0][:endcol].encode())
            spans.append((start, end, b"# comment omitted"))
    # Prefer the enclosing f-string over child literal spans.
    selected = []
    for span in sorted(spans, key=lambda x: (x[0], -x[1])):
        if selected and span[0] < selected[-1][1]:
            continue
        selected.append(span)
    for start, end, replacement in reversed(selected):
        raw = raw[:start] + replacement + raw[end:]
    output = raw.decode("utf-8")
    try:
        ast.parse(output)
    except SyntaxError:
        return {"source": "# SOURCE_WITHHELD: sanitized source did not parse\n",
                "status": "withheld", "redactions": len(set(masked) | set(partial)), "reason": "output_parse_failed"}
    return {"source": output, "status": "sanitized", "redactions": len(set(masked) | set(partial)),
            "semantic_masking": bool(masked or partial), "masked_values_are_unknown": True,
            "schema_version": "python-redaction-dev-3"}
