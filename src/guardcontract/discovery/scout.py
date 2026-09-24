from __future__ import annotations

import ast
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from guardcontract.evidence.slicing import EXCLUDED_PARTS
from guardcontract.evidence.validation import safe_relative_path


GUARD_MARKERS = (
    "input_guardrail", "output_guardrail", "tool_input_guardrail", "tool_output_guardrail",
    "guardrail=", "guardrails=", "before_tool_callback", "after_tool_callback",
    "before_tool_call", "after_tool_call", "wrap_tool_call", "output_validator", "result_validator",
    "request_confirmation", "needs_approval",
)
GUARD_KEYWORDS = {
    "input_guardrail", "input_guardrails", "output_guardrail", "output_guardrails",
    "tool_input_guardrail", "tool_input_guardrails", "tool_output_guardrail", "tool_output_guardrails",
    "guardrail", "guardrails", "before_tool_callback", "after_tool_callback",
    "before_model_callback", "after_model_callback", "before_tool_call", "after_tool_call",
    "output_validator", "output_validators", "result_validator", "result_validators",
    "needs_approval", "request_confirmation",
}
EFFECT_TEXT_MARKERS = (
    "requests.", "httpx.", "aiohttp.", "urllib.request.", "socket.",
    "sendmail(", "send_message(", "send_email(", "send_mail(",
    "subprocess.", "os.system(", "create_subprocess_", ".write_text(",
    ".write_bytes(", "open(", ".commit(", ".insert_one(", ".update_one(",
    ".delete_one(", ".click(", ".goto(",
)


@dataclass(frozen=True)
class EffectSite:
    path: str
    line: int
    family: str
    call: str


@dataclass(frozen=True)
class ScoutCandidate:
    guard_path: str
    guard_line: int
    guard_marker: str
    effect: EffectSite
    guard_definition: tuple[str, int] | None = None

    @property
    def path(self) -> str:
        return self.guard_path


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _path_like_receiver(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        return _dotted_name(node.func).rsplit(".",1)[-1] in {"Path","PurePath","PurePosixPath","PureWindowsPath"}
    name=_dotted_name(node).lower().rsplit(".",1)[-1]
    return name in {"path","file_path","target_path","directory","folder"} or name.endswith(("_path","_dir"))


def classify_effect_call(call: ast.Call, origin=None) -> tuple[str, str] | None:
    name = _dotted_name(call.func)
    lower = name.lower()
    leaf = lower.rsplit(".", 1)[-1]
    http_methods = {"get", "post", "put", "patch", "delete", "request", "head",
                    "options", "stream", "urlopen", "urlretrieve"}
    if (lower.startswith(("requests.", "httpx.", "aiohttp.", "urllib.request."))
            and leaf in http_methods):
        return "network", name
    if leaf in {"sendmail", "send_message", "send_email", "send_mail", "publish_message"}:
        return "message", name
    if lower.startswith("subprocess.") or lower in {"os.system", "os.popen", "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell"}:
        return "subprocess", name
    if leaf in {"write_text", "write_bytes"} or lower in {"os.remove", "os.unlink", "os.rename", "shutil.rmtree", "shutil.move"}:
        return "filesystem", name
    if leaf in {"unlink","rmdir","rename"} and isinstance(call.func,ast.Attribute) and _path_like_receiver(call.func.value):
        return "filesystem", name
    if name in {"open", "io.open"}:
        mode = None
        if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
            mode = call.args[1].value
        for keyword in call.keywords:
            if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                mode = keyword.value.value
        if isinstance(mode, str) and any(flag in mode for flag in "wax+"):
            return "filesystem", name
    if leaf in {"commit", "rollback", "insert_one", "update_one", "update_many", "delete_one", "delete_many", "executemany"}:
        return "database", name
    if leaf in {"click", "goto", "navigate", "submit", "press"} and any(part in lower for part in ("page.", "browser.", "driver.")):
        return "browser", name
    resolved = origin(call.func.value) if origin and isinstance(call.func, ast.Attribute) else None
    if (leaf in {"get", "post", "put", "patch", "delete", "request", "send"}
            and isinstance(resolved, str)
            and resolved in {"httpx.Client", "httpx.AsyncClient", "requests.Session",
                             "aiohttp.ClientSession"}):
        return "network", name
    if (leaf in {"connect", "connect_ex", "send", "sendall", "sendto"}
            and resolved == "socket.socket"):
        return "network", name
    if leaf == "execute" and isinstance(resolved, str) and resolved.startswith("googleapiclient.discovery.build"):
        return "network", name
    return None


def effect_sites_from_tree(tree: ast.AST, path: str, *, within: ast.AST | None = None,
                           origin_resolver=None) -> list[EffectSite]:
    scope = within or tree
    sites = []
    def nodes():
        pending = [scope]
        while pending:
            node = pending.pop()
            yield node
            if within is not None and node is not scope and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                # Definition-time expressions execute in the enclosing scope;
                # the nested callable body needs a separately resolved call edge.
                pending.extend(node.args.defaults)
                pending.extend(x for x in node.args.kw_defaults if x is not None)
                pending.extend(getattr(node, "decorator_list", []))
                continue
            pending.extend(ast.iter_child_nodes(node))
    all_nodes=list(nodes())
    imports={}
    module_body=getattr(tree,"body",[])
    for node in module_body:
        if isinstance(node,ast.ImportFrom) and node.module:
            for alias in node.names:imports[alias.asname or alias.name]=node.module+"."+alias.name
        elif isinstance(node,ast.Import):
            for alias in node.names:imports[alias.asname or alias.name.split(".")[0]]=alias.name
    assignments={}
    for node in all_nodes:
        if isinstance(node,(ast.Assign,ast.AnnAssign)):
            targets=node.targets if isinstance(node,ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target,ast.Name):assignments.setdefault(target.id,[]).append(node.value)
    def local_origin(node,seen=frozenset()):
        if isinstance(node,ast.Name):
            if node.id in imports:return imports[node.id]
            values=assignments.get(node.id,[])
            if len(values)==1 and node.id not in seen:return local_origin(values[0],seen|{node.id})
            return None
        if isinstance(node,ast.Attribute):
            base=local_origin(node.value,seen);return f"{base}.{node.attr}" if base else None
        if isinstance(node,ast.Call):return local_origin(node.func,seen)
        return None
    origin = origin_resolver or local_origin
    for node in all_nodes:
        if not isinstance(node, ast.Call):
            continue
        classified = classify_effect_call(node,origin)
        if classified is not None and isinstance(getattr(node, "lineno", None), int):
            family, name = classified
            sites.append(EffectSite(path, node.lineno, family, name))
    return sorted(set(sites), key=lambda item: (item.line, item.family, item.call))


def effect_sites_in_function(root: Path, relative_path: str, definition_line: int) -> list[EffectSite]:
    relative = safe_relative_path(relative_path)
    target = root.joinpath(*relative.parts)
    if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root.resolve()):
        return []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(target.read_text(encoding="utf-8"), filename=relative_path)
    except (OSError, UnicodeError, SyntaxError):
        return []
    functions = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= definition_line <= getattr(node, "end_lineno", node.lineno)
    ]
    if not functions:
        return []
    function = min(functions, key=lambda node: getattr(node, "end_lineno", node.lineno) - node.lineno)
    return effect_sites_from_tree(tree, relative_path, within=function)


def _python_files(root: Path, *, include_tests: bool, max_files: int) -> Iterable[tuple[str, Path]]:
    count = 0
    for target in sorted(root.rglob("*.py")):
        if count >= max_files:
            return
        try:
            relative = target.relative_to(root).as_posix()
        except ValueError:
            continue
        parts = target.relative_to(root).parts
        if target.is_symlink() or not target.resolve().is_relative_to(root) or any(part in EXCLUDED_PARTS for part in parts):
            continue
        lowered = relative.lower()
        if not include_tests and (lowered.startswith("test") or "/test" in "/" + lowered):
            continue
        count += 1
        yield relative, target


def _symbol_names(node: ast.AST) -> list[str]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = []
        for item in node.elts:
            values.extend(_symbol_names(item))
        return values
    name = _dotted_name(node)
    return [name] if name else []


def _bound_guard_calls(tree: ast.AST) -> list[tuple[int, str, list[str], list[str]]]:
    rows = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(getattr(node, "lineno", None), int):
            continue
        keywords = {item.arg: item.value for item in node.keywords if item.arg}
        guard_names = sorted(name for name in keywords if name.lower() in GUARD_KEYWORDS)
        tool_values = [value for name, value in keywords.items() if name.lower() in {"tools", "functions", "toolsets"}]
        if not guard_names or not tool_values:
            continue
        tools = []
        for value in tool_values:
            tools.extend(_symbol_names(value))
        if tools:
            guards = []
            for name in guard_names:
                guards.extend(_symbol_names(keywords[name]))
            marker = "+".join(guard_names)
            if guards:
                marker += ":" + ",".join(dict.fromkeys(guards))
            rows.append((node.lineno, marker, list(dict.fromkeys(tools)), list(dict.fromkeys(guards))))
    return rows


def _module_name(path: str) -> str:
    value = path[:-3] if path.endswith(".py") else path
    if value.endswith("/__init__"):
        value = value[: -len("/__init__")]
    return value.replace("/", ".")


def _import_bindings(tree: ast.AST) -> dict[str, tuple[str, str | None]]:
    bindings = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                bindings[alias.asname or alias.name] = (node.module, alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                bindings[alias.asname or alias.name.split(".", 1)[0]] = (alias.name, None)
    return bindings


def discover_repository_candidates(
    root: Path,
    *,
    include_tests: bool = False,
    max_files: int = 2000,
    max_file_bytes: int = 512_000,
    max_candidates: int = 20,
) -> list[ScoutCandidate]:
    parsed: list[tuple[str, str, ast.AST]] = []
    definitions: dict[tuple[str, str], list[EffectSite]] = {}
    function_lines: dict[tuple[str, str], int] = {}
    module_paths: dict[str, list[str]] = {}
    resolved_root = root.resolve()
    for path, target in _python_files(resolved_root, include_tests=include_tests, max_files=max_files):
        try:
            raw = target.read_bytes()
            if len(raw) > max_file_bytes:
                continue
            text = raw.decode("utf-8")
            module_paths.setdefault(_module_name(path), []).append(path)
            compact = text.lower().replace(" ", "")
            possible_guard_config = any(marker.replace(" ", "") in compact for marker in GUARD_MARKERS) and any(token in compact for token in ("tools=", "functions=", "toolsets="))
            possible_effect = any(marker in compact for marker in EFFECT_TEXT_MARKERS)
            if not possible_guard_config and not possible_effect:
                continue
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(text, filename=path)
        except (OSError, UnicodeError, SyntaxError):
            continue
        parsed.append((path, text, tree))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            function_lines[(path, node.name)] = node.lineno
            effects = effect_sites_from_tree(tree, path, within=node)
            if effects:
                definitions.setdefault((path, node.name), []).extend(effects)

    candidates: list[ScoutCandidate] = []
    seen: set[tuple[str, int, str, int]] = set()

    def resolve_symbol(symbol: str, source_path: str, imports: dict[str, tuple[str, str | None]]) -> tuple[str, str] | None:
        leaf = symbol.rsplit(".", 1)[-1]
        if (source_path, leaf) in function_lines:
            return source_path, leaf
        local = symbol.split(".", 1)[0]
        imported = imports.get(local)
        if imported is not None:
            module, imported_symbol = imported
            target_leaf = imported_symbol or leaf
            matches = [target for key, paths in module_paths.items() if key == module or key.endswith("." + module) for target in paths]
            if len(matches) == 1 and (matches[0], target_leaf) in function_lines:
                return matches[0], target_leaf
        if "." in symbol and imported is None:
            module = symbol.rsplit(".", 1)[0]
            matches = [target for key, paths in module_paths.items() if key == module or key.endswith("." + module) for target in paths]
            if len(matches) == 1 and (matches[0], leaf) in function_lines:
                return matches[0], leaf
        return None

    for path, text, tree in parsed:
        imports = _import_bindings(tree)
        for guard_line, marker, tool_names, guard_names in _bound_guard_calls(tree):
            guard_definition = None
            resolved_guards = [resolved for name in guard_names if (resolved := resolve_symbol(name, path, imports)) is not None]
            if len(resolved_guards) == 1:
                guard_path, guard_name = resolved_guards[0]
                guard_definition = (guard_path, function_lines[(guard_path, guard_name)])
            for tool_name in tool_names:
                resolved_tool = resolve_symbol(tool_name, path, imports)
                if resolved_tool is not None:
                    target_path, target_name = resolved_tool
                    for effect in definitions.get((target_path, target_name), []):
                        key = (path, guard_line, effect.path, effect.line)
                        if key in seen:
                            continue
                        seen.add(key)
                        candidates.append(ScoutCandidate(path, guard_line, marker, effect, guard_definition))
                        if len(candidates) >= max_candidates:
                            return candidates

    return candidates
