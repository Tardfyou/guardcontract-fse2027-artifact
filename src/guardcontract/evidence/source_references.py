"""Authenticate explicit source references, without certifying claim semantics."""
import ast
from copy import deepcopy
import hashlib
from pathlib import PurePosixPath
import re


RANGE = re.compile(r"(?P<anchor>[^\s:]+):(?P<start>[0-9]+)-(?P<end>[0-9]+)(?:(?: |:)(?P<symbol>[A-Za-z_][\w.]*))?")


def normalize_view_citation_paths(answer, sources):
    """Resolve only unambiguous extension-clipped aliases; never alter opinions.

    Raw response bytes remain the authority. The returned correction receipt
    is an explicit decoding transformation, not a semantic certificate.
    """
    value = deepcopy(answer)
    known = {source["path"] for source in sources}
    fixes = []
    for index, citation in enumerate(value.get("citations", [])):
        original = citation.get("path")
        if original in known:
            continue
        matches = [path for path in known if isinstance(original, str) and original.endswith(".")
                   and PurePosixPath(path).suffix and PurePosixPath(path).with_suffix("").as_posix() + "." == original]
        if len(matches) != 1:
            raise ValueError("view_citation_unknown_or_ambiguous_path")
        citation["path"] = matches[0]
        fixes.append({"citation_index": index, "original_path": original, "registered_source_path": matches[0],
                      "rule": "unique_extension_clipped_alias", "source_semantics_verified": False})
    return value, fixes


def function_spans(source):
    found = {}

    def visit(node, prefix=""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                symbol = prefix + child.name
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    found.setdefault(symbol, []).append((child.lineno, child.end_lineno))
                visit(child, symbol + ".")
            else:
                visit(child, prefix)
    visit(ast.parse(source))
    return found


class SourceIndex:
    def __init__(self, excerpts, registered_sources):
        self.sources = {}
        for alias, excerpt in excerpts.items():
            if excerpt.get("coverage") != "complete_module":
                continue
            path = excerpt["path"]
            text = excerpt["content"]
            if not isinstance(text, str) or len(text.encode()) > 1_000_000:
                raise ValueError("reference209_source_budget_or_type")
            sha = hashlib.sha256(text.encode()).hexdigest()
            if path not in registered_sources or sha != registered_sources[path] or sha != excerpt.get("sha256"):
                raise ValueError("reference209_source_identity")
            if excerpt["start_line"] != 1 or excerpt["end_line"] != len(text.splitlines()):
                raise ValueError("reference209_module_span")
            self.sources[alias] = {"path": path, "source_sha256": sha, "end_line": excerpt["end_line"],
                                   "functions": function_spans(text)}

    def resolve(self, citation):
        if not isinstance(citation, str):
            raise ValueError("reference209_string_required")
        if citation in self.sources:
            anchor, start, end, symbol = citation, 1, self.sources[citation]["end_line"], None
        else:
            match = RANGE.fullmatch(citation)
            if match is None:
                raise ValueError("reference209_syntax")
            anchor, start, end, symbol = match.group("anchor", "start", "end", "symbol")
            start, end = int(start), int(end)
        candidates = [(alias, source) for alias, source in self.sources.items() if alias == anchor or source["path"] == anchor]
        if len(candidates) != 1:
            raise ValueError("reference209_ambiguous_or_unknown_source")
        alias, source = candidates[0]
        if not 1 <= start <= end <= source["end_line"]:
            raise ValueError("reference209_range")
        if symbol is not None:
            spans = source["functions"].get(symbol, [])
            if len(spans) != 1 or spans[0] != (start, end):
                raise ValueError("reference209_symbol_span")
        return {"original": citation, "excerpt_alias": alias, "path": source["path"],
                "source_sha256": source["source_sha256"], "start_line": start, "end_line": end,
                "symbol": symbol, "symbol_verified": symbol is not None,
                "reference_identity_verified": True, "source_semantics_verified": False}

    def covers_actor(self, certificate, actor):
        # Re-resolve rather than trusting a caller-created certificate dictionary.
        verified = self.resolve(certificate["original"])
        if certificate != verified:
            raise ValueError("reference209_certificate_changed")
        if (verified["path"] != actor["path"] or verified["source_sha256"] != actor["source_sha256"]
                or verified["start_line"] > actor["start_line"] or verified["end_line"] < actor["end_line"]):
            return False
        source = self.sources[verified["excerpt_alias"]]
        return source["functions"].get(actor["symbol"]) == [(actor["start_line"], actor["end_line"])]
