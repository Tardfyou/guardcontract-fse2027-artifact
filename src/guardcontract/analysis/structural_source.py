"""Pinned Tree-sitter token evidence; error trees never count as parsed source."""
import hashlib
import json

from tree_sitter import Language, Parser
import tree_sitter_typescript


def fingerprint(raw, language, max_tokens=100000):
    if language not in {"typescript", "tsx"}:
        raise ValueError("unsupported_structural_language")
    source = raw.decode("utf-8-sig").encode("utf-8")
    grammar = tree_sitter_typescript.language_tsx() if language == "tsx" else tree_sitter_typescript.language_typescript()
    tree = Parser(Language(grammar)).parse(source)
    if tree.root_node.has_error:
        errors, todo = [], [tree.root_node]
        while todo and len(errors) < 20:
            node = todo.pop()
            if node.type == "ERROR" or node.is_missing:
                errors.append({"type": node.type, "missing": node.is_missing,
                               "start_line": node.start_point.row + 1, "end_line": node.end_point.row + 1})
            todo.extend(reversed(node.children))
        return {"status": "syntax_unavailable", "errors": errors, "source_sha256": hashlib.sha256(raw).hexdigest()}
    literal, shape, todo = [], [], [tree.root_node]
    while todo:
        node = todo.pop()
        if node.type == "comment":
            continue
        if node.children:
            todo.extend(reversed(node.children))
            continue
        value = source[node.start_byte:node.end_byte].decode("utf-8")
        if not value or value.isspace():
            continue
        literal.append((node.type, value))
        shape.append((node.type, "<IDENTIFIER>" if node.type in {"identifier", "property_identifier", "type_identifier", "shorthand_property_identifier", "shorthand_property_identifier_pattern"} else value))
        if len(shape) > max_tokens:
            raise ValueError("structural_token_budget")
    def digest(value):
        return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()
    return {"status": "parsed", "source_sha256": hashlib.sha256(raw).hexdigest(), "tokens": len(shape),
            "literal_token_sha256": digest(literal), "identifier_normalized_sha256": digest(shape),
            "shingles": sorted({digest(shape[i:i + 5]) for i in range(max(0, len(shape) - 4))}),
            "semantic_equivalence_proven": False}
