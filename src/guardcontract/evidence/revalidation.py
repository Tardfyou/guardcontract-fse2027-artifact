from __future__ import annotations

import ast
import textwrap
import warnings
from pathlib import Path
from typing import Any

from guardcontract.core.schemas import FindingEnvelope
from guardcontract.discovery.scout import effect_sites_from_tree
from guardcontract.evidence.validation import span_bytes


def _parse_fragment(source: str) -> list[ast.AST]:
    trees = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        try:
            return [ast.parse(textwrap.dedent(source))]
        except SyntaxError:
            pass
        for line in source.splitlines():
            try:
                trees.append(ast.parse(line.strip()))
            except SyntaxError:
                continue
    return trees


def revalidate_finding(repo: Path, finding: FindingEnvelope, *, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or {}
    result: dict[str, Any] = {
        "effect": "not_claimed",
        "ordering": "not_claimed",
        "high_priority_review": False,
        "proved": False,
        "errors": [],
    }
    if finding.effect is not None:
        observed: set[str] = set()
        for span in finding.effect.evidence:
            try:
                source = span_bytes(repo, span).decode("utf-8")
                trees = _parse_fragment(source)
                if not trees:
                    raise SyntaxError("no parseable statements")
            except (OSError, UnicodeError, SyntaxError, ValueError) as exc:
                result["errors"].append(f"effect evidence is not parseable: {type(exc).__name__}")
                continue
            for tree in trees:
                observed.update(site.family for site in effect_sites_from_tree(tree, span.path))
        if finding.effect.family in observed:
            result["effect"] = "confirmed"
        else:
            result["effect"] = "unconfirmed"
            result["errors"].append(f"cited source does not contain a recognized {finding.effect.family} sink")
    definite = [edge for edge in finding.path_edges if edge.kind in {"precedes", "dominates"}]
    if definite:
        result["ordering"] = "model_supported_pending_path_oracle"
        if context.get("decidability") == "post_effect_dependent":
            result["errors"].append("post_effect_dependent does not prove this guard and effect share a reachable execution")
        elif context.get("decidability") == "pre_effect_decidable":
            result["errors"].append("pre_effect_decidable describes availability, not proven blocking order")
    return result
