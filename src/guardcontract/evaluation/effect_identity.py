"""Stable logical identities for effect-specific evaluation units."""


def logical_effect_key(effect):
    return tuple(effect.get(name) for name in
                 ("path", "line", "family", "call", "tool_symbol"))


def deduplicate_effects(effects):
    """Keep the first occurrence of each logical source effect identity."""
    seen = set()
    unique = []
    for index, effect in enumerate(effects):
        key = logical_effect_key(effect)
        if key in seen:
            continue
        seen.add(key)
        unique.append((index, effect))
    return unique
