"""Lexical similarity candidates, never a proof of semantic equivalence."""
from collections import Counter, defaultdict
import hashlib
import json

from pygments import lex
from pygments.lexers import get_lexer_by_name
from pygments.token import Comment, Error, Name

LANGUAGES = {"py": "python", "ts": "typescript", "tsx": "typescript", "mts": "typescript", "java": "java", "cs": "csharp", "kt": "kotlin"}


def fingerprint(source, language, max_tokens=100000):
    literal, shape = [], []
    for kind, value in lex(source, get_lexer_by_name(language, stripnl=False, ensurenl=False)):
        if kind in Error:
            raise ValueError("lexer_error")
        if not value or value.isspace() or kind in Comment:
            continue
        literal.append(value)
        shape.append("<IDENTIFIER>" if kind in Name else value)
        if len(shape) > max_tokens:
            raise ValueError("token_budget_exceeded")
    def digest(tokens):
        return hashlib.sha256(json.dumps(tokens, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    shingles = {hashlib.blake2b(json.dumps(shape[i:i + 5], ensure_ascii=False, separators=(",", ":")).encode(), digest_size=8).hexdigest() for i in range(max(0, len(shape) - 4))}
    return {"tokens": len(shape), "literal_token_sha256": digest(literal), "identifier_normalized_sha256": digest(shape), "shingles": shingles}


def similar_pairs(entries, pair_budget=200000, min_shingles=40):
    """Exact prefix candidate generation for >=9/10 set Jaccard, if not capped.

    Global frequency ordering is common to all sets. A qualifying pair must
    intersect prefixes of length n-ceil(0.9*n)+1. Hash collisions may still
    affect lexical similarity and no semantic claim follows from a match.
    """
    eligible = {key: set(value) for key, value in entries.items() if len(value) >= min_shingles}
    frequency = Counter(token for tokens in eligible.values() for token in tokens)
    postings, candidates = defaultdict(list), set()
    complete = True
    for key in sorted(eligible, key=lambda k: (len(eligible[k]), k)):
        tokens = sorted(eligible[key], key=lambda t: (frequency[t], t))
        prefix = tokens[:len(tokens) - (9 * len(tokens) + 9) // 10 + 1]
        for token in prefix:
            for other in postings[token]:
                if 10 * len(eligible[other]) < 9 * len(tokens): continue
                pair = tuple(sorted((key, other)))
                if pair not in candidates and len(candidates) >= pair_budget:
                    complete = False
                    break
                candidates.add(pair)
            if not complete: break
        if not complete: break
        for token in prefix: postings[token].append(key)
    matched = []
    for left, right in sorted(candidates):
        a, b = eligible[left], eligible[right]
        intersection = len(a & b); union = len(a | b)
        if intersection * 10 >= union * 9:
            matched.append({"left": left, "right": right, "intersection": intersection, "union": union, "jaccard": intersection / union})
    return {"eligible_files": len(eligible), "candidate_pairs_compared": len(candidates), "candidate_generation_complete": complete, "pairs": matched}
