"""Preserve source lines while masking credential values in JSON/YAML/text."""
import json
import re

from guardcontract.evidence.python_redaction import TOKEN, EMBEDDED

SENSITIVE_KEY = re.compile(r"(?i)(api[_-]?key|access[_-]?token|password|passwd|secret|authorization|private[_-]?key|credential|(?:^|_)token$)")


def _assignment_spans(text):
    spans, offset = [], 0
    pattern = re.compile(r'''(?<![A-Za-z0-9_])["']?(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]\s*''')
    for line in text.splitlines(keepends=True):
        matches = list(pattern.finditer(line))
        for index, match in enumerate(matches):
            if not SENSITIVE_KEY.search(match["key"]): continue
            end = matches[index + 1].start() if index + 1 < len(matches) else len(line.rstrip("\r\n"))
            trailing = " " if index + 1 < len(matches) else ""
            spans.append((offset + match.end(), offset + end, "<REDACTED>" + trailing))
        offset += len(line)
    return spans


def redact_data(raw):
    encoding = ("utf-32" if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")) else
                "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")
    text = raw.decode(encoding)
    spans = []
    try:
        json.loads(text)
        decoder = json.JSONDecoder(); i = 0
        while i < len(text):
            if text[i] != '"': i += 1; continue
            value, end = decoder.raw_decode(text, i)
            cursor = end
            while cursor < len(text) and text[cursor].isspace(): cursor += 1
            if cursor < len(text) and text[cursor] == ":" and SENSITIVE_KEY.search(value):
                start = cursor + 1
                while start < len(text) and text[start].isspace(): start += 1
                secret, stop = decoder.raw_decode(text, start)
                if secret is not None and type(secret) is not bool:
                    spans.append((start, stop, '"<REDACTED>"' + "\n" * text[start:stop].count("\n")))
                i = stop
            else:
                cleaned = EMBEDDED.sub("<REDACTED>", TOKEN.sub("<REDACTED>", value))
                if cleaned != value: spans.append((i, end, json.dumps(cleaned, ensure_ascii=True)))
                i = end
    except (ValueError, TypeError):
        try:
            import yaml
            tree = yaml.compose(text, Loader=yaml.SafeLoader)
            seen = set()
            def walk(node):
                if node is None or id(node) in seen: return
                seen.add(id(node))
                if isinstance(node, yaml.MappingNode):
                    for key, value in node.value:
                        if isinstance(key, yaml.ScalarNode) and SENSITIVE_KEY.search(key.value) and value.tag not in {"tag:yaml.org,2002:bool", "tag:yaml.org,2002:null"}:
                            start, end = value.start_mark.index, value.end_mark.index
                            original = text[start:end]
                            anchor = re.match(r"&[A-Za-z0-9_-]+\s+", original)
                            prefix = anchor[0] if anchor else ""
                            spans.append((start, end, prefix + '"<REDACTED>"' + "\n" * original.count("\n")))
                        else: walk(value)
                elif isinstance(node, yaml.SequenceNode):
                    for value in node.value: walk(value)
            walk(tree)
            # .env and Dockerfile input often parses as a scalar. Successful
            # YAML parsing must not bypass credential value masking.
            if tree is None or isinstance(tree, yaml.ScalarNode): spans.extend(_assignment_spans(text))
        except Exception:
            spans.extend(_assignment_spans(text))
    selected = []
    for span in sorted(spans, key=lambda s: (s[0], -s[1])):
        if selected and span[0] < selected[-1][1]: continue
        selected.append(span)
    for start, end, replacement in reversed(selected): text = text[:start] + replacement + text[end:]
    text = re.sub(r"-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)-----.*?-----END [^-]+-----",
                  lambda m: "<REDACTED>" + "\n" * m[0].count("\n"), text, flags=re.S)
    text = TOKEN.sub("<REDACTED>", text)
    return {"source": text, "status": "sanitized", "redactions": text.count("<REDACTED>"),
            "masked_values_are_unknown": True}
