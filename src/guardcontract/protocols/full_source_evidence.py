"""Replace typed-review snippets with bounded authenticated complete source files."""
from copy import deepcopy
import hashlib
import json


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def replace(payload, spec, sources, system, max_bytes=65536):
    if sum(len(source.encode()) for source in sources.values()) > max_bytes:
        raise ValueError("full_source_budget")
    for evidence in payload["evidence"].values():
        if "path" in evidence:
            source = sources[evidence["path"]]
            if hashlib.sha256(source.encode()).hexdigest() != evidence["source_sha256"]:
                raise ValueError("full_source_identity")
    new_payload, new_spec = deepcopy(payload), deepcopy(spec)
    evidence = {key: value for key, value in payload["evidence"].items() if "path" not in value}
    for index, (path, source) in enumerate(sorted(sources.items())):
        if not source:
            raise ValueError("full_source_empty")
        source_hash = hashlib.sha256(source.encode()).hexdigest()
        evidence[f"source{index}"] = {"path": path, "start_line": 1,
            "end_line": len(source.splitlines()), "content": source,
            "source_sha256": source_hash, "content_sha256": source_hash}
    new_payload["evidence"] = evidence
    new_payload.pop("input_id")
    new_payload["input_id"] = "full-source:" + digest({"system": system, "payload": new_payload})[:24]
    new_spec.update(input_id=new_payload["input_id"], evidence=evidence,
                    model_input_sha256=digest(new_payload),
                    requirements={field: sorted(evidence) for field in spec["requirements"]})
    return new_payload, new_spec
