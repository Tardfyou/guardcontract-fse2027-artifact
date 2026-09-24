"""Offline transport for immutable RecordedTransport call artifacts."""
import hashlib
import json
from pathlib import Path

from guardcontract.backends.base import BackendError


class RecordedReplay:
    source_root = None

    def __init__(self, directory, *, model, **kwargs):
        if self.source_root is None:
            raise ValueError("replay_source_root")
        self.directory = Path(self.source_root) / Path(directory).parent.name / "calls"
        self.model, self.calls, self.total_tokens, self.usage_known = model, [], 0, True

    def __call__(self, url, headers, body, timeout):
        calls = list(self.directory.glob("call-*"))
        if len(calls) != 1 or calls[0].name != "call-000":
            raise ValueError("replay_call_inventory")
        directory = calls[0]
        metadata = json.loads((directory / "CALL.json").read_bytes())
        if ((directory / "REQUEST.raw").read_bytes() != body
                or json.loads((directory / "REQUEST.json").read_bytes()) != json.loads(body)
                or hashlib.sha256(body).hexdigest() != metadata["request_sha256"]):
            raise ValueError("replay_request_mismatch")
        raw = (directory / "RESPONSE.raw").read_bytes() if metadata.get("response_sha256") else None
        if raw is not None and hashlib.sha256(raw).hexdigest() != metadata["response_sha256"]:
            raise ValueError("replay_response_digest")
        if metadata["status"] in {"completed", "model_invalid"}:
            outer = json.loads(raw)
            if outer.get("model") != self.model or outer["choices"][0]["finish_reason"] != metadata["finish_reason"]:
                raise ValueError("replay_response_identity")
        self.usage_known = metadata.get("usage_known", False)
        if self.usage_known:
            self.total_tokens = metadata["usage"]["total_tokens"]
        self.calls = [metadata]
        if metadata["status"] != "completed":
            raise BackendError("recorded_terminal_error")
        return raw


def verify_inventory(source_root, records):
    expected = {record["cell_id"] + "/calls/call-000" for record in records if record["calls"]}
    actual = {str(path.relative_to(source_root)) for path in Path(source_root).glob("*/calls/call-*")}
    if actual != expected or len(expected) != sum(len(record["calls"]) for record in records):
        raise ValueError("replay_global_call_inventory")
