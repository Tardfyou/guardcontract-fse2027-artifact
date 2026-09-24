"""Bounded provider transport with immutable evidence and no implicit resume."""
import hashlib
import json
from pathlib import Path
import time
import urllib.error
import urllib.request

from guardcontract.backends.base import BackendError
from guardcontract.backends.provider_endpoint import CHAT_COMPLETIONS_ENDPOINT, model_identity_matches

ALLOWED_EXTERNAL_MODEL = "GLM-5.3-Flash"
CALL_STATE = Path(__file__).resolve().parents[3] / "config/external-model-call-state.json"


def save(path, value):
    with path.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def bounded_http(url, headers, body, timeout):
    request = urllib.request.Request(url, data=body, headers=dict(headers))
    with urllib.request.build_opener(NoRedirect).open(request, timeout=timeout) as response:
        raw = response.read(2_000_001)
    if len(raw) > 2_000_000:
        raise BackendError("provider response byte limit", retryable=False)
    return raw


class RecordedTransport:
    def __init__(self, directory, *, model, max_calls=2, max_total_tokens=40000, transport=bounded_http):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        if any(self.directory.iterdir()):
            raise ValueError("existing_call_artifacts_require_offline_recovery_not_resend")
        if type(max_calls) is not int or not 1 <= max_calls <= 4 or type(max_total_tokens) is not int or max_total_tokens < 1:
            raise ValueError("invalid_recording_budget")
        self.model, self.max_calls, self.max_total_tokens = model, max_calls, max_total_tokens
        self.transport, self.calls, self.total_tokens, self.usage_known = transport, [], 0, True

    def __call__(self, url, headers, body, timeout):
        if url != CHAT_COMPLETIONS_ENDPOINT:
            raise BackendError("unregistered recording endpoint")
        if self.transport is bounded_http:
            if self.model != ALLOWED_EXTERNAL_MODEL:
                raise BackendError("external model policy requires GLM-5.3-Flash")
            if json.loads(CALL_STATE.read_text()).get("enabled") is not True:
                raise BackendError("external model calls paused")
        if len(self.calls) >= self.max_calls or not self.usage_known or self.total_tokens >= self.max_total_tokens:
            raise BackendError("recorded call budget or unknown usage prevents next request")
        payload = json.loads(body)
        if payload.get("model") != self.model:
            raise BackendError("request model mismatch")
        number = len(self.calls)
        directory = self.directory / f"call-{number:03d}"
        directory.mkdir()
        save(directory / "REQUEST.json", payload)
        with (directory / "REQUEST.raw").open("xb") as handle:
            handle.write(body)
        metadata = {"index": number, "request_sha256": hashlib.sha256(body).hexdigest(), "request_attempted": True}
        started = time.monotonic()
        error, raw = None, None
        try:
            raw = self.transport(url, headers, body, timeout)
        except KeyboardInterrupt:
            metadata.update(status="cancelled", fault_domain="operator")
            error = BackendError("recorded provider call interrupted")
        except (urllib.error.URLError, OSError, TimeoutError, BackendError) as exc:
            metadata.update(status="error", fault_domain="provider", error_kind=type(exc).__name__)
            if isinstance(exc, urllib.error.HTTPError):
                metadata["http_status"] = exc.code
            error = BackendError("recorded provider transport failed")
        if raw is not None:
            metadata["response_sha256"] = hashlib.sha256(raw).hexdigest()
            try:
                with (directory / "RESPONSE.raw").open("xb") as handle:
                    handle.write(raw)
            except OSError:
                metadata.update(status="error", fault_domain="client", error_kind="response_persistence")
                error = BackendError("recorded response persistence failed")
            if error is None:
                try:
                    outer = json.loads(raw)
                    if not isinstance(outer, dict):
                        raise ValueError("envelope")
                    metadata.update(provider_model=outer.get("model"), usage=outer.get("usage"),
                                    finish_reason=outer["choices"][0]["finish_reason"])
                    if not model_identity_matches(self.model, outer.get("model")):
                        raise ValueError("model_identity")
                    usage = outer.get("usage")
                    self.usage_known = isinstance(usage, dict) and type(usage.get("total_tokens")) is int and usage["total_tokens"] >= 0
                    if self.usage_known:
                        self.total_tokens += usage["total_tokens"]
                    metadata["usage_known"] = self.usage_known
                    if metadata["finish_reason"] != "stop":
                        metadata.update(status="model_invalid", fault_domain="model")
                        error = BackendError("recorded model generation incomplete")
                    else:
                        metadata.update(status="completed", fault_domain=None)
                except (ValueError, KeyError, TypeError, IndexError):
                    metadata.update(status="error", fault_domain="provider", error_kind="invalid_envelope_or_identity")
                    error = BackendError("recorded provider envelope invalid")
        metadata["duration_seconds"] = round(time.monotonic() - started, 6)
        if error is not None and "usage_known" not in metadata:
            self.usage_known = False
        self.calls.append(metadata)
        save(directory / "CALL.json", metadata)
        if error is not None:
            raise error
        return raw
