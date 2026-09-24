"""Framework-thin, prediction-blind source guard invocation contracts."""
from __future__ import annotations

import asyncio
import ast
import copy
import inspect
import hashlib
import json
import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional
from urllib.parse import urlsplit, urlunsplit


VERDICTS = {"ALLOW", "DENY", "UNKNOWN"}


class UniversalOutput(str):
    """String-compatible output with common structured-output attributes."""

    def __new__(cls, allow: bool, text: str | None = None, fields: dict[str, Any] | None = None):
        if text is None:
            text = "[GUARDCONTRACT_ALLOW_CANARY]" if allow else "[GUARDCONTRACT_DENY_CANARY]"
        value = super().__new__(cls, text)
        value.raw = text
        value.raw_output = text
        value.output = text
        value.content = text
        value.final_output = text
        value.pydantic = None
        value.json_dict = {}
        value.rollback_plan = ["rollback"] if allow else []
        value.observability_plan = ["observe"] if allow else []
        value.evidence = ["evidence"] if allow else []
        value.decision = "go"
        value.required_approvals = ["approval"] if allow else []
        value.confidence = 1.0 if allow else 0.0
        for key, item in (fields or {}).items():
            if not isinstance(key, str) or not key.isidentifier() or key.startswith("_"):
                raise ValueError("source_oracle_output_field")
            setattr(value, key, _fixture_namespace(item))
        return value


@dataclass(frozen=True)
class GuardStimulus:
    tool_name: str
    payload: dict[str, Any]
    state: dict[str, Any]
    output: str
    evidence: tuple[str, ...] = ()
    deps: dict[str, Any] | None = None
    output_fields: dict[str, Any] | None = None
    context_fields: dict[str, Any] | None = None

    @classmethod
    def default(cls, allow: bool):
        marker = "[GUARDCONTRACT_ALLOW_CANARY]" if allow else "[GUARDCONTRACT_DENY_CANARY]"
        return cls(
            tool_name="guardcontract_allow_canary" if allow else "guardcontract_deny_canary",
            payload={"input": marker, "command": marker, "secret": marker,
                     "city": "London" if allow else "", "currency_code": "USD" if allow else "12",
                     "expression": "1+1" if allow else ""},
            state={},
            output=marker,
            evidence=("guardcontract allow evidence",) if allow else (),
            deps={},
            output_fields={},
            context_fields={},
        )


@dataclass(frozen=True)
class GuardObservation:
    framework: str
    lifecycle_position: str
    stimulus: str
    verdict: str
    result_type: str | None
    exception_type: str | None
    reason: str

    def __post_init__(self):
        if self.verdict not in VERDICTS:
            raise ValueError("source_oracle_verdict")


def _positional_count(function: Callable[..., Any]) -> int:
    kinds = {inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD}
    return sum(parameter.kind in kinds for parameter in inspect.signature(function).parameters.values())


def _await(value):
    return asyncio.run(value) if inspect.isawaitable(value) else value


class ModelRetry(Exception):
    """Local denial signal compatible with Pydantic validator source slices."""


class FixtureMapping(dict):
    """JSON object that preserves mapping methods and supports record attributes."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


def _fixture_namespace(value):
    if isinstance(value, dict):
        return FixtureMapping({key: _fixture_namespace(item) for key, item in value.items()})
    if isinstance(value, list):
        return [_fixture_namespace(item) for item in value]
    return value


class FluentDependencyStub:
    """Closed, inert async factory for fluent clients described by JSON fixtures."""

    def __init__(self, name):
        if not isinstance(name, str) or not name.isidentifier():
            raise ValueError("source_oracle_dependency_stub_name")
        self.name = name
        self.fixture = {}

    def set_fixture(self, value):
        if not isinstance(value, dict):
            raise ValueError("source_oracle_dependency_fixture")
        self.fixture = copy.deepcopy(value)

    async def __call__(self, *_args, **_kwargs):
        return _FluentClient(self.fixture)


class _FluentClient:
    def __init__(self, fixture):
        self.fixture = fixture

    def __getattr__(self, name):
        if name == "execute":
            async def execute(*_args, **_kwargs):
                return _fixture_namespace(self.fixture.get("result", {}))
            return execute

        def chained(*_args, **_kwargs):
            return self
        return chained


def build_record_type(name: str):
    if not isinstance(name, str) or not name.isidentifier():
        raise ValueError("source_oracle_record_type_name")

    class Record:
        def __init__(self, **fields):
            for key, value in fields.items():
                setattr(self, key, value)

        @classmethod
        def model_validate_json(cls, raw):
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("record_json_object")
            return cls(**value)

    Record.__name__ = name
    Record.__qualname__ = name
    return Record


def build_guard_runner(tripwire_field=None, tripwire_inverted=False, output_fields=None,
                       boolean_fields=None):
    """Build a closed, inert runner whose structured verdict follows the canary text."""
    class GuardRunner:
        @staticmethod
        async def run(_agent, text=None, **_kwargs):
            if text is None:
                text = _kwargs.get("input", _kwargs.get("prompt"))
            denied = "[guardcontract_deny_canary]" in str(text).lower()
            final_output = SimpleNamespace(
                is_unsafe_code=denied,
                unsafe=denied,
                blocked=denied,
                denied=denied,
                allowed=not denied,
                is_valid=not denied,
                is_todo_related=not denied,
            )
            if tripwire_field is not None:
                if not isinstance(tripwire_field, str) or not tripwire_field.isidentifier():
                    raise ValueError("source_oracle_tripwire_field")
                setattr(final_output, tripwire_field,
                        (not denied) if tripwire_inverted else denied)
            for name in output_fields or ():
                if not isinstance(name, str) or not name.isidentifier() or name.startswith("_"):
                    raise ValueError("source_oracle_runner_output_field")
                if not hasattr(final_output, name):
                    setattr(final_output, name, "local structured output")
            for name in boolean_fields or ():
                if not isinstance(name, str) or not name.isidentifier() or name.startswith("_"):
                    raise ValueError("source_oracle_runner_boolean_field")
                setattr(final_output, name, not denied)
            class Result:
                def __init__(self, value):
                    self.final_output = value

                def final_output_as(self, _output_type):
                    return self.final_output

            return Result(final_output)

    return GuardRunner


def materialize_fixture_value(value, record_types=None):
    """Build inert objects from a closed JSON fixture vocabulary."""
    record_types = record_types or {}
    if isinstance(value, list):
        return [materialize_fixture_value(item, record_types) for item in value]
    if not isinstance(value, dict):
        return value
    if "$namespace" in value:
        if set(value) != {"$namespace"} or not isinstance(value["$namespace"], dict):
            raise ValueError("source_oracle_namespace_fixture")
        return SimpleNamespace(**{
            key: materialize_fixture_value(item, record_types)
            for key, item in value["$namespace"].items()
        })
    if "$record" in value:
        if set(value) != {"$record"} or not isinstance(value["$record"], dict):
            raise ValueError("source_oracle_record_fixture")
        spec = value["$record"]
        if set(spec) != {"type", "fields"} or not isinstance(spec["fields"], dict):
            raise ValueError("source_oracle_record_fixture")
        record_type = record_types.get(spec["type"])
        if record_type is None:
            raise ValueError("source_oracle_stimulus_type")
        fields = {key: materialize_fixture_value(item, record_types)
                  for key, item in spec["fields"].items()}
        return record_type(**fields)
    return {key: materialize_fixture_value(item, record_types) for key, item in value.items()}


def instantiate_guard(factory, factory_call, record_types=None):
    """Instantiate a guard factory from frozen JSON-safe positional/keyword data."""
    if not isinstance(factory_call, dict) or set(factory_call) - {"args", "kwargs"}:
        raise ValueError("source_oracle_factory_call")
    args = materialize_fixture_value(factory_call.get("args", []), record_types)
    kwargs = materialize_fixture_value(factory_call.get("kwargs", {}), record_types)
    if not isinstance(args, list) or not isinstance(kwargs, dict):
        raise ValueError("source_oracle_factory_call")
    guard = _await(factory(*args, **kwargs))
    if not callable(guard):
        raise ValueError("source_oracle_factory_not_callable")
    return guard


def _symbol_leaf(symbol: str) -> str:
    if symbol.startswith("<call:"):
        symbol = symbol[len("<call:"):].split(":", 1)[0]
    return symbol.rsplit(".", 1)[-1]


def _safe_assignment(value):
    """Allow only closed, deterministic module values needed by a source slice."""
    if isinstance(value, ast.Constant):
        return True
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return all(_safe_assignment(item) for item in value.elts)
    if isinstance(value, ast.Dict):
        return all(key is not None and _safe_assignment(key) and _safe_assignment(item)
                   for key, item in zip(value.keys, value.values))
    if isinstance(value, ast.UnaryOp) and isinstance(value.op, (ast.UAdd, ast.USub)):
        return _safe_assignment(value.operand)
    if isinstance(value, ast.BinOp) and isinstance(value.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod, ast.Pow)):
        return _safe_assignment(value.left) and _safe_assignment(value.right)
    if isinstance(value, ast.Call):
        return (isinstance(value.func, ast.Attribute)
                and isinstance(value.func.value, ast.Name)
                and value.func.value.id == "re" and value.func.attr == "compile"
                and all(_safe_assignment(item) for item in value.args)
                and all(keyword.arg is not None and _safe_assignment(keyword.value)
                        for keyword in value.keywords))
    return False


def load_source_function(source_path: Path, symbol: str, extra_namespace=None):
    """Load one source function and its module-local pure helper closure."""
    source_path = Path(source_path)
    source = source_path.read_text(encoding="utf-8-sig")
    tree = ast.parse(source, filename=str(source_path))
    leaf = _symbol_leaf(symbol)
    matches = [node for node in ast.walk(tree)
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == leaf]
    if len(matches) != 1:
        raise ValueError("source_oracle_function_not_unique")
    top_level = {node.name: node for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    needed = {leaf}
    pending = [matches[0]]
    while pending:
        current = pending.pop()
        for call in ast.walk(current):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                name = call.func.id
                if name in top_level and name not in needed:
                    needed.add(name)
                    pending.append(top_level[name])
    nodes = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in needed:
            cloned = copy.deepcopy(node)
            cloned.decorator_list = []
            nodes.append(cloned)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is not None and _safe_assignment(value):
                nodes.append(copy.deepcopy(node))
    if leaf not in top_level:
        cloned = copy.deepcopy(matches[0])
        cloned.decorator_list = []
        nodes.append(cloned)
    module = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *nodes],
        type_ignores=[],
    )
    ast.fix_missing_locations(module)
    namespace = {
        "Any": Any, "Dict": Dict, "Iterable": Iterable, "List": List,
        "Mapping": Mapping, "Optional": Optional, "SimpleNamespace": SimpleNamespace,
        "copy": copy, "json": json, "logging": logging, "logger": logging.getLogger("guardcontract.source_oracle"),
        "math": math, "re": re, "ModelRetry": ModelRetry,
        "urlsplit": urlsplit, "urlunsplit": urlunsplit,
        "emit_metric": lambda *_args, **_kwargs: None,
    }
    namespace.update(extra_namespace or {})
    exec(compile(module, str(source_path), "exec"), namespace)
    return namespace[leaf]


def _openai_call(function, allow, stimulus):
    count = _positional_count(function)
    output = UniversalOutput(allow, stimulus.output, stimulus.output_fields)
    payload = dict(stimulus.payload)
    if count == 1:
        data = SimpleNamespace(
            context=SimpleNamespace(tool_arguments=json.dumps(payload)),
            output=output,
        )
        return function(data)
    if count >= 3:
        policy = SimpleNamespace(contains_forbidden_intent=lambda text: (
            "[guardcontract_deny_canary]" in str(text).lower(), "local fixture denial"
        ))
        context_fields = stimulus.state.get("context", {}) if isinstance(stimulus.state, dict) else {}
        if not isinstance(context_fields, dict) or not all(
                isinstance(key, str) and key.isidentifier() for key in context_fields):
            raise ValueError("openai_source_guard_context_fields")
        context = SimpleNamespace(context=SimpleNamespace(
            **{**{key: _fixture_namespace(value) for key, value in context_fields.items()},
               "policy": policy}))
        return function(context, SimpleNamespace(name="local-agent"), output)
    raise ValueError("openai_source_guard_signature")


def _invoke_openai(function, allow, stimulus):
    return _await(_openai_call(function, allow, stimulus))


def _invoke_adk(function, lifecycle_position, allow, stimulus):
    output = UniversalOutput(allow, stimulus.output, stimulus.output_fields)
    tool = SimpleNamespace(name=stimulus.tool_name)
    payload = dict(stimulus.payload)
    context = SimpleNamespace(state=dict(stimulus.state), delicate=False, tool_arguments=json.dumps(payload))
    arguments = [tool, payload, context]
    if lifecycle_position == "post":
        arguments.append({"output": str(output), "result": str(output),
                          "status": "ok" if allow else "blocked"})
    count = _positional_count(function)
    if count < 1 or count > len(arguments):
        raise ValueError("adk_source_guard_signature")
    return _await(function(*arguments[:count]))


def _invoke_crewai(function, lifecycle_position, allow, stimulus):
    output = UniversalOutput(allow, stimulus.output, stimulus.output_fields)
    count = _positional_count(function)
    if lifecycle_position == "pre":
        context = SimpleNamespace(tool_name=stimulus.tool_name,
                                  tool_input=dict(stimulus.payload), tool=SimpleNamespace(name=stimulus.tool_name))
        arguments = [context]
    else:
        arguments = [output, list(stimulus.evidence)]
    if count < 1 or count > len(arguments):
        raise ValueError("crewai_source_guard_signature")
    return _await(function(*arguments[:count]))


def _invoke_pydantic(function, allow, stimulus):
    output = UniversalOutput(allow, stimulus.output, stimulus.output_fields)
    count = _positional_count(function)
    if count == 1:
        return _await(function(output))
    if count == 2:
        context = SimpleNamespace(deps=SimpleNamespace(**(stimulus.deps or {})),
                                  usage=SimpleNamespace(), retry=0,
                                  **(stimulus.context_fields or {}))
        return _await(function(context, output))
    raise ValueError("pydantic_source_guard_signature")


def _boolean_verdict(value):
    if type(value) is bool:
        return "ALLOW" if value else "DENY"
    if isinstance(value, tuple) and value and type(value[0]) is bool:
        return "ALLOW" if value[0] else "DENY"
    if isinstance(value, dict):
        for key in ("passed", "success", "allowed", "allow"):
            if type(value.get(key)) is bool:
                return "ALLOW" if value[key] else "DENY"
        for key in ("blocked", "denied", "deny"):
            if type(value.get(key)) is bool:
                return "DENY" if value[key] else "ALLOW"
    for key in ("passed", "success", "allowed"):
        flag = getattr(value, key, None)
        if type(flag) is bool:
            return "ALLOW" if flag else "DENY"
    return None


def _normalize_verdict(framework, lifecycle_position, result, exception):
    if exception is not None:
        name = type(exception).__name__
        if name in {"ModelRetry", "InputGuardrailTripwireTriggered", "OutputGuardrailTripwireTriggered",
                    "GuardrailTripwireTriggered"}:
            return "DENY", f"denial_exception:{name}"
        return "UNKNOWN", f"unclassified_exception:{name}"
    if framework == "openai-agents":
        if bool(getattr(result, "tripwire_triggered", False)):
            return "DENY", "tripwire_triggered"
        behavior = getattr(result, "behavior", None)
        behavior_type = behavior.get("type") if isinstance(behavior, dict) else getattr(behavior, "type", None)
        if behavior_type in {"reject_content", "tripwire_triggered"}:
            return "DENY", f"behavior:{behavior_type}"
        return "ALLOW", "no_denial_signal"
    if framework == "google-adk":
        if lifecycle_position == "pre":
            return ("ALLOW", "callback_returned_none") if result is None else ("DENY", "pre_callback_short_circuit")
        verdict = _boolean_verdict(result)
        return (verdict, "explicit_post_callback_signal") if verdict else ("UNKNOWN", "post_callback_has_no_explicit_deny_signal")
    if framework == "crewai":
        verdict = _boolean_verdict(result)
        return (verdict, "crewai_guard_result") if verdict else ("UNKNOWN", "crewai_guard_result_unclassified")
    if framework == "pydantic-ai":
        return "ALLOW", "validator_returned"
    return "UNKNOWN", "framework_adapter_unavailable"


def observe_guard(function, *, framework, lifecycle_position, allow, stimulus=None):
    stimulus = stimulus or GuardStimulus.default(allow)
    if lifecycle_position not in {"pre", "post"}:
        return GuardObservation(framework, lifecycle_position, "ALLOW" if allow else "DENY",
                                "UNKNOWN", None, None, "lifecycle_unknown")
    result = None
    exception = None
    try:
        dependencies = {value.name: value for value in function.__globals__.values()
                        if isinstance(value, FluentDependencyStub)}
        for name, dependency in dependencies.items():
            dependency.set_fixture((stimulus.deps or {}).get(name, {}))
        if framework == "openai-agents":
            result = _invoke_openai(function, allow, stimulus)
        elif framework == "google-adk":
            result = _invoke_adk(function, lifecycle_position, allow, stimulus)
        elif framework == "crewai":
            result = _invoke_crewai(function, lifecycle_position, allow, stimulus)
        elif framework == "pydantic-ai":
            result = _invoke_pydantic(function, allow, stimulus)
        else:
            return GuardObservation(framework, lifecycle_position, "ALLOW" if allow else "DENY",
                                    "UNKNOWN", None, None, "framework_adapter_unavailable")
    except Exception as exc:
        exception = exc
    verdict, reason = _normalize_verdict(framework, lifecycle_position, result, exception)
    return GuardObservation(
        framework=framework,
        lifecycle_position=lifecycle_position,
        stimulus="ALLOW" if allow else "DENY",
        verdict=verdict,
        result_type=None if result is None else type(result).__module__ + "." + type(result).__qualname__,
        exception_type=None if exception is None else type(exception).__module__ + "." + type(exception).__qualname__,
        reason=reason,
    )


async def observe_openai_guard_async(function, *, lifecycle_position, allow, stimulus=None):
    """Evaluate one extracted OpenAI guard inside a running SDK event loop."""
    stimulus = stimulus or GuardStimulus.default(allow)
    if lifecycle_position not in {"pre", "post"}:
        return GuardObservation("openai-agents", lifecycle_position,
                                "ALLOW" if allow else "DENY", "UNKNOWN",
                                None, None, "lifecycle_unknown")
    result = None
    exception = None
    try:
        dependencies = {value.name: value for value in function.__globals__.values()
                        if isinstance(value, FluentDependencyStub)}
        for name, dependency in dependencies.items():
            dependency.set_fixture((stimulus.deps or {}).get(name, {}))
        result = _openai_call(function, allow, stimulus)
        if inspect.isawaitable(result):
            result = await result
    except Exception as exc:
        exception = exc
    verdict, reason = _normalize_verdict(
        "openai-agents", lifecycle_position, result, exception)
    return GuardObservation(
        framework="openai-agents", lifecycle_position=lifecycle_position,
        stimulus="ALLOW" if allow else "DENY", verdict=verdict,
        result_type=None if result is None else type(result).__module__ + "." + type(result).__qualname__,
        exception_type=None if exception is None else type(exception).__module__ + "." + type(exception).__qualname__,
        reason=reason)


def observe_pair(function, *, framework, lifecycle_position, allow_stimulus=None, deny_stimulus=None):
    return [
        observe_guard(function, framework=framework, lifecycle_position=lifecycle_position, allow=True,
                      stimulus=allow_stimulus),
        observe_guard(function, framework=framework, lifecycle_position=lifecycle_position, allow=False,
                      stimulus=deny_stimulus),
    ]


def execute_paired_trace(function, *, framework, lifecycle_position, sample_id, marker_dir,
                         allow_stimulus=None, deny_stimulus=None):
    marker_dir = Path(marker_dir)
    marker_dir.mkdir(parents=True, exist_ok=True)
    observations = observe_pair(
        function, framework=framework, lifecycle_position=lifecycle_position,
        allow_stimulus=allow_stimulus, deny_stimulus=deny_stimulus,
    )
    rows = []
    for observation in observations:
        decision = observation.stimulus
        invocation_id = hashlib.sha256(f"{sample_id}\0{decision}".encode()).hexdigest()[:20]
        marker = marker_dir / f"{invocation_id}.marker"
        marker.unlink(missing_ok=True)
        events = [{"kind": "invocation_start", "invocation_id": invocation_id, "decision": decision}]
        if lifecycle_position == "post":
            marker.write_text("committed", encoding="utf-8")
            events.append({"kind": "effect_committed", "invocation_id": invocation_id,
                           "decision": decision, "effect": "local_canary"})
        events.append({"kind": "guard_verdict", "invocation_id": invocation_id,
                       "decision": decision, "verdict": observation.verdict})
        if lifecycle_position == "pre" and observation.verdict == "DENY":
            events.append({"kind": "effect_skipped", "invocation_id": invocation_id,
                           "decision": decision, "effect": "local_canary"})
        elif lifecycle_position == "pre" and observation.verdict == "ALLOW":
            events.append({"kind": "effect_attempt", "invocation_id": invocation_id,
                           "decision": decision, "effect": "local_canary"})
            marker.write_text("committed", encoding="utf-8")
            events.append({"kind": "effect_committed", "invocation_id": invocation_id,
                           "decision": decision, "effect": "local_canary"})
        marker_record = None
        if marker.exists():
            marker_record = {"invocation_id": invocation_id, "relative_path": marker.name,
                             "bytes": marker.stat().st_size,
                             "sha256": hashlib.sha256(marker.read_bytes()).hexdigest()}
        rows.append({"decision": decision, "invocation_id": invocation_id,
                     "guard_verdict": observation.verdict, "guard_reason": observation.reason,
                     "events": events, "independent_markers": [] if marker_record is None else [marker_record],
                     "execution_health": "completed"})
    return rows
