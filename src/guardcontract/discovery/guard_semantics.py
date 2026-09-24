"""Framework-thin denial-signal analysis over shared Python AST slices."""
from __future__ import annotations

import ast
from typing import Iterable

from guardcontract.analysis.guard_denial_contracts import denial_contract


DENIAL_EXCEPTIONS = {
    "ModelRetry",
    "InputGuardrailTripwireTriggered",
    "OutputGuardrailTripwireTriggered",
    "GuardrailTripwireTriggered",
    "HookAborted",
}
DENIAL_KEYS = {"blocked", "denied", "deny", "error"}
ALLOW_KEYS = {"passed", "success", "allowed", "allow"}


def _name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return None


def _constant_bool(node: ast.AST | None) -> bool | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is bool else None


def _dict_boolean_signal(node: ast.AST | None):
    if not isinstance(node, ast.Dict):
        return None
    found = []
    for key, value in zip(node.keys, node.values):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            continue
        flag = _constant_bool(value)
        if flag is None:
            if key.value in DENIAL_KEYS | ALLOW_KEYS:
                found.append("present")
        elif key.value in DENIAL_KEYS:
            found.append("present" if flag else "absent")
        elif key.value in ALLOW_KEYS:
            found.append("absent" if flag else "present")
    return "present" if "present" in found else None


def _tuple_boolean_signal(node: ast.AST | None):
    if not isinstance(node, (ast.Tuple, ast.List)) or not node.elts:
        return None
    flag = _constant_bool(node.elts[0])
    return None if flag is None else ("absent" if flag else "present")


def _tripwire_signal(node: ast.AST | None):
    if not isinstance(node, ast.Call):
        return None
    for keyword in node.keywords:
        if keyword.arg != "tripwire_triggered":
            continue
        flag = _constant_bool(keyword.value)
        return "absent" if flag is False else "present"
    return None


def _return_alternatives(node: ast.AST | None):
    if isinstance(node, ast.IfExp):
        return [*_return_alternatives(node.body), *_return_alternatives(node.orelse)]
    return [node]


def classify(functions: Iterable[ast.AST], *, framework: str, parameter: str) -> dict:
    """Return tri-state capability to emit a framework-defined denial signal."""
    functions = list(functions)
    returns = [node.value for function in functions for node in ast.walk(function)
               if isinstance(node, ast.Return)]
    raises = [node for function in functions for node in ast.walk(function)
              if isinstance(node, ast.Raise)]
    denial_raises = sorted({name for node in raises
                            if (name := _name(node.exc)) is not None
                            and name.rsplit(".", 1)[-1] in DENIAL_EXCEPTIONS})
    evidence = []
    contract = denial_contract(framework, parameter)
    if denial_raises:
        evidence.append({"kind": "denial_exception", "symbols": denial_raises})
        return {"deny_capability": "present", "evidence": evidence,
                "analysis_complete": True}

    if contract == "pre_short_circuit":
        non_neutral = [value for value in returns
                       if not (value is None or isinstance(value, ast.Constant) and value.value is None)]
        signals = [_dict_boolean_signal(value) for value in non_neutral]
        if "present" in signals:
            evidence.append({"kind": "pre_callback_explicit_denial_return"})
            return {"deny_capability": "present", "evidence": evidence,
                    "analysis_complete": True}
        if raises:
            return {"deny_capability": "unknown",
                    "evidence": [{"kind": "pre_callback_unclassified_raise", "count": len(raises)}],
                    "analysis_complete": False}
        if non_neutral:
            return {"deny_capability": "unknown",
                    "evidence": [{"kind": "pre_callback_non_denial_short_circuit", "count": len(non_neutral)}],
                    "analysis_complete": False}
        evidence.append({"kind": "pre_callback_only_none_return", "count": len(returns)})
        return {"deny_capability": "absent", "evidence": evidence,
                "analysis_complete": True}
    if contract == "post_explicit_boolean":
        signals = [_dict_boolean_signal(value) for value in returns]
        if "present" in signals:
            return {"deny_capability": "present",
                    "evidence": [{"kind": "explicit_post_boolean_signal"}],
                    "analysis_complete": True}
        if raises:
            return {"deny_capability": "unknown",
                    "evidence": [{"kind": "post_callback_unclassified_raise", "count": len(raises)}],
                    "analysis_complete": False}
        neutral = all(value is None or isinstance(value, ast.Constant) and value.value is None
                      for value in returns)
        if neutral:
            return {"deny_capability": "absent",
                    "evidence": [{"kind": "post_callback_only_none_return", "count": len(returns)}],
                    "analysis_complete": True}
        return {"deny_capability": "unknown",
                "evidence": [{"kind": "post_callback_return_unclassified"}],
                "analysis_complete": False}

    if contract == "retry_exception":
        return {"deny_capability": "unknown",
                "evidence": [{"kind": "no_model_retry_signal"}],
                "analysis_complete": False}

    if contract == "boolean_result":
        signals = [_tuple_boolean_signal(value) or _dict_boolean_signal(value)
                   for returned in returns for value in _return_alternatives(returned)]
        if "present" in signals:
            return {"deny_capability": "present",
                    "evidence": [{"kind": "crewai_false_result"}], "analysis_complete": True}
        if signals and all(signal == "absent" for signal in signals):
            return {"deny_capability": "absent",
                    "evidence": [{"kind": "crewai_only_true_results"}], "analysis_complete": True}

    if contract == "before_hook_boolean":
        alternatives = [value for returned in returns for value in _return_alternatives(returned)]
        flags = [_constant_bool(value) for value in alternatives]
        if False in flags:
            return {"deny_capability": "present",
                    "evidence": [{"kind": "crewai_before_hook_false"}], "analysis_complete": True}
        if alternatives and all(value is None or flag is True
                                for value, flag in zip(alternatives, flags)):
            return {"deny_capability": "absent",
                    "evidence": [{"kind": "crewai_before_hook_only_allow"}], "analysis_complete": True}

    if contract == "tripwire_result":
        signals = [_tripwire_signal(value) or _dict_boolean_signal(value)
                   for returned in returns for value in _return_alternatives(returned)]
        if "present" in signals:
            return {"deny_capability": "present",
                    "evidence": [{"kind": "openai_tripwire_result"}], "analysis_complete": True}
        if signals and all(signal == "absent" for signal in signals):
            return {"deny_capability": "absent",
                    "evidence": [{"kind": "openai_tripwire_always_false"}], "analysis_complete": True}

    if contract == "around_handler":
        handler_names = {arg.arg for function in functions
                         if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
                         for arg in (*function.args.posonlyargs, *function.args.args)
                         if arg.arg == "handler"}
        handler_calls = sum(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                            and node.func.id in handler_names
                            for function in functions for node in ast.walk(function))
        return {"deny_capability": "unknown",
                "evidence": [{"kind": "around_middleware_handler_calls", "count": handler_calls}],
                "analysis_complete": False}

    return {"deny_capability": "unknown",
            "evidence": [{"kind": "denial_signal_unclassified"}],
            "analysis_complete": False}
