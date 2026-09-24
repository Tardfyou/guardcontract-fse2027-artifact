"""Bounded source evaluation of the pinned request object's mutable data.

Only registered plain-data operations are supported; no source is executed.
Callback observations are argument snapshots, never protected-effect events.
"""
import ast
from dataclasses import dataclass, replace
import hashlib

from guardcontract.analysis.request_data import DataDomainError, snapshot


class Unknown(ValueError):
    pass


@dataclass(eq=False)
class Request:
    tool_call: dict
    state: object


class Flow:
    def __init__(self, source, initial, bindings):
        self.source = source
        self.tree = ast.parse(source)
        self.initial = Request(snapshot(initial), {})
        self.initial_tool_call = self.initial.tool_call
        self.initial_args = self.initial.tool_call.get("args")
        self.env = {"request": self.initial, "handler": self.callback, **bindings}
        self.calls, self.events = [], []
        self.returned = False
        self.steps = 0

    def callback(self, request):
        if len(self.calls) >= 64:
            raise Unknown("callback_observation_budget")
        if not isinstance(request, Request):
            raise Unknown("callback_non_request")
        self.calls.append({"tool_call": snapshot(request.tool_call), "same_request_object": request is self.initial,
                           "same_initial_tool_call_object": request.tool_call is self.initial_tool_call,
                           "same_initial_args_object": request.tool_call.get("args") is self.initial_args})
        return None

    def value(self, node):
        self.steps += 1
        if self.steps > 512:
            raise Unknown("expression_budget")
        if isinstance(node, ast.Constant) and type(node.value) in {str, bool, int, type(None)}:
            return node.value
        if isinstance(node, ast.Name) and node.id in self.env:
            return self.env[node.id]
        if isinstance(node, ast.Attribute):
            owner = self.value(node.value)
            if isinstance(owner, Request) and node.attr in {"tool_call", "state"}:
                return getattr(owner, node.attr)
            raise Unknown("unregistered_attribute")
        if isinstance(node, ast.Subscript):
            owner, key = self.value(node.value), self.value(node.slice)
            if type(owner) is dict and type(key) in {str, int, bool}:
                return owner[key]
            raise Unknown("unregistered_subscript")
        if isinstance(node, ast.Dict):
            result = {}
            for key_node, value_node in zip(node.keys, node.values, strict=True):
                if key_node is None:
                    value = self.value(value_node)
                    if type(value) is not dict:
                        raise Unknown("non_dict_unpack")
                    result.update(value)
                else:
                    key = self.value(key_node)
                    if type(key) not in {str, int, bool}:
                        raise Unknown("non_scalar_key")
                    result[key] = self.value(value_node)
            return result
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.value(node.operand)
            if type(value) is not bool:
                raise Unknown("non_boolean_condition")
            return not value
        if isinstance(node, ast.Call):
            return self.call(node)
        raise Unknown("expression_" + type(node).__name__)

    def call(self, node):
        if any(k.arg is None for k in node.keywords):
            raise Unknown("dynamic_keyword_unpack")
        # Resolve the callable before arguments, matching Python evaluation order.
        if isinstance(node.func, ast.Name):
            function = self.env.get(node.func.id)
            if function != self.callback:
                raise Unknown("unresolved_call")
            args = [self.value(a) for a in node.args]
            if len(args) != 1 or node.keywords:
                raise Unknown("callback_signature")
            self.events.append({"kind": "callback", "line": node.lineno})
            return self.callback(args[0])
        if not isinstance(node.func, ast.Attribute):
            raise Unknown("unresolved_callable")
        owner = self.value(node.func.value)
        name = node.func.attr
        args = [self.value(a) for a in node.args]
        keywords = {k.arg: self.value(k.value) for k in node.keywords}
        if isinstance(owner, Request) and name == "override" and not args and set(keywords) <= {"tool_call", "state"}:
            if "tool_call" in keywords and type(keywords["tool_call"]) is not dict:
                raise Unknown("override_non_dict_tool_call")
            self.events.append({"kind": "request_override", "line": node.lineno, "fields": sorted(keywords)})
            return replace(owner, **keywords)
        if type(owner) is dict and not keywords:
            if name == "get" and 1 <= len(args) <= 2:
                return owner.get(*args)
            if name == "copy" and not args:
                return owner.copy()
            if name == "update" and len(args) == 1 and type(args[0]) is dict:
                owner.update(args[0])
                self.events.append({"kind": "dict_update", "line": node.lineno})
                return None
        raise Unknown("unregistered_method")

    def assign(self, node, value):
        if isinstance(node, ast.Name):
            self.env[node.id] = value
            return
        if isinstance(node, ast.Subscript):
            owner, key = self.value(node.value), self.value(node.slice)
            if type(owner) is dict and type(key) in {str, int, bool}:
                owner[key] = value
                self.events.append({"kind": "dict_assignment", "line": node.lineno})
                return
        if isinstance(node, ast.Attribute):
            owner = self.value(node.value)
            if isinstance(owner, Request) and node.attr in {"tool_call", "state"}:
                if node.attr == "tool_call" and type(value) is not dict:
                    raise Unknown("assign_non_dict_tool_call")
                setattr(owner, node.attr, value)
                self.events.append({"kind": "request_assignment", "line": node.lineno})
                return
        raise Unknown("assignment_target")

    def block(self, statements):
        for node in statements:
            if self.returned:
                return
            self.steps += 1
            if self.steps > 512:
                raise Unknown("statement_budget")
            if isinstance(node, ast.Assign):
                value = self.value(node.value)
                for target in node.targets:
                    self.assign(target, value)
            elif isinstance(node, ast.Expr):
                self.value(node.value)
            elif isinstance(node, ast.Return):
                if node.value is not None:
                    self.value(node.value)
                self.returned = True
            elif isinstance(node, ast.If):
                value = self.value(node.test)
                if type(value) is not bool:
                    raise Unknown("non_boolean_branch")
                self.block(node.body if value else node.orelse)
            elif isinstance(node, ast.Pass):
                continue
            else:
                raise Unknown("statement_" + type(node).__name__)

    def run(self):
        if len(self.tree.body) != 1 or not isinstance(self.tree.body[0], ast.FunctionDef):
            raise Unknown("one_plain_wrapper_required")
        fn = self.tree.body[0]
        if fn.name != "wrapper" or fn.decorator_list or fn.returns or getattr(fn, "type_params", []):
            raise Unknown("wrapper_definition")
        args = fn.args
        if args.posonlyargs or args.kwonlyargs or args.kwarg or args.vararg or args.defaults or any(a.annotation for a in args.args):
            raise Unknown("wrapper_signature")
        names = [a.arg for a in args.args]
        if len(names) != len(set(names)) or set(names) != set(self.env):
            raise Unknown("wrapper_binding")
        self.block(fn.body)


def analyze(source, initial, *, bindings=None):
    result = {"task_version": "199-1", "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
              "scope": "controlled_plain_request_data_and_nonmutating_observer_callback",
              "callback_observations_are_not_effects": True, "effect_occurrence_proven": False}
    try:
        if set(bindings or {}) & {"request", "handler"} or any(type(v) is not bool for v in (bindings or {}).values()):
            raise Unknown("scenario_bindings")
        flow = Flow(source, initial, bindings or {})
        flow.run()
        final = snapshot(flow.initial.tool_call)
    except (Unknown, SyntaxError, KeyError, TypeError, AttributeError, ValueError) as exc:
        return {**result, "status": "unknown", "reason": str(exc) if isinstance(exc, (Unknown, DataDomainError)) else type(exc).__name__,
                "callback_snapshots": None, "original_final_tool_call": None}
    return {**result, "status": "supported", "callback_snapshots": flow.calls, "events": flow.events,
            "original_final_tool_call": final}
