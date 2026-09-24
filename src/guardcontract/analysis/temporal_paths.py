"""Bounded source paths for an explicitly contracted controlled IO interface.

This is a mechanism checker, not a Python interpreter or framework detector.
Only normal successful controlled-IO calls have the registered effect semantics.
"""
from copy import deepcopy
from dataclasses import dataclass, field
import ast
import hashlib

import z3

IO = object()


@dataclass
class State:
    condition: object
    events: list = field(default_factory=list)
    pending: list = field(default_factory=list)
    control: str = "normal"
    gaps: list = field(default_factory=list)

    def fork(self, condition):
        return State(condition, deepcopy(self.events), deepcopy(self.pending), self.control, list(self.gaps))


class Unsupported(ValueError):
    pass


class Paths:
    def __init__(self, source, bindings, max_steps=512):
        self.tree = ast.parse(source)
        self.source_sha256 = hashlib.sha256(source.encode()).hexdigest()
        self.functions = {}
        for node in self.tree.body:
            if not isinstance(node, ast.FunctionDef) or node.name in self.functions or node.name == "RuntimeError":
                raise Unsupported("module_requires_unique_plain_functions")
            if node.decorator_list or node.args.defaults or node.args.kw_defaults or node.args.vararg or node.args.kwarg or node.args.posonlyargs or node.args.kwonlyargs:
                raise Unsupported("function_signature_or_decorator")
            if node.returns is not None or any(a.annotation is not None for a in node.args.args) or getattr(node, "type_params", []):
                raise Unsupported("function_annotations")
            if len({a.arg for a in node.args.args}) != len(node.args.args):
                raise Unsupported("duplicate_parameters")
            self.functions[node.name] = node
        self.bindings = bindings
        self.steps, self.max_steps = 0, max_steps

    def feasible(self, condition):
        solver = z3.Solver()
        solver.set(timeout=1000)
        solver.add(condition)
        result = solver.check()
        if result == z3.unknown:
            raise Unsupported("solver_unknown")
        return result == z3.sat

    def value(self, node, env):
        if isinstance(node, ast.Name) and node.id in env:
            return env[node.id]
        if isinstance(node, ast.Constant) and type(node.value) in {bool, str, int, type(None)}:
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return z3.Not(self.boolean(self.value(node.operand, env)))
        if isinstance(node, ast.BoolOp):
            values = [self.boolean(self.value(v, env)) for v in node.values]
            return z3.And(*values) if isinstance(node.op, ast.And) else z3.Or(*values)
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            left, right = self.value(node.left, env), self.value(node.comparators[0], env)
            if left is IO or right is IO:
                raise Unsupported("io_comparison")
            equality = left == right
            return z3.Not(equality) if isinstance(node.ops[0], ast.NotEq) else equality
        raise Unsupported("expression_" + type(node).__name__)

    @staticmethod
    def boolean(value):
        if type(value) is bool or z3.is_bool(value):
            return value
        raise Unsupported("non_boolean_condition")

    def definite_bool(self, value, condition):
        value = self.boolean(value)
        yes, no = self.feasible(z3.And(condition, value)), self.feasible(z3.And(condition, z3.Not(value)))
        if yes and no:
            raise Unsupported("unresolved_primitive_boolean")
        return yes

    def call(self, call, state, env, stack):
        if call.keywords:
            raise Unsupported("keyword_call")
        if isinstance(call.func, ast.Name) and call.func.id in env:
            raise Unsupported("locally_shadowed_call")
        args = [self.value(arg, env) for arg in call.args]
        if isinstance(call.func, ast.Name) and call.func.id in self.functions:
            name = call.func.id
            if name in stack or len(stack) >= 8:
                raise Unsupported("recursive_or_deep_call")
            fn = self.functions[name]
            if len(fn.args.args) != len(args):
                raise Unsupported("call_arity")
            called = self.block(fn.body, [state], dict(zip((a.arg for a in fn.args.args), args)), (*stack, name))
            for result in called:
                if result.control == "return":
                    result.control = "normal"
            return called
        if not isinstance(call.func, ast.Attribute) or self.value(call.func.value, env) is not IO:
            raise Unsupported("unresolved_dispatch")
        method = call.func.attr
        event = {"kind": method, "line": call.lineno, "function": stack[-1]}
        if method in {"write", "stage"} and len(args) == 3 and all(type(a) is str for a in args):
            if args[1] not in {"resource-0", "resource-1"}:
                raise Unsupported("unregistered_resource")
            effect = dict(zip(("request", "resource", "payload"), args))
            state.events.append({**event, **effect})
            if method == "stage":
                state.pending.append(effect)
        elif method == "guard" and len(args) == 1:
            state.events.append({**event, "deny": self.definite_bool(args[0], state.condition)})
        elif method in {"commit", "abort"} and not args:
            state.events.append(event)
            if method == "commit":
                state.events.extend({**effect, "kind": "write", "line": call.lineno,
                                     "function": stack[-1], "origin": "pending_commit"} for effect in state.pending)
            state.pending = []
        else:
            raise Unsupported("unregistered_io_call")
        return [state]

    def statement(self, node, state, env, stack):
        self.steps += 1
        if self.steps > self.max_steps:
            raise Unsupported("step_budget")
        if isinstance(node, ast.Pass):
            return [state]
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            return self.call(node.value, state, env, stack)
        if isinstance(node, ast.If):
            test = self.boolean(self.value(node.test, env))
            rows = []
            for condition, body in ((z3.And(state.condition, test), node.body), (z3.And(state.condition, z3.Not(test)), node.orelse)):
                if self.feasible(condition):
                    rows.extend(self.block(body, [state.fork(condition)], env, stack))
            return rows
        if isinstance(node, ast.Return) and (node.value is None or isinstance(node.value, ast.Constant) and node.value.value is None):
            state.control = "return"
            return [state]
        if isinstance(node, ast.Raise):
            if "RuntimeError" in env:
                raise Unsupported("locally_shadowed_exception")
            if node.cause is not None or not isinstance(node.exc, ast.Call) or not isinstance(node.exc.func, ast.Name) or node.exc.func.id != "RuntimeError" or node.exc.args or node.exc.keywords:
                raise Unsupported("raise_shape")
            state.control = "raised"
            state.events.append({"kind": "raise", "line": node.lineno, "function": stack[-1]})
            return [state]
        if isinstance(node, ast.Try) and not node.handlers and not node.orelse:
            rows = []
            for result in self.block(node.body, [state], env, stack):
                if result.control == "unknown":
                    rows.append(result)
                    continue
                previous = result.control
                result.control = "normal"
                final = self.block(node.finalbody, [result], env, stack)
                for item in final:
                    if item.control == "normal":
                        item.control = previous
                rows.extend(final)
            return rows
        raise Unsupported("statement_" + type(node).__name__)

    def block(self, body, states, env, stack):
        for node in body:
            next_states = []
            for state in states:
                if state.control != "normal":
                    next_states.append(state)
                    continue
                try:
                    next_states.extend(self.statement(node, state, env, stack))
                except (Unsupported, z3.Z3Exception) as exc:
                    state.control = "unknown"
                    state.gaps.append({"line": node.lineno, "reason": str(exc) if isinstance(exc, Unsupported) else "solver_expression_error"})
                    next_states.append(state)
            states = next_states
        return states

    def run(self):
        entry = self.functions.get("run")
        if entry is None or {a.arg for a in entry.args.args} != {"io", *self.bindings}:
            raise Unsupported("entrypoint_binding")
        env, conditions = {"io": IO}, []
        for key, value in self.bindings.items():
            if type(value) is not bool:
                raise Unsupported("scenario_binding_type")
            env[key] = z3.Bool(key)
            conditions.append(env[key] == value)
        return self.block(entry.body, [State(z3.And(*conditions))], env, ("run",))


def analyze(source, *, deny, request="request-0", resource="resource-0", bindings=None):
    result = {"task_version": "196-2", "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
              "semantics": "controlled_io_196_successful_calls_only", "not_general_framework_detection": True}
    try:
        paths = Paths(source, {**(bindings or {}), "deny": deny}).run()
    except (Unsupported, SyntaxError) as exc:
        return {**result, "status": "unknown", "paths": [], "effect_count": None, "guard_reports_deny": None,
                "reason": str(exc) if isinstance(exc, Unsupported) else "syntax_error"}
    rows = []
    for path in paths:
        effects = [e for e in path.events if e["kind"] == "write" and e["request"] == request and e["resource"] == resource]
        rows.append({"condition": str(z3.simplify(path.condition)), "events": path.events,
                     "termination": path.control, "gaps": path.gaps, "effect_count": len(effects),
                     "guard_reports_deny": any(e["kind"] == "guard" and e["deny"] for e in path.events)})
    known = bool(rows) and all(r["termination"] != "unknown" for r in rows)
    counts = {r["effect_count"] for r in rows}
    guards = {r["guard_reports_deny"] for r in rows}
    return {**result, "status": "supported" if known else "unknown", "paths": rows,
            "effect_count": next(iter(counts)) if known and len(counts) == 1 else None,
            "guard_reports_deny": next(iter(guards)) if known and len(guards) == 1 else None}
