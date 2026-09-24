"""Check explicit ALLOW-branch placement; never claim whole-program safety."""
import ast

from guardcontract.analysis.langchain_paths import dotted, function


def validate(source, guard_symbol, sink_call, decision="verdict", allow="ALLOW", expected_writes=1):
    tree = ast.parse(source)
    guard = function(tree, guard_symbol)
    writes = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and dotted(node.func) == sink_call]
    branches = [node for node in guard.body if isinstance(node, ast.If)
                and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name)
                and node.test.left.id == decision and len(node.test.ops) == len(node.test.comparators) == 1
                and isinstance(node.test.ops[0], ast.Eq)
                and isinstance(node.test.comparators[0], ast.Constant)
                and node.test.comparators[0].value == allow]
    if len(writes) != expected_writes or len(branches) != 1:
        raise ValueError("guarded_write_count_or_allow_predicate")
    # Inspect only the true branch, never the enclosing If including its else arm.
    allowed = {id(node) for statement in branches[0].body for node in ast.walk(statement)}
    if any(id(write) not in allowed for write in writes):
        raise ValueError("write_outside_allow_branch")
    return {"allow_branch_placement_verified": True, "whole_program_safety_verified": False,
            "writes": len(writes), "boundary": "Exact syntactic sink and branch only; aliases, mutations, callbacks, exceptions and runtime behavior need independent verification."}
