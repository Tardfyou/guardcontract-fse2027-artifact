"""Recognize explicit constant tuple verdicts without inferring relocation safety."""
import ast

from guardcontract.analysis.langchain_paths import function, Unsupported


def inspect(source, symbol):
    result = {"verdict_dependency": "unknown", "constant_verdict": None,
              "relocation_safe": False, "runtime_verified": False}
    try:
        node = function(ast.parse(source), symbol)
    except (SyntaxError, Unsupported):
        return result
    statements = list(node.body)
    if statements and isinstance(statements[0], ast.Expr) and isinstance(statements[0].value, ast.Constant) and isinstance(statements[0].value.value, str):
        statements.pop(0)
    if not statements or not isinstance(statements[-1], ast.Return):
        return result
    # Only deleted local parameters may precede the unconditional return.
    parameters = {arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}
    deleted = set()
    for statement in statements[:-1]:
        if not isinstance(statement, ast.Delete):
            return result
        for target in statement.targets:
            if not isinstance(target, ast.Name) or target.id not in parameters or target.id in deleted:
                return result
            deleted.add(target.id)
    value = statements[-1].value
    if not isinstance(value, ast.Tuple) or len(value.elts) != 2:
        return result
    verdict, data = value.elts
    if not isinstance(verdict, ast.Constant) or type(verdict.value) is not bool:
        return result
    if any(isinstance(n, ast.Name) and n.id in deleted for n in ast.walk(data)):
        return result
    return {**result, "verdict_dependency": "explicit_constant", "constant_verdict": verdict.value,
            "return_line": statements[-1].lineno,
            "boundary": "Boolean tuple element only. Evaluating return data may read output, raise or cause effects; no move-before-effect authorization."}
