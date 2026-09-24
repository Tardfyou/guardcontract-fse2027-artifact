"""Bind arguments with the SDK parser without invoking the source function."""
import ast
from copy import deepcopy
import importlib.metadata
import json
from guardcontract.analysis.sdk_arguments import schema_for,ArgumentProfileError
from guardcontract.evaluation.scoped_issue import digest


def literal_defaults(function):
    pairs=list(zip(function.args.args[-len(function.args.defaults):],function.args.defaults)) if function.args.defaults else []
    pairs.extend((a,v) for a,v in zip(function.args.kwonlyargs,function.args.kw_defaults) if v is not None)
    return {a.arg:ast.literal_eval(v) for a,v in pairs}


def normalize(function,arguments,*,default_state=None):
    # Check the closed JSON value domain without serializing it into a new
    # object graph: guard-created aliases must survive SDK validation.
    json.dumps(arguments,allow_nan=False)
    before=deepcopy(arguments)
    schema=schema_for(function)
    from langchain_core.tools import StructuredTool
    def never_execute(**kwargs):raise RuntimeError('signature_stub_must_never_execute')
    inert=StructuredTool(name=function.name,description='Inert source signature',args_schema=schema,func=never_execute)
    try:parsed=inert._parse_input(arguments,None)
    except Exception as exc:raise ArgumentProfileError('sdk_argument_validation_failed:'+type(exc).__name__) from exc
    defaults=literal_defaults(function) if default_state is None else default_state
    # The enrolled SDK also injects schema defaults (fresh per validation).
    # Use its parser rather than reproducing version-dependent field selection.
    # Only parameters it omits fall back to Python's function default objects.
    effective=dict(defaults)
    effective.update(parsed)
    receipt={'raw_arguments':before,'effective_arguments':deepcopy(effective),
        'schema_sha256':digest(schema.model_json_schema()),'profile':'langchain-identity-preserving-argument-binding-2',
        'versions':{name:importlib.metadata.version(name) for name in ('langchain-core','pydantic')},
        'source_body_executed':False,'default_semantics':'SDK parser defaults first; Python function defaults only for omitted keys'}
    return effective,receipt
