"""Build SDK argument schemas from inert signatures, never from source bodies."""
import ast
import importlib.metadata
import inspect
import typing

from guardcontract.evaluation.scoped_issue import digest


class ArgumentProfileError(ValueError):
    pass


BUILTINS={'str':str,'int':int,'float':float,'bool':bool,'dict':dict,'list':list,'tuple':tuple,
          'Any':typing.Any,'Optional':typing.Optional,'Union':typing.Union,'List':typing.List,
          'Dict':typing.Dict,'Tuple':typing.Tuple,'Literal':typing.Literal}


def annotation(node):
    if node is None:return typing.Any
    if isinstance(node,ast.Name) and node.id in BUILTINS:return BUILTINS[node.id]
    if isinstance(node,ast.Constant) and node.value is None:return type(None)
    if isinstance(node,ast.BinOp) and isinstance(node.op,ast.BitOr):return typing.Union[annotation(node.left),annotation(node.right)]
    if isinstance(node,ast.Subscript):
        base=annotation(node.value)
        parts=node.slice.elts if isinstance(node.slice,ast.Tuple) else [node.slice]
        values=tuple(ast.literal_eval(n) for n in parts) if base is typing.Literal else tuple(annotation(n) for n in parts)
        try:return base[values[0] if len(values)==1 else values]
        except (TypeError,KeyError):pass
    raise ArgumentProfileError('source_annotation_not_in_closed_type_profile')


def schema_for(function):
    from langchain_core.tools.base import create_schema_from_function
    if function.args.posonlyargs or function.args.vararg or function.args.kwarg:
        raise ArgumentProfileError('sdk_signature_shape_unsupported')
    args=function.args.args+function.args.kwonlyargs
    if any(a.arg in {'run_manager','callbacks'} for a in args):
        raise ArgumentProfileError('injected_sdk_arguments_require_separate_profile')
    defaults={a.arg:v for a,v in zip(function.args.args[-len(function.args.defaults):],function.args.defaults)} if function.args.defaults else {}
    defaults.update({a.arg:v for a,v in zip(function.args.kwonlyargs,function.args.kw_defaults) if v is not None})
    params=[];annotations={}
    for arg in args:
        typ=annotation(arg.annotation);annotations[arg.arg]=typ
        try:default=ast.literal_eval(defaults[arg.arg]) if arg.arg in defaults else inspect.Parameter.empty
        except (ValueError,TypeError):raise ArgumentProfileError('nonliteral_signature_default')
        kind=inspect.Parameter.KEYWORD_ONLY if arg in function.args.kwonlyargs else inspect.Parameter.POSITIONAL_OR_KEYWORD
        params.append(inspect.Parameter(arg.arg,kind,default=default,annotation=typ))
    def inert_signature(**kwargs):
        raise RuntimeError('signature_stub_must_never_execute')
    inert_signature.__signature__=inspect.Signature(params)
    inert_signature.__annotations__=annotations
    return create_schema_from_function(function.name,inert_signature,filter_args=[])


def normalize(function,arguments):
    schema=schema_for(function)
    try:effective=schema.model_validate(arguments).model_dump()
    except Exception as exc:raise ArgumentProfileError('sdk_argument_validation_failed:'+type(exc).__name__) from exc
    return effective,{'raw_arguments':arguments,'effective_arguments':effective,
        'schema_sha256':digest(schema.model_json_schema()),
        'profile':'langchain-inert-signature-normalization-1',
        'versions':{name:importlib.metadata.version(name) for name in ('langchain-core','pydantic')},
        'source_body_executed':False}
