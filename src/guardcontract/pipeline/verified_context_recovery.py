"""Accept source-retrieval proposals only after recomputing a scoped proof.

The caller supplies the trusted frozen source inventory and scenario. A proposer
can name additional source files, but cannot supply source text, labels, new
stimuli, a different effect, or a proof. Source is parsed, never executed here.
This adapter currently uses the synchronous LangChain closure verifier; it is
not a verifier for arbitrary protection-obligation prose or whole applications.
"""
from copy import deepcopy
import ast
import hashlib
import json
from pathlib import PurePosixPath

from guardcontract.analysis.source_closure_v3 import enroll
from guardcontract.analysis.closure_interpreter_v1 import predict
from guardcontract.analysis.scenario_interpreter_v4 import captured_dispatch_profile


PROFILE = 'verified-source-retrieval-synchronous-closure-1'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _path(path):
    if (not isinstance(path, str) or not path or '\\' in path
            or PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts
            or str(PurePosixPath(path)) != path or not path.endswith('.py')):
        raise ValueError('recovery_source_path')
    return path


def make_request(item, source_inventory, initial_paths):
    """Source inventory and scenario are trusted enrollment inputs, not model data."""
    if not isinstance(source_inventory, dict) or not source_inventory:
        raise ValueError('recovery_inventory_required')
    for path, value in source_inventory.items():
        _path(path)
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('recovery_source_digest')
    paths = [_path(p) for p in initial_paths]
    if len(paths) != len(set(paths)) or not set(paths) <= set(source_inventory):
        raise ValueError('recovery_initial_inventory')
    request = {'profile': PROFILE, 'scenario_sha256': digest(item),
               'source_inventory_sha256': digest(source_inventory), 'initial_paths': sorted(paths),
               'allowed_source_paths': sorted(source_inventory),
               'sdk_dispatch_profile': captured_dispatch_profile()}
    return {**request, 'request_sha256': digest(request)}


def missing_local_imports(sources, source_inventory):
    """Never treat a withheld local module as an installed external package."""
    modules = {}
    for path in source_inventory:
        module = path[:-3].replace('/', '.')
        if module.endswith('.__init__'):
            module = module[:-9]
        modules.setdefault(module, []).append(path)
    missing = set()
    for path, source in sources.items():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                name = node.module or ''
                if node.level:
                    package = path[:-3].split('/')[:-1]
                    if node.level > len(package):
                        raise ValueError('recovery_invalid_relative_import')
                    name = '.'.join(package[:len(package) - node.level + 1] + ([name] if name else []))
                names = [name, *[name + '.' + a.name for a in node.names if a.name != '*']]
            for name in names:
                parts = name.split('.')
                for i in range(1, len(parts) + 1):
                    for candidate in modules.get('.'.join(parts[:i]), []):
                        if candidate not in sources:
                            missing.add(candidate)
    return sorted(missing)


def _derive(item, sources, source_inventory):
    try:
        missing = missing_local_imports(sources, source_inventory)
        if missing:
            return {'prediction': 'unknown', 'status': 'missing_source',
                    'reason': 'local_import_frontier_not_closed', 'missing_source_paths': missing,
                    'traces': [], 'closure_receipt': None}
        closure = enroll(sources, item)
        result = predict(closure, item)
        return {**result, 'closure_receipt': closure.receipt()}
    except (ValueError, KeyError, TypeError, SyntaxError) as exc:
        return {'prediction': 'unknown', 'status': 'unsupported',
                'reason': str(exc), 'traces': [], 'closure_receipt': None}


def recover(item, source_inventory, available_sources, initial_paths, proposal, *, max_files=128, max_source_bytes=2_000_000):
    """A proposed retrieval can add a checked proof, never a model verdict."""
    request = make_request(item, source_inventory, initial_paths)
    if (not isinstance(proposal, dict)
            or set(proposal) != {'request_sha256', 'additional_source_paths'}
            or proposal['request_sha256'] != request['request_sha256']):
        raise ValueError('recovery_proposal_binding')
    extra = proposal['additional_source_paths']
    if not isinstance(extra, list) or len(extra) != len(set(extra)):
        raise ValueError('recovery_proposal_inventory')
    extra = [_path(p) for p in extra]
    if not set(extra) <= set(source_inventory):
        raise ValueError('recovery_proposal_unenrolled_source')
    selected = sorted(set(initial_paths) | set(extra))
    sources = {}
    for path in selected:
        source = available_sources.get(path)
        if (not isinstance(source, str)
                or hashlib.sha256(source.encode()).hexdigest() != source_inventory[path]):
            raise ValueError('recovery_source_drift')
        sources[path] = source
    base = {'schema_version': PROFILE, 'sample_id': item['sample_id'],
            'request_sha256': request['request_sha256'], 'scenario_sha256': request['scenario_sha256'],
            'proposal_sha256': digest(proposal), 'selected_source_sha256': {p: source_inventory[p] for p in selected},
            'source_bodies_executed': False, 'oracle_read': False, 'model_verdict_accepted': False,
            'scope': 'Frozen synchronous source-closure scenarios only; not open-domain application safety.'}
    if len(selected) > max_files or sum(len(s.encode()) for s in sources.values()) > max_source_bytes:
        return {**base, 'prediction': 'unknown', 'status': 'budget_deferred',
                'reason': 'recovery_verification_budget', 'baseline': None, 'verified': None,
                'release_certificate': None}
    baseline = _derive(deepcopy(item), {p: sources[p] for p in initial_paths}, source_inventory)
    checked = _derive(deepcopy(item), sources, source_inventory)
    label = checked['prediction']
    certificate = None
    if label != 'unknown' and checked['status'] == 'completed':
        certificate = {'rule': PROFILE, 'request_sha256': request['request_sha256'],
                       'scenario_sha256': request['scenario_sha256'],
                       'source_inventory_sha256': request['source_inventory_sha256'],
                       'derivation_sha256': digest(checked), 'prediction': label,
                       'scope_limited': True, 'runtime_observations_read': False}
    else:
        label = 'unknown'
    return {**base, 'prediction': label, 'status': checked['status'],
            'reason': checked.get('reason'), 'baseline': baseline, 'verified': checked,
            'recovered_unknown': baseline['prediction'] == 'unknown' and label != 'unknown',
            'release_certificate': certificate}
