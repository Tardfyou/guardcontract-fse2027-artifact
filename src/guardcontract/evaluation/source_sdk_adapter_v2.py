"""Origin-, scenario- and profile-authenticated adapter for bounded SDK traces."""
import ast
import hashlib
import json
from pathlib import Path

from guardcontract.evaluation.source_sdk_adapter import observations as base_observations
from guardcontract.runtime.approval_slice import sha,extract,audit


PROFILE='synchronous-source-capabilities-2'
REQUIRED_CODE=('tools/run_scoped_source_sdk_oracle.py','tools/run_approval_source_sdk_oracle.py',
               'src/guardcontract/runtime/approval_slice.py')


def validate_receipt(item,trace,marker_root,*,instrumentation_sha256,base_runner_sha256):
    role=trace['decision']
    cases=[c for c in item['cases'] if c['expected_verdict']==role]
    if len(cases)!=1 or trace.get('stimulus')!=cases[0]:raise ValueError('runtime_stimulus_mismatch')
    iid=hashlib.sha256((item['sample_id']+':'+role).encode()).hexdigest()[:24]
    if cases[0].get('invocation_id')!=iid or trace.get('invocation_id')!=iid:
        raise ValueError('runtime_invocation_identity')
    if trace.get('expected_marker')!=iid+'.marker':raise ValueError('runtime_marker_case_identity')
    receipt=trace.get('origin_receipt')
    if not isinstance(receipt,dict) or receipt.get('profile')!=PROFILE:
        raise ValueError('runtime_origin_profile_missing')
    if receipt.get('instrumentation_sha256')!=instrumentation_sha256 or receipt.get('base_runner_sha256')!=base_runner_sha256:
        raise ValueError('runtime_origin_code_mismatch')
    initial={'name':item['effect']['symbol'],'args':item['tool_arguments'],'id':iid,'type':'tool_call'}
    actual=dict(receipt['initial_tool_request'])
    # LangChain versions may omit the optional type tag from ToolCallRequest.
    actual.setdefault('type','tool_call')
    if actual!=initial:raise ValueError('runtime_initial_tool_request_mismatch')
    if trace.get('guard_verdict')=='DENY' and receipt.get('guard_return_origin')!='guard_constructor':
        raise ValueError('runtime_deny_not_guard_origin')
    calls=receipt.get('effect_calls')
    if not isinstance(calls,list) or any(c.get('phase')!='tool' for c in calls):
        raise ValueError('runtime_effect_origin')
    markers=trace.get('independent_markers',[])
    if len(calls)!=len(markers) or (calls and not receipt.get('tool_invocations')):
        raise ValueError('runtime_effect_call_inventory')
    for call,marker in zip(calls,markers):
        path=marker_root/marker['relative_path']
        payload=json.loads(path.read_text())
        if payload!={'invocation_id':iid,'args':call['args'],'kwargs':call['kwargs']}:
            raise ValueError('runtime_effect_payload_mismatch')
    return iid


def observations(root,queue_path,runtime_dir,scope_bindings,*,manifest_sha256):
    root=Path(root).resolve()
    manifest=json.loads((runtime_dir/'RUN_MANIFEST.json').read_text())
    if manifest.get('runtime_profile')!=PROFILE:raise ValueError('unsupported_runtime_profile')
    for name in REQUIRED_CODE:
        if manifest['behavior_inputs'].get(name)!=sha(root/name):raise ValueError('runtime_code_not_authenticated')
    for path in [runtime_dir/'RESULT.json',runtime_dir/'RUN_PLAN.json',runtime_dir/'DEPENDENCIES.json']:
        if manifest['artifacts'].get(str(path.relative_to(root)))!=sha(path):
            raise ValueError('required_runtime_artifact_not_authenticated')
    scope_path=queue_path.parent/'SCOPES.json'
    if manifest['behavior_inputs'].get(str(scope_path.relative_to(root)))!=sha(scope_path):
        raise ValueError('runtime_scope_manifest_not_authenticated')
    if scope_bindings!=json.loads(scope_path.read_text())['bindings']:
        raise ValueError('runtime_scope_binding_inventory')
    queue=json.loads(queue_path.read_text());runtime=json.loads((runtime_dir/'RESULT.json').read_text())
    items={r['sample_id']:r for r in queue['rows']};ids=set()
    for row in runtime['rows']:
        item=items[row['sample_id']]
        files={f['path']:f['sha256'] for f in item['inventory']}
        for key,calls in [('guard',{'input','print','confirm.lower','ToolMessage','handler','request.tool_call.get','st.session_state.get'}),
                          ('effect',{'os.getenv','requests.get','response.json','data.get','str','print'})]:
            part=item[key];path=queue_path.parent/'sources'/item['root']/part['path']
            if manifest['behavior_inputs'].get(str(path.relative_to(root)))!=files[part['path']]:
                raise ValueError('source_profile_input_not_authenticated')
            node=extract(path,part['symbol'],files[part['path']]);audit(node,calls)
            if any(isinstance(n,(ast.AsyncFunctionDef,ast.Await,ast.Yield,ast.YieldFrom)) for n in ast.walk(node)):
                raise ValueError('source_profile_has_async_capability')
        for trace in row.get('traces',[]):
            iid=validate_receipt(item,trace,runtime_dir/'markers',
                instrumentation_sha256=sha(root/REQUIRED_CODE[0]),base_runner_sha256=sha(root/REQUIRED_CODE[1]))
            if iid in ids:raise ValueError('duplicate_runtime_invocation')
            ids.add(iid)
    # Completed process + authenticated synchronous capability profile closes
    # this observation window; absence of a pending flag is not the evidence.
    return base_observations(root,queue_path,runtime_dir,scope_bindings,manifest_sha256=manifest_sha256)
