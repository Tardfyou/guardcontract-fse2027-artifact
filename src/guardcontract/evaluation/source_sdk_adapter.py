"""Recompute observations from the authenticated constrained source SDK runner.

Only this local adapter converts runtime records into scoped observations.
Policy meaning is enrolled independently; scope bytes alone do not establish it.
"""
import json
from pathlib import Path

from guardcontract.runtime.approval_slice import sha,source_identity
from guardcontract.evaluation.scoped_issue import digest,validate_scope
from tools.independent_trace_oracle import evaluate


SCENARIO_FIELDS=('guard','effect','registration','inventory','cases','tool_arguments',
                 'environment','http_response','denial_messages')


def scenario(item):
    return {k:item[k] for k in SCENARIO_FIELDS}


def observations(root,queue_path,runtime_dir,scope_bindings,*,manifest_sha256):
    root=Path(root).resolve()
    manifest_path=runtime_dir/'RUN_MANIFEST.json'
    if sha(manifest_path)!=manifest_sha256:raise ValueError('runtime_manifest_identity')
    manifest=json.loads(manifest_path.read_text())
    for name,expected in manifest['behavior_inputs'].items():
        path=root/name
        if path.is_symlink() or not path.resolve().is_relative_to(root) or sha(path)!=expected:
            raise ValueError('runtime_behavior_input_drift')
    for name,expected in manifest['artifacts'].items():
        path=root/name
        if path.is_symlink() or not path.resolve().is_relative_to(root) or sha(path)!=expected:
            raise ValueError('runtime_output_drift')
    if manifest['behavior_inputs'].get(str(queue_path.relative_to(root)))!=sha(queue_path):
        raise ValueError('runtime_queue_not_enrolled')
    command=manifest['command']
    for flag,value in [('--network','none'),('--cap-drop','ALL'),('--security-opt','no-new-privileges')]:
        if flag not in command or command[command.index(flag)+1]!=value:raise ValueError('runtime_isolation_profile')
    if '--read-only' not in command or '--user' not in command:
        raise ValueError('runtime_isolation_profile')
    if any(int(part)==0 for part in command[command.index('--user')+1].split(':')):
        raise ValueError('runtime_root_user')
    if manifest['returncode']!=0 or manifest['execution_health']!='completed':
        raise ValueError('runtime_not_completed')
    queue=json.loads(queue_path.read_text())
    runtime=json.loads((runtime_dir/'RESULT.json').read_text())
    items={r['sample_id']:r for r in queue['rows']}
    traces={r['sample_id']:r for r in runtime['rows']}
    if len(items)!=len(queue['rows']) or len(traces)!=len(runtime['rows']) or set(items)!=set(traces):
        raise ValueError('runtime_row_inventory')
    recomputed=evaluate(queue_path,runtime_dir/'RESULT.json',runtime_dir/'markers')
    enrolled={r['sample_id'] for r in scope_bindings}
    if set(items)-enrolled:raise ValueError('runtime_unenrolled_item')
    outputs=[]
    for binding in scope_bindings:
        sid=binding['sample_id']
        if sid not in items:continue
        item=items[sid]
        scope=validate_scope(binding['scope'])
        scenario_id=digest(scenario(item))
        if scenario_id not in scope['scenarios'] or scope['scenarios'][scenario_id]!=scenario(item):
            raise ValueError('runtime_scenario_not_in_scope')
        if scope['subject']['source_inventory_sha256']!=source_identity(item):
            raise ValueError('runtime_source_scope_mismatch')
        expected={'guard_sha256':digest(item['guard']), 'effect_sha256':digest(item['effect']),
                  'registration_sha256':digest(item['registration'])}
        if any(scope['subject'][k]!=v for k,v in expected.items()):raise ValueError('runtime_subject_scope_mismatch')
        dependencies=runtime_dir/'DEPENDENCIES.json'
        sdk_id=digest({'image_id':manifest['image_id'],'dependencies_sha256':sha(dependencies)})
        if scope['subject']['sdk_environment_sha256']!=sdk_id:raise ValueError('runtime_sdk_scope_mismatch')
        label=recomputed['labels'][sid]
        for trace in traces[sid].get('traces',[]):
            kinds=[e.get('kind') for e in trace.get('events',[])]
            if (trace.get('status')!='passed' or trace.get('observed',{}).get('guard_calls')!=1
                    or kinds.count('sdk_invocation_completed')!=1
                    or kinds.index('sdk_invocation_completed')<kinds.index('guard_verdict')
                    or trace.get('pending_effect_tasks',0)!=0):
                label='unknown'
        outputs.append({'scope_id':scope['scope_id'],'scenario_id':scenario_id,'label':label,
                        'evidence_sha256':digest({'runtime_manifest_sha256':manifest_sha256,
                            'recomputed_record':next(r for r in recomputed['records'] if r['sample_id']==sid)})})
    return outputs
