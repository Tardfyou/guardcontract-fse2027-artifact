"""Authenticate parent artifacts and the complete standard wire request for reuse."""
import hashlib
import json
from pathlib import Path


def authenticate_parent(root,parent):
    root=Path(root).resolve();parent=Path(parent).resolve()
    manifest=json.loads((parent/'RUN_MANIFEST.json').read_text())
    if manifest.get('execution_health')!='completed' or manifest.get('input_drift'):
        raise ValueError('recorded_parent_not_completed')
    for name,expected in manifest['artifacts'].items():
        p=root/name
        if p.is_symlink() or not p.resolve().is_relative_to(root) or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:
            raise ValueError('recorded_parent_artifact_drift')
    for name in ('REVIEWS.json','ACCOUNTING.json','PREDICTION_SEAL.json','PREDICTIONS.json','ARMS.json'):
        p=parent/name
        if manifest['artifacts'].get(str(p.relative_to(root)))!=hashlib.sha256(p.read_bytes()).hexdigest():
            raise ValueError('recorded_parent_required_artifact_missing')
    return manifest


def validate_wire_request(parent,role,payload,plan,system):
    paths=list((Path(parent)/role/'calls').glob('call-*/REQUEST.raw'))
    if len(paths)!=1:raise ValueError('recorded_wire_request_inventory')
    request={'model':plan['model'],'temperature':0,'max_tokens':plan['max_tokens'],
        'response_format':{'type':'json_object'},'messages':[{'role':'system','content':system},
            {'role':'user','content':json.dumps(payload,sort_keys=True)}]}
    expected=json.dumps(request,separators=(',',':')).encode()
    if paths[0].read_bytes()!=expected:raise ValueError('recorded_wire_request_changed')
    metadata=json.loads((paths[0].parent/'CALL.json').read_text())
    if metadata['request_sha256']!=hashlib.sha256(expected).hexdigest():raise ValueError('recorded_wire_request_hash_mismatch')
    if metadata.get('provider_model')!=plan['model'] or metadata.get('finish_reason')!='stop':raise ValueError('recorded_provider_identity')
    return {'request_sha256':metadata['request_sha256'],'complete_wire_request_equal':True,
        'covers':['system_prompt','source_only_user_payload','model','temperature','output_budget','response_format']}
