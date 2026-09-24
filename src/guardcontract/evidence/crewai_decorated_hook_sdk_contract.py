"""Enroll CrewAI decorated-hook behavior over the frozen v1 source contract."""
import hashlib,json
from pathlib import Path
from guardcontract.evidence.crewai_sdk_contract import enroll as enroll_v1
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def enroll(metadata_path,task_path,tool_utils_path,hooks_path,result_path):
 base=enroll_v1(metadata_path,task_path,tool_utils_path,hooks_path);path=Path(result_path);result=json.loads(path.read_text())
 if result.get('schema_version')!='crewai-decorated-hook-contract-fixture-1' or result.get('execution_health')!='completed' or result.get('scientific_outcome')!='success' or result.get('public_repository_code_executed') is not False or result.get('telemetry_disabled') is not True or result.get('network_enforcement',{}).get('socket_creation_probe')!='EPERM':raise ValueError('crewai_decorated_hook_result')
 rows={(r['dialect'],r['decision']):r for r in result['rows']}
 if set(rows)!={(d,v) for d in ('before_tool_call','on') for v in ('ALLOW','DENY')} or not all(r['matches_contract'] for r in rows.values()):raise ValueError('crewai_decorated_hook_rows')
 if result['framework_versions']!=base['framework_versions']:raise ValueError('crewai_decorated_hook_versions')
 contract={'schema_version':'crewai-sdk-contract-2','framework_versions':base['framework_versions'],'facts':{**base['facts'],'decorated_before_tool_false_blocks_tool_invocation':True,'on_pre_tool_false_blocks_tool_invocation':True},'limits':[*base['limits'],'before_tool_call and on(PRE_TOOL_CALL) decorators','one inert dispatcher context'],'evidence':{'base_contract_sha256':base['contract_sha256'],'decorated_result':sha(path),'runtime_source':result['runtime_source']},'application_path_or_effect_verified':False}
 contract['contract_sha256']=hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(',',':')).encode()).hexdigest();return contract
