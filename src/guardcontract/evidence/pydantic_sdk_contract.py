"""Enroll Pydantic AI 2.40.0 tool/output-validator order from frozen controls."""
import hashlib,json
from pathlib import Path
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def enroll(directory):
    directory=Path(directory);generation=json.loads((directory/"GENERATION_RUN_MANIFEST.json").read_bytes());scoring=json.loads((directory/"SCORE_RUN_MANIFEST.json").read_bytes())
    raw_hash=next(r["sha256"] for r in generation["files"] if r["path"].endswith("/raw-result.json") and r["role"]=="artifact-output")
    score_hash=next(r["sha256"] for r in scoring["files"] if r["path"].endswith("/scored-result.json") and r["role"]=="artifact-output")
    if sha(directory/"raw-result.json")!=raw_hash or sha(directory/"scored-result.json")!=score_hash:raise ValueError("pydantic_contract_artifact_drift")
    raw=json.loads((directory/"raw-result.json").read_bytes());score=json.loads((directory/"scored-result.json").read_bytes())
    if not score["gate_passed"] or score["counts"]!={"completed":4,"passed_checks":14,"planned":4,"total_checks":14}:raise ValueError("pydantic_contract_gate")
    cells={(r["mode"],r["verdict"]):r for r in raw["cells"]}
    if len(cells)!=4 or [cells[("vulnerable",d)]["effect_count"] for d in ("ALLOW","DENY")]!=[1,1] or [cells[("repaired",d)]["effect_count"] for d in ("ALLOW","DENY")]!=[1,0]:raise ValueError("pydantic_contract_cells")
    contract={"schema_version":"pydantic-sdk-contract-1","framework_versions":{"pydantic-ai-slim":raw["framework"]["version"]},
        "facts":{"registered_tool_executes_before_output_validator":True,"output_validator_retry_occurs_after_tool":True,
                 "output_validator_allow_returns_final_output":True,"one_fixed_tool_request":True},
        "limits":["Agent.run_sync","TestModel one configured tool","retries zero","one output validator","normal local IO"],
        "evidence":{"raw_result_sha256":raw_hash,"scored_result_sha256":score_hash},"application_path_or_effect_verified":False}
    contract["contract_sha256"]=hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(",",":")).encode()).hexdigest();return contract
