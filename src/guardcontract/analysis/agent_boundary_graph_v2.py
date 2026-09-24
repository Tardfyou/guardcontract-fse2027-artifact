"""Interpret recovered handoff edges relative to the guarded root run.

A handoff inside an agent-as-tool subrun does not cross its caller's input
guard join. Keep the first graph implementation frozen for its replay artifact.
"""
from guardcontract.analysis.agent_boundary_graph import recover as recover_topology


def recover(source,root_agent,target_tool,guard_symbol):
    result=recover_topology(source,root_agent,target_tool)
    paths=[{**p,'root_guard_joins':sum(e['kind']=='handoff' and e['owner']==root_agent for e in p['edges'])}
           for p in result['paths']]
    if result['gaps'] or not paths or guard_symbol not in result['root_input_guards']:
        status='unknown'
    elif all(p['root_guard_joins'] for p in paths):status='requires_root_guard_join'
    else:status='reachable_before_root_guard_join'
    return {**result,'status':status,'paths':paths,'guard_symbol':guard_symbol,
            'claim_boundary':'Literal source topology only; SDK join semantics and bounded behavior require independent enrollment.'}
