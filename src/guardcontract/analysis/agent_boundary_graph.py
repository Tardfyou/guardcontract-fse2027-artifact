"""Recover literal agent/as-tool/handoff topology without executing source.

SDK ordering is a separate, versioned premise. A handoff edge crosses the
first-turn input-guard join; an agent-as-tool edge does not. Unknown bindings
remain gaps. This graph alone never supplies a behavior label.
"""
import ast


def recover(source,root_agent,target_tool):
    tree=ast.parse(source);agents={};agent_tools={};values={};functions=set();gaps=[]
    imported={a.asname or a.name:(n.module,a.name) for n in tree.body if isinstance(n,ast.ImportFrom) for a in n.names}
    if imported.get('Agent')!=('agents','Agent'):
        return {'status':'unknown','reason':'sdk_agent_import_unbound','paths':[]}
    def names(node,resolving=frozenset()):
        if isinstance(node,ast.Name):
            if node.id in resolving:gaps.append('cyclic_binding');return []
            if node.id in values:return names(values[node.id],resolving|{node.id})
            return [node.id]
        if isinstance(node,(ast.List,ast.Tuple)):
            out=[]
            for n in node.elts:out.extend(names(n,resolving))
            return out
        gaps.append('dynamic_registration');return []
    for n in tree.body:
        if isinstance(n,ast.ImportFrom) and any(a.name=='*' for a in n.names):gaps.append('wildcard_import')
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
            functions.add(n.name)
        if not isinstance(n,ast.Assign) or len(n.targets)!=1 or not isinstance(n.targets[0],ast.Name):continue
        name=n.targets[0].id;value=n.value
        if name=='Agent':gaps.append('sdk_agent_name_rebound')
        if isinstance(value,ast.Call) and isinstance(value.func,ast.Name) and value.func.id=='Agent':
            kw={k.arg:k.value for k in value.keywords}
            agents[name]={'tools':names(kw['tools']) if 'tools' in kw else [],
                          'handoffs':names(kw['handoffs']) if 'handoffs' in kw else [],
                          'input_guards':names(kw['input_guardrails']) if 'input_guardrails' in kw else [],
                          'line':n.lineno}
        elif isinstance(value,ast.Call) and isinstance(value.func,ast.Attribute) and value.func.attr=='as_tool' and isinstance(value.func.value,ast.Name):
            agent_tools[name]=value.func.value.id
        elif isinstance(value,(ast.Name,ast.List,ast.Tuple)):
            values[name]=value
    paths=[]
    def walk(agent,path,joins,seen):
        if agent in seen:gaps.append('agent_cycle');return
        if agent not in agents:gaps.append('unresolved_agent:'+agent);return
        seen=seen|{agent}
        for tool in agents[agent]['tools']:
            step={'kind':'tool','owner':agent,'target':tool}
            if tool==target_tool:paths.append({'edges':path+[step],'handoff_joins':joins})
            elif tool in agent_tools:walk(agent_tools[tool],path+[dict(step,kind='agent_as_tool')],joins,seen)
            elif tool not in functions:gaps.append('unresolved_tool:'+tool)
        for target in agents[agent]['handoffs']:
            walk(target,path+[{'kind':'handoff','owner':agent,'target':target}],joins+1,seen)
    walk(root_agent,[],0,set())
    status='unknown' if gaps or not paths else ('requires_handoff_join' if all(p['handoff_joins']>0 for p in paths) else 'reachable_in_first_turn')
    return {'status':status,'paths':paths,'gaps':sorted(set(gaps)),
            'agents':agents,'agent_tools':agent_tools,
            'root_input_guards':agents.get(root_agent,{}).get('input_guards',[]),
            'sdk_barrier_verified':False,'behavior_label':None}
