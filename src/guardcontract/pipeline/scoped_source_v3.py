"""Compose authenticated source slices, scoped prediction and model hypotheses.

This opt-in development route leaves v24 untouched. A model can challenge a
deterministic prediction but cannot supply a missing proof or a behavior label.
"""
import ast
from pathlib import Path

from guardcontract.analysis.scenario_interpreter_v3 import predict
from guardcontract.runtime.approval_slice import extract,registration_proof,sha,source_identity,audit
from guardcontract.evidence.python_redaction import redact_python
from guardcontract.evaluation.scoped_issue import digest,validate_scope
from guardcontract.evaluation.source_sdk_adapter import scenario
from guardcontract.core.path_consistency import CONTRACT_FIELDS,plan_contract_queries


def static_stage(item,source_root,scope):
    validate_scope(scope)
    if digest(scenario(item)) not in scope['scenarios']:
        raise ValueError('prediction_scenario_scope_mismatch')
    identities={'source_inventory_sha256':source_identity(item),'guard_sha256':digest(item['guard']),
                'effect_sha256':digest(item['effect']),'registration_sha256':digest(item['registration'])}
    if any(scope['subject'][k]!=v for k,v in identities.items()):raise ValueError('prediction_subject_scope_mismatch')
    files={r['path']:r['sha256'] for r in item['inventory']}
    root=Path(source_root)/item['root']
    for name,expected in files.items():
        p=root/name
        if p.is_symlink() or not p.resolve().is_relative_to(root.resolve()) or sha(p)!=expected:
            raise ValueError('prediction_source_drift')
    base={'sample_id':item['sample_id'],'scope_id':scope['scope_id'],
          'scenario_id':digest(scenario(item)),
          'source_verified_facts':{},'model_hypotheses':None,'release_certificate':None,'issue_label':None}
    try:
        g,e,r=item['guard'],item['effect'],item['registration']
        registration=registration_proof(root/r['path'],files[r['path']],r['line'],g['symbol'],e['symbol'])
        guard=extract(root/g['path'],g['symbol'],files[g['path']])
        tool=extract(root/e['path'],e['symbol'],files[e['path']])
        audit(guard,{'input','print','confirm.lower','ToolMessage','handler','st.session_state.get'})
        audit(tool,{'os.getenv','requests.get','response.json','data.get','str','print'})
        # A scope about the selected sink cannot silently become a scope about
        # any other call or an unrelated helper.
        calls=[n for n in ast.walk(tool) if isinstance(n,ast.Call)
               and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name)
               and n.func.value.id=='requests' and n.func.attr=='get']
        if len(calls)!=1 or calls[0].lineno!=e['line']:
            raise ValueError('selected_sink_not_unique')
        result=predict(guard,tool,item)
        base['source_verified_facts']={'source_inventory':files,'registration':registration,
            'closed_scenario_derivation':result,'scope_only':True}
        base['prediction']=result['prediction']
        if result['prediction']!='unknown':
            base['release_certificate']={'scope_id':scope['scope_id'],'rule':'sdk-captured-target-source-scenario-3',
                'scenario_id':base['scenario_id'],
                'derivation_sha256':digest(result),'scope_only':True,'runtime_observations_read':False,
                'assumptions':'Only the frozen JSON stimuli, scripted single tool call, and specified synchronous HTTP replacement.'}
        base['status']=result.get('status','completed')
        if base['status']=='unsupported':base['reason']=result['reason']
    except (ValueError,KeyError,OSError,SyntaxError) as exc:
        base.update(prediction='unknown',status='unsupported',reason=str(exc))
    return base


def model_plan(entries,queue,source_root):
    """Feed the existing six-predicate protocol an explicit analysis scope."""
    items={i['sample_id']:i for i in queue['rows']}
    excerpts={}
    candidates=[]
    obligations=[]
    for entry in entries:
        evidence_ids=entry['evidence_sample_ids']
        item=items[evidence_ids[0]]
        # Every scenario sent under one source contract must have identical
        # authenticated inventory and selected guard/effect/registration.
        for sid in evidence_ids:
            other=items[sid]
            if any(other[k]!=item[k] for k in ('inventory','guard','effect','registration')):
                raise ValueError('mixed_source_inventory_in_model_scope')
        files={r['path']:r['sha256'] for r in item['inventory']}
        aliases=[]
        for path,expected in files.items():
            raw=(Path(source_root)/item['root']/path).read_text()
            if sha(Path(source_root)/item['root']/path)!=expected:raise ValueError('model_source_drift')
            cleaned=redact_python(raw)
            if cleaned['status']!='sanitized':raise ValueError('model_source_withheld')
            alias='s'+str(len(excerpts));aliases.append(alias)
            excerpts[alias]={'path':path,'start_line':1,'end_line':len(raw.splitlines()),'sha256':expected,
                             'content':cleaned['source'],'sanitization':{k:v for k,v in cleaned.items() if k!='source'}}
        facts=dict.fromkeys(CONTRACT_FIELDS,'unknown')
        guard_node='guard:'+digest([source_identity(item),item['guard']])
        effect_node='effect:'+digest([source_identity(item),item['effect']])
        policy_path=entry['policy_contract'].get('source_path')
        policy_aliases=[a for a in aliases if excerpts[a]['path']==policy_path]
        if len(policy_aliases)!=1:raise ValueError('policy_source_not_enrolled')
        policy_source=excerpts[policy_aliases[0]]
        obligations.append({'id':'policy:'+digest(entry['policy_contract']),
            'guard_node':guard_node,'logical_effect_id':effect_node,
            'operation':item['effect']['symbol'],'resource':'exact tool arguments in the assessment scope',
            'source':{k:policy_source[k] for k in ('path','start_line','end_line','sha256')}})
        candidates.append({'candidate_id':entry['sample_id'],'guard_node':guard_node,
            'logical_effect_id':effect_node,'facts':facts,
            'query_plan':plan_contract_queries(facts),
            'guard_source':item['guard'],'effect_source':item['effect'],
            'source_nodes':[], 'lifecycle':[{'position':'around_tool_call','source_aliases':aliases}]})
    return {'schema_version':'registration-contract-plan-1','framework':'langchain',
            'analysis_contract':{'policy_obligations':obligations,
                'assessment_scopes':{r['sample_id']:r['scope'] for r in entries},
                'scope_boundary':'Only the declared synchronous source-slice scenarios; not all application paths.',
                'obligation':'A guard-origin denial message must prevent the selected HTTP effect in the same tool invocation. Tool output containing denial text is not a guard verdict.'},
            'sdk_contract_sha256':entries[0]['scope']['subject']['sdk_environment_sha256'],
            'sdk_semantics':{'framework':'langchain','facts':{
                'wrapper_return_without_handler_skips_selected_tool':True},
                'limits':['single scripted call','original callback and tool bodies','closed local HTTP response']},
            'candidates':candidates},excerpts


def finalize(entry,static_rows,model_consensus=None):
    scope=entry['scope'];validate_scope(scope)
    if len(entry['evidence_sample_ids'])!=len(set(entry['evidence_sample_ids'])):
        raise ValueError('duplicate_scope_evidence_reference')
    by_id={r['sample_id']:r for r in static_rows}
    if len(by_id)!=len(static_rows):raise ValueError('duplicate_static_derivation')
    selected=[by_id[sid] for sid in entry['evidence_sample_ids'] if sid in by_id]
    valid=[]
    for row in selected:
        cert=row.get('release_certificate')
        derivation=row.get('source_verified_facts',{}).get('closed_scenario_derivation')
        if (row.get('scope_id')==scope['scope_id'] and row.get('status')=='completed'
                and row.get('scenario_id') in scope['scenarios'] and isinstance(cert,dict)
                and cert.get('scope_id')==scope['scope_id'] and cert.get('scenario_id')==row['scenario_id']
                and cert.get('rule')=='sdk-captured-target-source-scenario-3'
                and cert.get('derivation_sha256')==digest(derivation)
                and isinstance(derivation,dict) and derivation.get('prediction')==row.get('prediction')):
            valid.append(row)
    selected=valid
    classes={r['prediction'] for r in selected}
    value='unknown'
    if 'present' in classes:value='present'
    elif ({r['scenario_id'] for r in selected}==set(scope['scenarios']) and classes=={'absent'}
          and not scope['open_dimensions'] and scope['quantifier']!='exists_in_open_domain'):
        value='absent'
    hypothesis=None
    if model_consensus:
        hypothesis=next((r for r in model_consensus['candidates'] if r['candidate_id']==entry['sample_id']),None)
    model_disagrees=False
    if hypothesis and value!='unknown':
        h=hypothesis['assessment']['issue_prediction']
        model_disagrees=h is not None and h!=(value=='present')
        if model_disagrees:value='unknown'
    return {'sample_id':entry['sample_id'],'scope_id':scope['scope_id'],'prediction':value,
            'status':'completed','source_verified_facts':selected,'model_hypotheses':hypothesis,
            'release_certificate':None if value=='unknown' else {
                'scope_id':scope['scope_id'],'rule':'sdk-captured-target-source-aggregation-3',
                'derivations_sha256':digest(selected),'runtime_observations_read':False},
            'model_disagreement':model_disagrees,'issue_label':None,'development_only':True}


def single_assessment(plan, decoded):
    """Assess one analyst's assertions without manufacturing a second role."""
    from guardcontract.protocols.contract_predicates import _digest
    from guardcontract.core.path_consistency import assess_contract
    if decoded.get('role')!='analyst' or decoded.get('plan_sha256')!=_digest(plan):
        raise ValueError('single_role_plan_identity')
    expected={c['candidate_id'] for c in plan['candidates']}
    if set(decoded['candidates'])!=expected:raise ValueError('single_role_inventory')
    rows=[]
    for candidate in plan['candidates']:
        assertion=decoded['candidates'][candidate['candidate_id']]
        facts=dict(candidate['facts']);facts.update(assertion['facts'])
        rows.append({'candidate_id':candidate['candidate_id'],'facts':facts,
            'assessment':assess_contract(facts),'accepted_sources':{'analyst':assertion['sources']}})
    return {'schema_version':'single-analyst-assessment-1','candidates':rows,'semantic_proof':False}


def four_arms(entries,static,plan,reviews):
    from guardcontract.protocols.contract_predicates import consensus
    analyst=next((r for r in reviews if r['role']=='analyst' and r['execution_state']=='completed'),None)
    critic=next((r for r in reviews if r['role']=='critic' and r['execution_state']=='completed'),None)
    one=single_assessment(plan,analyst['review']) if analyst else None
    pair=consensus(plan,analyst['review'],critic['review']) if analyst and critic else None
    arms={a:[] for a in ('static','llm_only','static_analyst','full')}
    for entry in entries:
        base=finalize(entry,static)
        related=[r for r in static if r['sample_id'] in entry['evidence_sample_ids']]
        if base['prediction']=='unknown' and any(r['status']=='unsupported' for r in related):
            base.update(status='unsupported',reason='one_or_more_source_scenarios_unsupported')
        arms['static'].append(base)
        for arm,review in [('static_analyst',one),('full',pair)]:
            row=finalize(entry,static,review)
            row['method_capability']='static_certification_with_model_veto_only'
            if row['prediction']=='unknown' and base['status']=='unsupported':
                row.update(status='unsupported',reason=base['reason'])
            if review is None:row.update(prediction='unknown',status='error',release_certificate=None,reason='model_review_incomplete')
            arms[arm].append(row)
        candidate=next((c for c in pair['candidates'] if c['candidate_id']==entry['sample_id']),None) if pair else None
        value=candidate['assessment']['issue_prediction'] if candidate else None
        arms['llm_only'].append({'sample_id':entry['sample_id'],'scope_id':entry['scope']['scope_id'],
            'prediction':{True:'present',False:'absent',None:'unknown'}[value],
            'status':'completed' if candidate else 'error','hypothesis_only':True})
    return arms, pair
