"""Scope-typed issue admission and arithmetic for explicitly enrolled evidence.

The trusted enrollment fixes source, policy and execution-domain meaning. This
module checks identity, coverage and quantifiers; it never treats metadata flags
as a semantic proof. Observation bytes must be independently recomputed by the
runtime adapter before admission. Open-domain negatives are unsupported.
"""
import hashlib
import json
import math

from guardcontract.evaluation.confirmation_metrics import weighted_metrics


QUANTIFIERS = {'fixed_scenario', 'exists_in_finite_domain', 'exists_in_open_domain'}
SUBJECT_KEYS = {'source_inventory_sha256', 'guard_sha256', 'effect_sha256', 'policy_sha256',
                'registration_sha256', 'sdk_environment_sha256'}
CONTROL_KEYS = {'model', 'initial_state', 'environment', 'tool_arguments', 'retry',
                'schedule', 'completion', 'correlation'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


def _hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def make_scope(subject, scenarios, controlled_dimensions, *, quantifier='fixed_scenario', open_dimensions=()):
    if set(subject) != SUBJECT_KEYS or any(not _hash(v) for v in subject.values()):
        raise ValueError('scope_subject_identity')
    if quantifier not in QUANTIFIERS:
        raise ValueError('scope_quantifier')
    if not isinstance(scenarios, dict) or not scenarios or any(not _hash(k) or digest(v) != k for k,v in scenarios.items()):
        raise ValueError('scope_scenario_manifest')
    if quantifier == 'fixed_scenario' and len(scenarios) != 1:
        raise ValueError('fixed_scope_requires_one_scenario')
    if (not isinstance(controlled_dimensions, dict) or set(controlled_dimensions) != CONTROL_KEYS
            or any(not isinstance(v,str) or not v for v in controlled_dimensions.values())):
        raise ValueError('scope_controlled_dimensions')
    if any(d not in CONTROL_KEYS for d in open_dimensions) or len(set(open_dimensions)) != len(open_dimensions):
        raise ValueError('scope_open_dimensions')
    result = {'schema_version':'guardcontract-assessment-scope-1',
              'unit':'source_slice_guard_effect_tool_invocation', 'quantifier':quantifier,
              'subject':dict(subject), 'scenarios':dict(scenarios),
              'controlled_dimensions':dict(controlled_dimensions),
              'open_dimensions':sorted(open_dimensions)}
    result['scope_id'] = digest(result)
    return result


def validate_scope(scope):
    expected = make_scope(scope['subject'], scope['scenarios'], scope['controlled_dimensions'],
                          quantifier=scope['quantifier'], open_dimensions=scope['open_dimensions'])
    if scope != expected:
        raise ValueError('scope_hash_or_schema_mismatch')
    return expected


def admit(scope, observations):
    """Admit recomputed observations from the trusted verifier adapter.

    No JSON boolean can enable an open-negative or waive missing/unknown cells.
    All observed IDs must be enrolled; a positive witness need not exhaust a
    domain, but a finite negative must exhaust its closed declared dimensions.
    """
    validate_scope(scope)
    if not isinstance(observations,list):
        raise ValueError('scope_observation_inventory')
    rows={}
    for row in observations:
        if set(row) != {'scope_id','scenario_id','label','evidence_sha256'}:
            raise ValueError('scope_observation_shape')
        sid=row['scenario_id']
        if row['scope_id']!=scope['scope_id'] or sid not in scope['scenarios'] or sid in rows:
            raise ValueError('scope_observation_identity')
        if row['label'] not in {'present','absent','unknown'} or not _hash(row['evidence_sha256']):
            raise ValueError('scope_observation_value')
        rows[sid]=row
    label,reason='unknown','incomplete_or_unknown_scenario_evidence'
    if any(r['label']=='present' for r in rows.values()):
        label,reason='present','enrolled_positive_witness'
    elif scope['quantifier']=='exists_in_open_domain':
        reason='open_domain_negative_unsupported'
    elif scope['open_dimensions']:
        reason='unclosed_execution_dimensions'
    elif set(rows)==set(scope['scenarios']) and all(r['label']=='absent' for r in rows.values()):
        label,reason='absent','complete_closed_declared_scenarios'
    return {'scope_id':scope['scope_id'],'quantifier':scope['quantifier'],'label':label,
            'reason':reason,'observed_scenarios':len(rows),'enrolled_scenarios':len(scope['scenarios']),
            'evidence_sha256':digest(sorted(observations,key=lambda r:r['scenario_id'])),
            'scope_limited':True,'program_wide_safety_proven':False}


def score(scopes, predictions, truths):
    """Full inventory join. Mismatched identities fail before arithmetic."""
    def index(values,key):
        result={}
        for row in values:
            if row[key] in result:
                raise ValueError('duplicate_scoped_record')
            result[row[key]]=row
        return result
    enrolled=index(scopes,'sample_id')
    predicted=index(predictions,'sample_id')
    labeled=index(truths,'sample_id')
    if not enrolled or (set(predicted)|set(labeled))-set(enrolled):
        raise ValueError('unregistered_scoped_record')
    if len({r['scope']['scope_id'] for r in enrolled.values()})!=len(enrolled):
        raise ValueError('duplicate_scope_unit')
    groups={}
    joined=[]
    for sid,entry in enrolled.items():
        scope=validate_scope(entry['scope'])
        probability=entry['inclusion_probability']
        if type(probability) not in (int,float) or not math.isfinite(probability) or not 0<probability<=1:
            raise ValueError('scope_inclusion_probability')
        for row in (predicted.get(sid),labeled.get(sid)):
            if row and row.get('scope_id')!=scope['scope_id']:
                raise ValueError('prediction_truth_scope_mismatch')
        prediction=predicted.get(sid,{}).get('prediction','unknown')
        truth=labeled.get(sid,{}).get('label','unknown')
        if prediction not in {'present','absent','unknown'} or truth not in {'present','absent','unknown'}:
            raise ValueError('scoped_prediction_truth_value')
        status=predicted.get(sid,{}).get('status','missing')
        if status not in {'completed','missing','error','unsupported'}:raise ValueError('scoped_prediction_status')
        if status!='completed':prediction='unknown'
        row={'sample_id':sid,'scope_id':scope['scope_id'],'quantifier':scope['quantifier'],
             'source_family':entry['source_family'],'prediction':prediction,'behavior_label':truth,
             'prediction_status':status,
             'inclusion_probability':probability,'stratum':scope['quantifier']}
        joined.append(row)
        groups.setdefault(scope['quantifier'],[]).append(row)
    metrics={}
    for kind,rows in groups.items():
        arithmetic=weighted_metrics(rows)['overall']
        # No confidence interval is warranted by this small development design.
        arithmetic={k:v for k,v in arithmetic.items() if not k.endswith('_interval')}
        arithmetic['oracle_coverage']=arithmetic.pop('coverage')
        arithmetic['method_decision_coverage']=sum(r['prediction']!='unknown' for r in rows)/len(rows)
        arithmetic['missing_predictions']=sum(r['prediction_status']=='missing' for r in rows)
        arithmetic['error_predictions']=sum(r['prediction_status']=='error' for r in rows)
        arithmetic['unknown_truth']=sum(r['behavior_label']=='unknown' for r in rows)
        if kind=='exists_in_open_domain':
            arithmetic['precision']=None
            arithmetic['recall']=None
            arithmetic['metric_status']='positive_witness_selection_does_not_identify_population_performance'
        metrics[kind]=arithmetic
    return {'schema_version':'scope-separated-issue-score-1','rows':joined,'by_quantifier':metrics,
            'aggregate_across_quantifiers':None,'final_holdout_admission':False,
            'claim_boundary':'Arithmetic over scope-aligned enrolled development labels; no whole-program, prevalence, or independent holdout claim.'}
