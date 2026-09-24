"""Assemble a compact, claim-bounded manifest for paper writing."""
import json
from pathlib import Path

def build(root=Path("experiments")):
    def read(path): return json.loads(path.read_text())
    def read_optional(path):
        return read(path) if path.is_file() else None
    score=read(root/"five-framework-score-n260/SCORES.json")
    static=read(root/"static-full-frame-n322/FRAME.json")
    coverage=read(root/"static-frame-coverage-n319/RESULT.json")
    gate_path = root / "five-framework-delivery-gate-n335/RESULT.json"
    if not gate_path.is_file():
        gate_path = root / "five-framework-delivery-gate-n314/RESULT.json"
    gate=read(gate_path)
    ledger=read_optional(Path("artifacts/development/public-prospective-confirmation-ledger-v2-20260913.json"))
    burnin=read_optional(Path("artifacts/development/burnin-freeze-checklist-20260913.json"))
    family_round9=read_optional(Path("artifacts/development/gap-round9-n334-family-audit-20260913.json"))
    family_cross_batch=read_optional(Path("artifacts/development/gap-round4-round9-round10-cross-family-summary-20260913.json"))
    if family_cross_batch is None:
        family_cross_batch=read_optional(Path("artifacts/development/gap-round4-round9-cross-family-summary-20260913.json"))
    family_round10=read_optional(Path("artifacts/development/gap-round10-n336-family-audit-20260913.json"))
    static_round4=read_optional(Path("artifacts/development/gap-round4-frame-static-screen-20260913.json"))
    static_round9=read_optional(Path("artifacts/development/gap-round9-n334-static-screen-20260913.json"))
    static_round10=read_optional(Path("artifacts/development/gap-round10-n336-static-screen-20260913.json"))
    static_round11=read_optional(Path("artifacts/development/gap-round11-n337-crewai-static-screen-20260913.json"))
    census_round4=read_optional(Path("artifacts/development/gap-round4-behavior-screening-census-20260913.json"))
    census_round9=read_optional(Path("artifacts/development/gap-round9-behavior-screening-census-20260913.json"))
    oracle_manifest=read_optional(Path("artifacts/development/independent-oracle-manifest-queue-n12-20260913.json"))
    oracle_queue=read_optional(Path("artifacts/development/behavior-oracle-queue-ledger-n12-v2-20260913.json"))
    reconciliation=read_optional(Path("artifacts/development/evaluation-inventory-reconciliation-n12-20260913.json"))
    family_round11=read_optional(Path("artifacts/development/gap-round11-crewai-cross-family-summary-20260913.json"))
    crewai_round11=read_optional(Path("artifacts/development/aport-crewai-source-global-hook-fixture-v3-20260913.json"))
    detector_freeze_path = Path("artifacts/development/detector-stability-freeze-v12-20260914.json")
    if not detector_freeze_path.is_file():
        detector_freeze_path = Path("artifacts/development/detector-stability-freeze-v11-20260913.json")
    if not detector_freeze_path.is_file():
        detector_freeze_path = Path("artifacts/development/detector-stability-freeze-v10-20260913.json")
    if not detector_freeze_path.is_file():
        detector_freeze_path = Path("artifacts/development/detector-stability-freeze-v9-20260913.json")
    if not detector_freeze_path.is_file():
        detector_freeze_path = Path("artifacts/development/detector-stability-freeze-v8-20260913.json")
    detector_freeze=read_optional(detector_freeze_path)
    post_static=read_optional(Path("artifacts/development/post-stability-round12-static-screen-20260913.json"))
    post_family=read_optional(Path("artifacts/development/post-stability-round12-frame-family-admission-v4-20260913.json"))
    family_semantic_packet=read_optional(Path("artifacts/development/post-stability-round12-family-semantic-review-packet-v3-20260913.json"))
    post_census=read_optional(Path("artifacts/development/post-stability-round12-screening-census-20260913.json"))
    post_two_phase=read_optional(Path("artifacts/development/post-stability-round12-two-phase-freeze-20260913.json"))
    post_oracle_manifest=read_optional(Path("artifacts/development/post-stability-round12-independent-oracle-manifest-n73-v2-20260913.json"))
    post_oracle_queue=read_optional(Path("artifacts/development/post-stability-round12-oracle-queue-n73-v2-20260913.json"))
    post_prediction_freeze=read_optional(Path("artifacts/development/post-stability-round12-prediction-freeze-n73-v2-20260913.json"))
    post_runtime_plan=read_optional(Path("artifacts/development/post-stability-round12-runtime-screening-plan-v3-20260913.json"))
    post_runtime_oracle=read_optional(Path("artifacts/development/post-stability-round12-source-guard-oracle-v7-20260913.json"))
    post_runtime_validation=read_optional(Path("artifacts/development/post-stability-round12-source-guard-oracle-validation-v8-20260913.json"))
    repair_queue=read_optional(Path("artifacts/development/post-stability-round12-repair-candidate-queue-20260913.json"))
    repair_pilot=read_optional(Path("artifacts/development/post-stability-repair-verification-pilot-20260913.json"))
    source_pilot_metrics=read_optional(Path("artifacts/development/post-stability-round12-source-oracle-pilot-metrics-20260913.json"))
    confirmation_readiness_path = Path("artifacts/development/confirmation-readiness-current-v2-20260913.json")
    if not confirmation_readiness_path.is_file():
        confirmation_readiness_path = Path("artifacts/development/post-stability-round12-confirmation-readiness-20260913.json")
    confirmation_readiness=read_optional(confirmation_readiness_path)
    oracle_packet=read_optional(Path("artifacts/development/post-stability-round12-independent-oracle-packet-n73-v2-20260913.json"))
    deterministic_oracle=read_optional(Path("artifacts/development/post-stability-round12-deterministic-oracle-manifest-n73-20260913.json"))
    bound_metrics=read_optional(Path("artifacts/development/post-stability-round12-bound-confirmation-metrics-20260913.json"))
    independent_trace_oracle=read_optional(Path("artifacts/development/post-stability-round12-independent-trace-oracle-20260913.json"))
    oracle_agreement=read_optional(Path("artifacts/development/post-stability-round12-oracle-agreement-20260913.json"))
    round13_frame=read_optional(Path("experiments/post-stability-effect-dense-freeze-round13-n339/FRAME.json"))
    round13_material=read_optional(Path("experiments/post-stability-effect-dense-materialization-round13-n339/MATERIALIZATION.json"))
    round13_static=read_optional(Path("artifacts/development/post-stability-effect-dense-round13-static-20260913.json"))
    round13_family=read_optional(Path("artifacts/development/post-stability-effect-dense-round13-family-audit-20260913.json"))
    round13b_frame=read_optional(Path("experiments/post-stability-effect-dense-freeze-round13b-n340/FRAME.json"))
    round13b_material=read_optional(Path("experiments/post-stability-effect-dense-materialization-round13b-n340/MATERIALIZATION.json"))
    round13b_static=read_optional(Path("artifacts/development/post-stability-effect-dense-round13b-static-v2-20260913.json"))
    classifier_comparison=read_optional(Path("artifacts/development/detector-v3-v4-effect-classifier-comparison-20260913.json"))
    adk_google_api_recheck=read_optional(Path("artifacts/development/post-stability-effect-dense-single-iamjean6-v4-20260913.json"))
    round14_history=read_optional(Path("experiments/post-v8-history-audit-round14e-n361/RESULT.json"))
    clean_frame=read_optional(Path("experiments/post-v8-public-candidate-merged-round15-16-n366/FRAME.json"))
    clean_exclusion=read_optional(Path("experiments/post-v8-candidate-exclusion-validation-n367/RESULT.json"))
    clean_material=read_optional(Path("experiments/post-v8-materialization-round15-16-n368/MATERIALIZATION.json"))
    clean_static=read_optional(Path("experiments/post-v8-static-screen-round15-16-n369/RESULT.json"))
    clean_family=read_optional(Path("experiments/post-v8-family-admission-final-round15-16-n375/RESULT.json"))
    clean_two_phase=read_optional(Path("experiments/post-v8-confirmation-freeze-round15-16-n376/TWO_PHASE.json"))
    clean_predictions=read_optional(Path("experiments/post-v8-prediction-freeze-round15-16-n377/MANIFEST.json"))
    clean_oracle=read_optional(Path("experiments/post-v8-oracle-freeze-round15-16-n378/ORACLE_MANIFEST.json"))
    v9_round17=read_optional(Path("experiments/post-v9-public-candidate-merged-round17-18-n385/FRAME.json"))
    v9_exclusions=read_optional(Path("experiments/repository-exclusion-set-round17-n381/EXCLUSIONS.json"))
    v9_material=read_optional(Path("experiments/post-v9-materialization-round17-18-n387/MATERIALIZATION.json"))
    v9_static=read_optional(Path("experiments/post-v9-static-screen-round17-18-n388/RESULT.json"))
    v9_family=read_optional(Path("experiments/post-v9-family-admission-final-round17-18-n395/RESULT.json"))
    v9_two_phase=read_optional(Path("experiments/post-v9-confirmation-freeze-round17-18-n396/TWO_PHASE.json"))
    v9_predictions=read_optional(Path("experiments/post-v9-prediction-freeze-round17-18-n397/MANIFEST.json"))
    v9_oracle=read_optional(Path("experiments/post-v9-oracle-freeze-round17-18-n398/ORACLE_MANIFEST.json"))
    v9_runtime_plan=read_optional(Path("experiments/post-v9-runtime-plan-round17-18-n399/PLAN.json"))
    v9_runtime_oracle=read_optional(Path("experiments/post-v9-source-oracle-n417/RESULT.json"))
    v9_runtime_validation=read_optional(Path("experiments/post-v9-source-oracle-validation-n418/RESULT.json"))
    v9_bound_oracle=read_optional(Path("experiments/post-v9-bound-oracle-n419/BOUND_MANIFEST.json"))
    v9_bound_metrics=read_optional(Path("experiments/post-v9-bound-metrics-n420/RESULT.json"))
    v9_confirmation_readiness=read_optional(Path("experiments/post-v9-confirmation-readiness-n421/RESULT.json"))
    v9_run_chain=read_optional(Path("experiments/post-v9-run-chain-audit-n422/RESULT.json"))
    round19_frame=read_optional(Path("experiments/post-v9-effect-enriched-freeze-round19-n423/FRAME.json"))
    round19_material=read_optional(Path("experiments/post-v9-effect-enriched-materialization-round19-n424/MATERIALIZATION.json"))
    round19_static=read_optional(Path("experiments/post-v9-deny-capability-static-round19-n434/RESULT.json"))
    round19_family=read_optional(Path("experiments/post-v9-effect-enriched-family-admission-round19-n428/RESULT.json"))
    round19_runtime=read_optional(Path("experiments/source-oracle-round19-isolated-n432/RESULT.json"))
    round19_confirmation=read_optional(Path("experiments/post-v9-deny-capability-confirmation-round19-n435/TWO_PHASE.json"))
    round20_frame=read_optional(Path("experiments/post-v10-final-candidate-freeze-round20-n443/FRAME.json"))
    round20_material=read_optional(Path("experiments/post-v10-final-materialization-round20-n444/MATERIALIZATION.json"))
    round20_static=read_optional(Path("experiments/post-v10-final-static-round20-n447/RESULT.json"))
    round20_family=read_optional(Path("experiments/post-v10-final-family-admission-reviewed-round20-n453/RESULT.json"))
    round20_two_phase=read_optional(Path("experiments/post-v10-final-confirmation-round20-n454/TWO_PHASE.json"))
    round20_predictions=read_optional(Path("experiments/post-v10-final-prediction-freeze-round20-n455/MANIFEST.json"))
    round20_oracle=read_optional(Path("experiments/post-v10-final-oracle-freeze-round20-n461/ORACLE_MANIFEST.json"))
    round20_material_validation=read_optional(Path("experiments/post-v10-final-materialization-verification-round20-n458/RESULT.json"))
    round20_run_chain=read_optional(Path("experiments/post-v10-final-run-chain-audit-round20-n466/RESULT.json"))
    round20_runtime_plan=read_optional(Path("experiments/post-v10-final-runtime-plan-round20-n460/PLAN.json"))
    round20_handoff=read_optional(Path("experiments/post-v10-final-fixture-handoff-round20-n463/HANDOFF.json"))
    round20_fixture_tasks=read_optional(Path("experiments/post-v10-final-fixture-tasks-round20-n467/TASKS.json"))
    round20_fixture_proposals=read_optional(Path("experiments/post-v10-final-fixture-proposals-round20-n470/RESULT.json"))
    round20_ast_fixtures=read_optional(Path("experiments/post-v10-final-ast-fixture-config-round20-n474/CONFIG.json"))
    round20_runtime_validation=read_optional(Path("experiments/post-v10-final-source-oracle-validation-round20-n476/RESULT.json"))
    round20_bound_oracle=read_optional(Path("experiments/post-v10-final-bound-oracle-round20-n477/BOUND_MANIFEST.json"))
    round20_metrics=read_optional(Path("experiments/post-v10-final-bound-metrics-round20-n478/RESULT.json"))
    round20_readiness=read_optional(Path("experiments/post-v10-final-readiness-round20-n479/RESULT.json"))
    round21_frame=read_optional(Path("experiments/post-v11-final-candidate-census-round21-n495/FRAME.json"))
    round21_material=read_optional(Path("experiments/post-v11-final-materialization-round21-n497/MATERIALIZATION.json"))
    round21_material_validation=read_optional(Path("experiments/post-v11-final-materialization-verification-round21-n499/RESULT.json"))
    round21_static=read_optional(Path("experiments/post-v11-final-static-round21-n500/RESULT.json"))
    round21_family=read_optional(Path("experiments/post-v11-final-family-admission-conservative-round21-n507/RESULT.json"))
    round21_two_phase=read_optional(Path("experiments/post-v11-final-confirmation-round21-n508/TWO_PHASE.json"))
    round21_predictions=read_optional(Path("experiments/post-v11-final-prediction-freeze-round21-n509/MANIFEST.json"))
    round21_oracle=read_optional(Path("experiments/post-v11-final-oracle-freeze-round21-n510/ORACLE_MANIFEST.json"))
    round21_runtime_plan=read_optional(Path("experiments/post-v11-final-runtime-plan-round21-n511/PLAN.json"))
    round21_handoff=read_optional(Path("experiments/post-v11-final-fixture-handoff-round21-n512/HANDOFF.json"))
    round21_fixture_tasks=read_optional(Path("experiments/post-v11-final-fixture-tasks-round21-n513/TASKS.json"))
    round21_components=read_optional(Path("experiments/post-v11-final-registration-components-round21-n514/RESULT.json"))
    round21_ast_fixtures=read_optional(Path("experiments/post-v11-final-ast-fixture-config-round21-n517/CONFIG.json"))
    round21_runtime_validation=read_optional(Path("experiments/post-v11-final-source-oracle-validation-merged-round21-n542/RESULT.json"))
    round21_bound_oracle=read_optional(Path("experiments/post-v11-final-bound-oracle-merged-round21-n543/BOUND_MANIFEST.json"))
    round21_metrics=read_optional(Path("experiments/post-v11-final-bound-metrics-merged-round21-n544/RESULT.json"))
    round21_independent_trace=read_optional(Path("experiments/post-v11-final-independent-trace-oracle-merged-round21-n547/RESULT.json"))
    round21_oracle_agreement=read_optional(Path("experiments/post-v11-final-oracle-agreement-merged-round21-n548/RESULT.json"))
    round21_readiness=read_optional(Path("experiments/post-v11-final-readiness-merged-round21-n549/RESULT.json"))
    round21_effect_supplement=read_optional(Path("experiments/post-v11-final-effect-supplement-round21-n529/RESULT.json"))
    round21_effect_review=read_optional(Path("experiments/post-v11-final-effect-review-packet-round21-n532/PACKET.json"))
    round21_registration_binding=read_optional(Path("experiments/post-v11-final-effect-registration-binding-round21-n533/RESULT.json"))
    round21_deny_proof=read_optional(Path("experiments/post-v11-final-deny-unreachable-proof-round21-n534/RESULT.json"))
    round21_mixed_metrics=read_optional(Path("experiments/post-v11-final-mixed-issue-metrics-merged-round21-n545/RESULT.json"))
    large_scale_direct=read_optional(Path("experiments/large-scale-direct-census-post-v11-n502/CENSUS.json"))
    large_scale_family=read_optional(Path("experiments/large-scale-direct-family-audit-post-v11-n504/RESULT.json"))
    round21_run_chain=read_optional(Path("experiments/post-v11-large-scale-run-chain-audit-n550/RESULT.json"))
    round22_static=read_optional(Path("experiments/post-v11-effect-enriched-static-round22-n561/RESULT.json"))
    round22_family=read_optional(Path("experiments/post-v11-effect-enriched-family-admission-round22-n563/RESULT.json"))
    round22_two_phase=read_optional(Path("experiments/post-v11-effect-enriched-confirmation-round22-n565/TWO_PHASE.json"))
    round22_predictions=read_optional(Path("experiments/post-v11-effect-enriched-prediction-freeze-round22-n566/MANIFEST.json"))
    round22_components=read_optional(Path("experiments/post-v11-effect-enriched-registration-components-round22-n584/RESULT.json"))
    round22_fixtures=read_optional(Path("experiments/post-v11-effect-enriched-ast-fixtures-round22-n585/CONFIG.json"))
    round22_runtime=read_optional(Path("experiments/post-v11-effect-enriched-source-oracle-round22-n586/RESULT.json"))
    round22_validation=read_optional(Path("experiments/post-v11-effect-enriched-source-oracle-validation-round22-n587/RESULT.json"))
    round22_metrics=read_optional(Path("experiments/post-v11-effect-enriched-bound-metrics-round22-n589/RESULT.json"))
    round22_repair_queue=read_optional(Path("experiments/post-v11-effect-enriched-verified-repair-queue-round22-n590/QUEUE.json"))
    round22_repair_glm45=read_optional(Path("experiments/post-v11-effect-enriched-llm-repair-proposals-round22-n594/RESULT.json"))
    round22_repair_intern=read_optional(Path("experiments/post-v11-effect-enriched-llm-repair-proposals-round22-n595/RESULT.json"))
    round22_repair_glmz1=read_optional(Path("experiments/post-v11-effect-enriched-llm-repair-proposals-round22-n596/RESULT.json"))
    round22_v12_static=read_optional(Path("experiments/post-v11-effect-enriched-static-v12-development-round22-n600/RESULT.json"))
    round22_v12_comparison=read_optional(Path("experiments/post-v11-effect-enriched-static-v12-comparison-round22-n604/RESULT.json"))
    round22_repair_terra=read_optional(Path("experiments/post-v11-effect-enriched-llm-repair-proposals-round22-n607/RESULT.json"))
    round22_repair_correction=read_optional(Path("experiments/post-v11-effect-enriched-llm-repair-correction-round22-n608/RESULT.json"))
    round22_repair_policy=read_optional(Path("experiments/post-v11-effect-enriched-llm-repair-policy-validation-round22-n609/RESULT.json"))
    round22_repair_sdk=read_optional(Path("experiments/post-v11-effect-enriched-llm-repair-sdk-validation-round22-n610/RESULT.json"))
    paratera_catalog=read_optional(Path("experiments/paratera-model-catalog-20260914-n613/MODEL_CATALOG.json"))
    round22_run_chain=read_optional(Path("experiments/post-v11-large-scale-run-chain-audit-n614/RESULT.json"))
    round23_exclusions=read_optional(Path("experiments/repository-exclusion-set-round23-n616/EXCLUSIONS.json"))
    round23_raw_a=read_optional(Path("experiments/post-v12-effect-enriched-raw-round23a-n617/RAW.json"))
    round23_raw_b=read_optional(Path("experiments/post-v12-effect-enriched-raw-round23b-n618/RAW.json"))
    round23_census=read_optional(Path("experiments/post-v12-effect-enriched-census-round23-n620/FRAME.json"))
    pause_run_chain=read_optional(Path("experiments/post-v12-pause-run-chain-audit-n621/RESULT.json"))
    round24_frame=read_optional(Path("experiments/post-v12-complementary-census-round24-n631/FRAME.json"))
    round24_material=read_optional(Path("experiments/post-v12-complementary-materialization-round24-n632/MATERIALIZATION.json"))
    round24_material_validation=read_optional(Path("experiments/post-v12-complementary-materialization-verification-round24-n634/RESULT.json"))
    round24_static=read_optional(Path("experiments/post-v12-complementary-static-round24-n636/RESULT.json"))
    round24_family=read_optional(Path("experiments/post-v12-complementary-family-admission-round24-n640/RESULT.json"))
    round24_two_phase=read_optional(Path("experiments/post-v12-complementary-confirmation-round24-n642/TWO_PHASE.json"))
    round24_predictions=read_optional(Path("experiments/post-v12-complementary-prediction-freeze-round24-n643/MANIFEST.json"))
    round24_oracle=read_optional(Path("experiments/post-v12-complementary-oracle-freeze-round24-n644/ORACLE_MANIFEST.json"))
    round24_runtime_plan=read_optional(Path("experiments/post-v12-complementary-runtime-plan-round24-n645/PLAN.json"))
    round24_tasks=read_optional(Path("experiments/post-v12-complementary-fixture-tasks-round24-n647/TASKS.json"))
    round24_components=read_optional(Path("experiments/post-v12-complementary-registration-components-round24-n648/RESULT.json"))
    round24_fixtures=read_optional(Path("experiments/post-v12-complementary-ast-fixtures-round24-n660/CONFIG.json"))
    round24_runtime_validation=read_optional(Path("experiments/post-v12-complementary-source-oracle-validation-round24-n662/RESULT.json"))
    round24_bound=read_optional(Path("experiments/post-v12-complementary-bound-oracle-round24-n663/BOUND_MANIFEST.json"))
    round24_metrics=read_optional(Path("experiments/post-v12-complementary-bound-metrics-round24-n665/RESULT.json"))
    round24_deny_proof=read_optional(Path("experiments/post-v12-complementary-deny-unreachable-proof-round24-n666/RESULT.json"))
    round24_mixed=read_optional(Path("experiments/post-v12-complementary-mixed-issue-metrics-round24-n667/RESULT.json"))
    round24_agreement=read_optional(Path("experiments/post-v12-complementary-oracle-agreement-round24-n669/RESULT.json"))
    round24_readiness=read_optional(Path("experiments/post-v12-complementary-readiness-round24-n670/RESULT.json"))
    round24_run_chain=read_optional(Path("experiments/post-v12-round24-run-chain-audit-n671/RESULT.json"))
    generic_runtime_validation=read_optional(Path("artifacts/development/post-stability-round12-source-guard-oracle-generic-v9-validation-20260913.json"))
    ledger_validation=read_optional(Path("artifacts/development/prospective-ledger-v2-validation-20260913.json"))
    readiness_audit_path = Path("artifacts/development/goal-readiness-audit-current-20260913.json")
    if not readiness_audit_path.is_file():
        readiness_audit_path = Path("artifacts/development/goal-readiness-audit-20260913.json")
    readiness_audit=read_optional(readiness_audit_path)
    effect_coverage=read_optional(Path("artifacts/development/effect-coverage-audit-round4-10-20260913.json"))
    return {"schema_version":"paper-evidence-manifest-1","claims":{
        "development_control": {"evidence":"experiments/five-framework-score-n260/SCORES.json","precision":score["detection"]["precision"],"recall":score["detection"]["recall"],"repair":score["repair"],"claim":"Five-framework exposed development controls only."},
        "delivery_gate": {"evidence":str(gate_path),"passed":gate["passed"],"historical_threshold":gate.get("threshold", gate.get("historical_threshold")),"current_hard_gate":None,"claim":"Historical development delivery control; current evaluation has no fixed precision/recall threshold and this is not a holdout gate."},
        "static_corpus": {"evidence":"experiments/static-full-frame-n322/FRAME.json","sites":static["counts"]["static_auditable_sites"],"repositories":static["counts"]["repositories"],"source_file_families":static["counts"]["source_file_families"],"claim":"Static direct-relevance source frame; no behavior labels."},
        "prospective_pools": {
            "round4": (static_round4 or {}).get("counts", {}),
            "round9": (static_round9 or {}).get("counts", {}),
            "round10": (static_round10 or {}).get("counts", {}),
            "round11": (static_round11 or {}).get("counts", {}),
            "claim":"Supplemental prospective identity/static pools; static sites and guard candidates are not behavior labels or holdout admissions."
        },
        "coverage": {"evidence":"experiments/static-frame-coverage-n319/RESULT.json","frameworks":coverage["counts"]["frameworks"],"languages":coverage["counts"]["languages"],"timing":coverage["by_timing"],"claim":"Coverage and uncertainty inventory."},
        "behavior_validation": {
            "controlled_source_bound_confirmations": (ledger or {}).get("counts", {}).get("eligible_rows", 0),
            "independent_oracle_labels": 0,
            "claim":"Controlled source-bound mechanism confirmations are reported separately; no independent public-repository oracle labels are admitted."
        },
        "prospective_confirmation": {
            "evidence":"artifacts/development/public-prospective-confirmation-ledger-v2-20260913.json",
            "source_rows": (ledger or {}).get("counts", {}).get("source_rows", 0),
            "eligible_rows": (ledger or {}).get("counts", {}).get("eligible_rows", 0),
            "excluded_rows": (ledger or {}).get("counts", {}).get("excluded_rows", 0),
            "inventory_sha256": (ledger or {}).get("inventory_sha256"),
            "claim":"Prospective protocol/burn-in evidence only; no issue labels or final P/R."
        },
        "screening_census": {
            "round4": (census_round4 or {}).get("counts", {}),
            "round9": (census_round9 or {}).get("counts", {}),
            "claim":"Label-free phase-one census; every row remains runtime_unverified and requires independent oracle confirmation."
        },
        "oracle_manifest": {
            "evidence":"artifacts/development/independent-oracle-manifest-queue-n12-20260913.json",
            "inventory": len((oracle_manifest or {}).get("inventory", [])),
            "manifest_sha256": (oracle_manifest or {}).get("manifest_sha256"),
            "labels_bound": (oracle_manifest or {}).get("labels_bound", False),
            "claim":"Pre-label oracle inventory freeze only; external evaluator independence and label correctness remain unverified."
        },
        "oracle_queue": {
            "evidence":"artifacts/development/behavior-oracle-queue-ledger-n12-v2-20260913.json",
            "rows": len((oracle_queue or {}).get("rows", [])),
            "runtime_verified": (oracle_queue or {}).get("runtime_verified", 0),
            "labels_read": (oracle_queue or {}).get("labels_read", False),
            "claim":"Label-free oracle queue only; all cases remain unverified until an independently authenticated oracle binds labels."
        },
        "ledger_reconciliation": {
            "evidence":"artifacts/development/evaluation-inventory-reconciliation-n12-20260913.json",
            "reconciled": (reconciliation or {}).get("reconciled", False),
            "checks": (reconciliation or {}).get("checks", {}),
            "claim":"Mechanical reconciliation of validated ledger, burn-in matrix, oracle manifest and queue; no label or holdout claim."
        },
        "prospective_ledger_validation": {
            "evidence":"artifacts/development/prospective-ledger-v2-validation-20260913.json",
            "valid": (ledger_validation or {}).get("valid", False),
            "counts": (ledger_validation or {}).get("counts", {}),
            "checks": (ledger_validation or {}).get("checks", {}),
            "claim":"Mechanical provenance/schema validation only; invalid rows remain excluded from independent oracle labels, prevalence, P/R and holdout claims."
        },
        "goal_readiness_audit": {
            "evidence":str(readiness_audit_path),
            "counts": (readiness_audit or {}).get("counts", {}),
            "stable_ready": (readiness_audit or {}).get("stable_ready", False),
            "claim":"Machine-derived readiness status; partial gates remain explicit and no completion claim is made."
        },
        "effect_coverage": {
            "evidence":"artifacts/development/effect-coverage-audit-round4-10-20260913.json",
            "counts": (effect_coverage or {}).get("counts", {}),
            "by_framework": (effect_coverage or {}).get("by_framework", {}),
            "by_lifecycle": (effect_coverage or {}).get("by_lifecycle", {}),
            "by_effect_family": (effect_coverage or {}).get("by_effect_family", {}),
            "claim":"Static lifecycle/effect taxonomy coverage only; candidates remain unverified and no runtime prevalence or P/R claim is made."
        },
        "readiness": {
            "evidence":"artifacts/development/burnin-freeze-checklist-20260913.json",
            "stable_ready": (burnin or {}).get("stable_ready", False),
            "family_audit_round9": (family_round9 or {}).get("counts", {}),
            "cross_batch_family_audit": (family_cross_batch or {}).get("counts", {}),
            "family_audit_round10": (family_round10 or {}).get("counts", {}),
            "family_audit_round11": (family_round11 or {}).get("counts", {}),
            "claim":"Readiness and family coverage remain bounded by the current checklist; no completion claim."
        },
        "crewai_round11_runtime": {
            "evidence":"artifacts/development/aport-crewai-source-global-hook-fixture-v3-20260913.json",
            "crewai_version": (crewai_round11 or {}).get("crewai_version"),
            "external_effect_attempts": (crewai_round11 or {}).get("external_effect_attempts"),
            "observation_records": len((crewai_round11 or {}).get("validation", {}).get("records", [])),
            "claim":"Prediction-before-oracle source-owned hook replay through the real CrewAI registry with local marker only; not an issue label or holdout admission."
        },
        "detector_stability_freeze": {
            "evidence":str(detector_freeze_path),
            "version": (detector_freeze or {}).get("version"),
            "detector_stable": (detector_freeze or {}).get("detector_stable", False),
            "source_tree_sha256": (detector_freeze or {}).get("source_tree_sha256"),
            "harness_tree_sha256": (detector_freeze or {}).get("harness_tree_sha256"),
            "source_scope": (detector_freeze or {}).get("source_scope"),
            "regression_passed": (detector_freeze or {}).get("regression_passed"),
            "claim":"Detector implementation freeze only; confirmation evaluation and repair remain separate stages."
        },
        "post_stability_screening": {
            "evidence":"artifacts/development/post-stability-round12-static-screen-20260913.json",
            "repositories": (post_static or {}).get("counts", {}).get("completed_repositories", 0),
            "guard_sites": (post_static or {}).get("counts", {}).get("guard_sites", 0),
            "explicit_effect_sites": (post_static or {}).get("counts", {}).get("explicit_effect_sites", 0),
            "execution_incomplete_rows": (post_static or {}).get("counts", {}).get("execution_incomplete_repository_rows", 0),
            "family_passed": (post_family or {}).get("counts", {}).get("passed", 0),
            "family_partial": (post_family or {}).get("counts", {}).get("partial", 0),
            "family_quarantined": (post_family or {}).get("counts", {}).get("quarantined", 0),
            "family_holdout_admission": (post_family or {}).get("holdout_family_admission", False),
            "claim":"Post-stability label-free screening frame; static candidates, unknown and unsupported rows require behavior oracle and are not issue labels."
        },
        "post_stability_family_admission": {
            "evidence":"artifacts/development/post-stability-round12-frame-family-admission-v4-20260913.json",
            "counts": (post_family or {}).get("counts", {}),
            "screen_passed": (post_family or {}).get("frame_family_screen_passed", False),
            "semantic_review_complete": (post_family or {}).get("semantic_review_complete", False),
            "claim":"Frame-scoped family screening for selected evaluation paths; unresolved lexical/AST candidates and unavailable paths remain in the evaluation frame and are not silently removed."
        },
        "post_stability_family_semantic_review": {
            "evidence":"artifacts/development/post-stability-round12-family-semantic-review-packet-v3-20260913.json",
            "candidate_pairs": (family_semantic_packet or {}).get("counts", {}).get("candidate_pairs", 0),
            "units_with_candidate_pairs": (family_semantic_packet or {}).get("counts", {}).get("units_with_candidate_pairs", 0),
            "unavailable_units": (family_semantic_packet or {}).get("counts", {}).get("unavailable_units", 0),
            "semantic_reviews_complete": (family_semantic_packet or {}).get("counts", {}).get("semantic_reviews_complete", 0),
            "claim":"Semantic family review packet only; automatic signals remain provisional and no holdout admission is granted."
        },
        "post_stability_two_phase": {
            "evidence":"artifacts/development/post-stability-round12-two-phase-freeze-20260913.json",
            "detector_freeze_evidence":"artifacts/development/detector-stability-freeze-v3-20260913.json",
            "screening_census": (post_two_phase or {}).get("counts", {}).get("screening_census", 0),
            "confirmation_sample": (post_two_phase or {}).get("counts", {}).get("confirmation_sample", 0),
            "strata": (post_two_phase or {}).get("counts", {}).get("strata", 0),
            "labels_read": (post_two_phase or {}).get("labels_read", False),
            "claim":"Post-stability stratified sampling freeze only; inclusion probabilities are fixed and no behavior labels or P/R are established."
        },
        "post_stability_oracle_queue": {
            "evidence":"artifacts/development/post-stability-round12-oracle-queue-n73-v2-20260913.json",
            "manifest_evidence":"artifacts/development/post-stability-round12-independent-oracle-manifest-n73-v2-20260913.json",
            "rows": len((post_oracle_queue or {}).get("rows", [])),
            "labels_read": (post_oracle_queue or {}).get("labels_read", False),
            "runtime_verified": (post_oracle_queue or {}).get("runtime_verified", 0),
            "claim":"Independent oracle inventory and queue are frozen without labels; evaluator independence and holdout admission remain unverified."
        },
        "post_stability_runtime_observations": {
            "evidence":"artifacts/development/post-stability-round12-source-guard-oracle-v7-20260913.json",
            "validation_evidence":"artifacts/development/post-stability-round12-source-guard-oracle-validation-v8-20260913.json",
            "prediction_freeze":"artifacts/development/post-stability-round12-prediction-freeze-n73-v2-20260913.json",
            "planned_candidates": (post_runtime_plan or {}).get("counts", {}).get("source_fixture_required", 0),
            "executed": (post_runtime_oracle or {}).get("counts", {}).get("executed", 0),
            "verified": (post_runtime_validation or {}).get("counts", {}).get("verified", 0),
            "false_safe_observations": (post_runtime_validation or {}).get("counts", {}).get("false_safe_observations", 0),
            "pilot_metrics_evidence":"artifacts/development/post-stability-round12-source-oracle-pilot-metrics-20260913.json",
            "pilot_metric_rows": len((source_pilot_metrics or {}).get("rows", [])),
            "pilot_precision": ((source_pilot_metrics or {}).get("metrics", {}).get("overall", {}) or {}).get("precision"),
            "pilot_recall": ((source_pilot_metrics or {}).get("metrics", {}).get("overall", {}) or {}).get("recall"),
            "claim":"Source-bound ALLOW/DENY mechanism observations after prediction freeze; no public repository entrypoint, model, network or external effect, and no independent issue labels are bound."
        },
        "repair_candidate_queue": {
            "evidence":"artifacts/development/post-stability-round12-repair-candidate-queue-20260913.json",
            "candidates": (repair_queue or {}).get("counts", {}).get("candidates", 0),
            "unattempted": (repair_queue or {}).get("counts", {}).get("unattempted", 0),
            "validated": (repair_queue or {}).get("counts", {}).get("validated", 0),
            "claim":"Shared IR repair obligations only; no source patch is applied and repair effectiveness is not claimed until isolated AST/CST and paired behavior verification pass."
        },
        "repair_verification_pilot": {
            "evidence":"artifacts/development/post-stability-repair-verification-pilot-20260913.json",
            "gate_passed": (repair_pilot or {}).get("gate_passed", False),
            "gates": (repair_pilot or {}).get("gates", {}),
            "claim":"One controlled generated-patch repair verification pilot; it does not establish repair rate or validate the seven post-stability candidates."
        },
        "confirmation_readiness_audit": {
            "evidence":str(confirmation_readiness_path),
            "counts": (confirmation_readiness or {}).get("counts", {}),
            "prediction_counts": (confirmation_readiness or {}).get("prediction_counts", {}),
            "observed_counts": (confirmation_readiness or {}).get("observed_counts", {}),
            "ready_for_final_p_r": (confirmation_readiness or {}).get("ready_for_final_p_r", False),
            "claim":"Mechanical confirmation-stage denominator and coverage audit; independent labels, final P/R and holdout admission remain incomplete."
        },
        "independent_oracle_packet": {
            "evidence":"artifacts/development/post-stability-round12-independent-oracle-packet-n73-v2-20260913.json",
            "rows": len((oracle_packet or {}).get("rows", [])),
            "present_predictions": (oracle_packet or {}).get("counts", {}).get("present_predictions", 0),
            "absent_predictions": (oracle_packet or {}).get("counts", {}).get("absent_predictions", 0),
            "unknown_predictions": (oracle_packet or {}).get("counts", {}).get("unknown_predictions", 0),
            "labels_bound": (oracle_packet or {}).get("labels_bound", False),
            "claim":"Label-free independent evaluator handoff packet bound to pinned materialization and prediction hashes; no labels or holdout admission are established."
        },
        "deterministic_runtime_oracle": {
            "evidence":"artifacts/development/post-stability-round12-deterministic-oracle-manifest-n73-20260913.json",
            "labels_bound": (deterministic_oracle or {}).get("label_count", 0),
            "known_labels": (deterministic_oracle or {}).get("known_label_count", 0),
            "unknown_labels": (deterministic_oracle or {}).get("unknown_label_count", 0),
            "prediction_artifacts_read": (deterministic_oracle or {}).get("prediction_artifacts_read"),
            "claim":"Prediction-blind deterministic behavior oracle; unknown rows remain unscored and human evaluator independence is not certified."
        },
        "bound_confirmation_metrics": {
            "evidence":"artifacts/development/post-stability-round12-bound-confirmation-metrics-20260913.json",
            "counts": (bound_metrics or {}).get("counts", {}),
            "overall": (bound_metrics or {}).get("metrics", {}).get("overall", {}),
            "final_metrics_available": (bound_metrics or {}).get("final_metrics_available", False),
            "claim":"IPW and cluster-bootstrap arithmetic over bound deterministic labels; low known coverage and no holdout admission prevent final P/R claims."
        },
        "independent_trace_oracle": {
            "evidence":"artifacts/development/post-stability-round12-independent-trace-oracle-20260913.json",
            "known_labels": (independent_trace_oracle or {}).get("known_label_count", 0),
            "unknown_labels": (independent_trace_oracle or {}).get("unknown_label_count", 0),
            "prediction_artifacts_read": (independent_trace_oracle or {}).get("prediction_artifacts_read"),
            "evaluator": (independent_trace_oracle or {}).get("evaluator"),
            "claim":"Independent event-state-machine recomputation agrees with the source-trace validator on observed rows; runtime provenance is shared and external-human independence, issue labels and holdout admission remain unclaimed."
        },
        "oracle_agreement": {
            "evidence":"artifacts/development/post-stability-round12-oracle-agreement-20260913.json",
            "valid": (oracle_agreement or {}).get("valid", False),
            "known_overlap": (oracle_agreement or {}).get("counts", {}).get("known_overlap", 0),
            "disagreements": (oracle_agreement or {}).get("counts", {}).get("disagreements", 0),
            "claim":"Mechanical agreement and inventory check between two prediction-blind label paths; shared runtime provenance means this does not certify external evaluator independence or holdout validity."
        },
        "post_stability_effect_dense_round13": {
            "evidence":"artifacts/development/post-stability-effect-dense-round13-static-20260913.json",
            "frame":"experiments/post-stability-effect-dense-freeze-round13-n339/FRAME.json",
            "materialization":"experiments/post-stability-effect-dense-materialization-round13-n339/MATERIALIZATION.json",
            "family_audit":"artifacts/development/post-stability-effect-dense-round13-family-audit-20260913.json",
            "queries_completed": (round13_frame or {}).get("counts", {}).get("queries_completed", 0),
            "queries_planned": (round13_frame or {}).get("counts", {}).get("queries", 0),
            "repositories_materialized": (round13_material or {}).get("counts", {}).get("completed", 0),
            "guard_sites": (round13_static or {}).get("counts", {}).get("guard_sites", 0),
            "effect_sites": (round13_static or {}).get("counts", {}).get("explicit_effect_sites", 0),
            "effect_source_families": (round13_family or {}).get("counts", {}).get("source_families", 0),
            "window_b_frame":"experiments/post-stability-effect-dense-freeze-round13b-n340/FRAME.json",
            "window_b_materialization":"experiments/post-stability-effect-dense-materialization-round13b-n340/MATERIALIZATION.json",
            "window_b_static":"artifacts/development/post-stability-effect-dense-round13b-static-v2-20260913.json",
            "window_b_queries_completed": (round13b_frame or {}).get("counts", {}).get("queries_completed", 0),
            "window_b_repositories_materialized": (round13b_material or {}).get("counts", {}).get("completed", 0),
            "window_b_guard_sites": (round13b_static or {}).get("counts", {}).get("guard_sites", 0),
            "window_b_effect_sites": (round13b_static or {}).get("counts", {}).get("explicit_effect_sites", 0),
            "v4_adk_google_api_recheck":"artifacts/development/post-stability-effect-dense-single-iamjean6-v4-20260913.json",
            "v4_adk_google_api_effect_sites": (adk_google_api_recheck or {}).get("counts", {}).get("explicit_effect_sites", 0),
            "v4_adk_google_api_effect_families": (adk_google_api_recheck or {}).get("counts", {}).get("effect_families", {}),
            "claim":"Two disjoint effect-dense discovery windows; different freeze-scope hashes and exact duplicate candidates prevent merging into a probability or holdout frame."
        },
        "detector_v3_v4_effect_classifier": {
            "evidence":"artifacts/development/detector-v3-v4-effect-classifier-comparison-20260913.json",
            "guard_sites_before": (classifier_comparison or {}).get("guard_sites_before"),
            "guard_sites_after": (classifier_comparison or {}).get("guard_sites_after"),
            "effects_removed": len((classifier_comparison or {}).get("effects_removed", [])),
            "effects_added": len((classifier_comparison or {}).get("effects_added", [])),
            "claim":"Development precision fix for API-origin effect classification; Round12 predictions remain frozen under detector v3."
        },
        "post_v8_burnin_cohort": {
            "evidence":"experiments/post-v8-history-audit-round14e-n361/RESULT.json",
            "round14_prior_repository_overlap": (round14_history or {}).get("counts", {}).get("overlap_repositories", 0),
            "frame":"experiments/post-v8-public-candidate-merged-round15-16-n366/FRAME.json",
            "repositories": (clean_frame or {}).get("counts", {}).get("selected", 0),
            "strata": (clean_frame or {}).get("counts", {}).get("strata", 0),
            "ledger_validation_artifact":"experiments/post-v8-candidate-exclusion-validation-n367/RESULT.json",
            "historical_repository_overlap": (clean_exclusion or {}).get("counts", {}).get("overlap"),
            "materialization":"experiments/post-v8-materialization-round15-16-n368/MATERIALIZATION.json",
            "repositories_materialized": (clean_material or {}).get("counts", {}).get("completed_unique_repositories", 0),
            "source_static_artifact":"experiments/post-v8-static-screen-round15-16-n369/RESULT.json",
            "guard_sites": (clean_static or {}).get("counts", {}).get("guard_sites", 0),
            "effect_sites": (clean_static or {}).get("counts", {}).get("explicit_effect_sites", 0),
            "execution_incomplete_rows": (clean_static or {}).get("counts", {}).get("execution_incomplete_repository_rows", 0),
            "family_audit":"experiments/post-v8-family-admission-final-round15-16-n375/RESULT.json",
            "family_passed": (clean_family or {}).get("counts", {}).get("passed", 0),
            "family_quarantined": (clean_family or {}).get("counts", {}).get("quarantined", 0),
            "source_two_phase_freeze":"experiments/post-v8-confirmation-freeze-round15-16-n376/TWO_PHASE.json",
            "confirmation_sample": (clean_two_phase or {}).get("counts", {}).get("confirmation_sample", 0),
            "prediction_artifact":"experiments/post-v8-prediction-freeze-round15-16-n377/MANIFEST.json",
            "prediction_counts": (clean_predictions or {}).get("counts", {}),
            "oracle_manifest_artifact":"experiments/post-v8-oracle-freeze-round15-16-n378/ORACLE_MANIFEST.json",
            "oracle_labels_bound": (clean_oracle or {}).get("labels_bound", False),
            "claim":"Post-v8 identity/family/oracle burn-in only. Discovery of a shared multi-callback lifecycle defect caused detector v9, so this cohort is not the final v9 holdout and its labels remain unopened."
        },
        "post_v9_candidate_frame": {
            "evidence":"experiments/post-v9-public-candidate-merged-round17-18-n385/FRAME.json",
            "repositories": (v9_round17 or {}).get("counts", {}).get("selected", 0),
            "selected_by_stratum": (v9_round17 or {}).get("counts", {}).get("selected_by_stratum", {}),
            "source_ledger":"experiments/repository-exclusion-set-round17-n381/EXCLUSIONS.json",
            "excluded_repositories": (v9_exclusions or {}).get("counts", {}).get("repositories", 0),
            "materialization":"experiments/post-v9-materialization-round17-18-n387/MATERIALIZATION.json",
            "repositories_materialized": (v9_material or {}).get("counts", {}).get("completed_unique_repositories", 0),
            "source_static_artifact":"experiments/post-v9-static-screen-round17-18-n388/RESULT.json",
            "guard_sites": (v9_static or {}).get("counts", {}).get("guard_sites", 0),
            "effect_sites": (v9_static or {}).get("counts", {}).get("explicit_effect_sites", 0),
            "execution_incomplete_rows": (v9_static or {}).get("counts", {}).get("execution_incomplete_repository_rows", 0),
            "family_audit":"experiments/post-v9-family-admission-final-round17-18-n395/RESULT.json",
            "family_passed": (v9_family or {}).get("counts", {}).get("passed", 0),
            "family_quarantined": (v9_family or {}).get("counts", {}).get("quarantined", 0),
            "source_two_phase_freeze":"experiments/post-v9-confirmation-freeze-round17-18-n396/TWO_PHASE.json",
            "confirmation_sample": (v9_two_phase or {}).get("counts", {}).get("confirmation_sample", 0),
            "prediction_artifact":"experiments/post-v9-prediction-freeze-round17-18-n397/MANIFEST.json",
            "prediction_counts": (v9_predictions or {}).get("counts", {}),
            "oracle_manifest_artifact":"experiments/post-v9-oracle-freeze-round17-18-n398/ORACLE_MANIFEST.json",
            "oracle_labels_bound": (v9_oracle or {}).get("labels_bound", False),
            "manifest_evidence":"experiments/post-v9-runtime-plan-round17-18-n399/PLAN.json",
            "runtime_plan_counts": (v9_runtime_plan or {}).get("counts", {}),
            "claim":"Post-v9 identity, materialization, family and prediction freeze after excluding all registered development/burn-in repositories. The 101-unit confirmation sample covers present, absent and unknown predictions; later deterministic source observations remain sparse and do not authorize final P/R or holdout completion."
        },
        "post_v9_runtime_confirmation": {
            "evidence":"experiments/post-v9-source-oracle-n417/RESULT.json",
            "source_execution_counts": (v9_runtime_oracle or {}).get("counts", {}),
            "validation_evidence":"experiments/post-v9-source-oracle-validation-n418/RESULT.json",
            "validation_counts": (v9_runtime_validation or {}).get("counts", {}),
            "oracle_manifest_artifact":"experiments/post-v9-bound-oracle-n419/BOUND_MANIFEST.json",
            "known_labels": (v9_bound_oracle or {}).get("known_label_count", 0),
            "unknown_labels": (v9_bound_oracle or {}).get("unknown_label_count", 0),
            "prediction_artifacts_read": (v9_bound_oracle or {}).get("prediction_artifacts_read"),
            "measurement":"experiments/post-v9-bound-metrics-n420/RESULT.json",
            "weighted_metrics": (v9_bound_metrics or {}).get("metrics", {}).get("overall", {}),
            "final_metrics_available": (v9_bound_metrics or {}).get("final_metrics_available", False),
            "readiness_evidence":"experiments/post-v9-confirmation-readiness-n421/RESULT.json",
            "ready_for_final_p_r": (v9_confirmation_readiness or {}).get("ready_for_final_p_r", False),
            "claim":"Prediction-blind, source-bound paired local-canary observations cover four of 101 confirmation units. Three present and one absent observations are bound while 97 remain unknown; point estimates are diagnostic only because coverage and effective sample size are inadequate, evaluator independence is not externally authenticated, and holdout admission is false."
        },
        "post_v9_run_chain": {
            "evidence":"experiments/post-v9-run-chain-audit-n422/RESULT.json",
            "counts": (v9_run_chain or {}).get("counts", {}),
            "valid": (v9_run_chain or {}).get("valid", False),
            "claim":"Mechanical plan/manifest identity and component-fingerprint closure for the post-v9 collection-to-oracle-freeze stages; scientific meaning and label correctness remain separate."
        },
        "post_v9_effect_enriched_oracle_burnin": {
            "frame":"experiments/post-v9-effect-enriched-freeze-round19-n423/FRAME.json",
            "repositories": (round19_frame or {}).get("counts", {}).get("selected", 0),
            "materialization":"experiments/post-v9-effect-enriched-materialization-round19-n424/MATERIALIZATION.json",
            "repositories_materialized": (round19_material or {}).get("counts", {}).get("completed_unique_repositories", 0),
            "source_static_artifact":"experiments/post-v9-deny-capability-static-round19-n434/RESULT.json",
            "guard_sites": (round19_static or {}).get("counts", {}).get("guard_sites", 0),
            "effect_sites": (round19_static or {}).get("counts", {}).get("explicit_effect_sites", 0),
            "deny_capability": (round19_static or {}).get("counts", {}).get("deny_capability", {}),
            "deny_effect_candidates": (round19_static or {}).get("counts", {}).get("deny_effect_candidates", {}),
            "family_audit":"experiments/post-v9-effect-enriched-family-admission-round19-n428/RESULT.json",
            "family_counts": (round19_family or {}).get("counts", {}),
            "validation_evidence":"experiments/source-oracle-round19-isolated-n432/RESULT.json",
            "runtime_counts": (round19_runtime or {}).get("counts", {}),
            "container_isolation": (round19_runtime or {}).get("container_isolation", {}),
            "source_two_phase_freeze":"experiments/post-v9-deny-capability-confirmation-round19-n435/TWO_PHASE.json",
            "confirmation_counts": (round19_confirmation or {}).get("counts", {}),
            "claim":"Effect-enriched oracle-development pool only. One hundred fresh repositories yielded 19 explicit-effect sites, but denial-capability analysis reduced these to two DENY-capable candidates, three proven non-denying sites and fourteen unknowns. Exact/near-copy review left 25 repositories partial; five family-clean repositories contain eight independent effect-bearing sites. The first new Pydantic post-effect source guard passed paired local-canary replay inside a pinned read-only, networkless, capability-free container. This pool is used to stabilize the oracle and is not a final holdout or prevalence frame."
        },
        "post_v10_final_evaluation_frame": {
            "frame":"experiments/post-v10-final-candidate-freeze-round20-n443/FRAME.json",
            "repositories": (round20_frame or {}).get("counts", {}).get("selected", 0),
            "queries": (round20_frame or {}).get("counts", {}).get("queries_completed", 0),
            "source_ledger":"experiments/repository-exclusion-set-round20-n436/EXCLUSIONS.json",
            "materialization":"experiments/post-v10-final-materialization-round20-n444/MATERIALIZATION.json",
            "materialization_counts": (round20_material or {}).get("counts", {}),
            "validation_evidence":"experiments/post-v10-final-materialization-verification-round20-n458/RESULT.json",
            "materialization_validation": (round20_material_validation or {}).get("counts", {}),
            "source_static_artifact":"experiments/post-v10-final-static-round20-n447/RESULT.json",
            "guard_sites": (round20_static or {}).get("counts", {}).get("guard_sites", 0),
            "effect_sites": (round20_static or {}).get("counts", {}).get("explicit_effect_sites", 0),
            "deny_effect_candidates": (round20_static or {}).get("counts", {}).get("deny_effect_candidates", {}),
            "family_audit":"experiments/post-v10-final-family-admission-reviewed-round20-n453/RESULT.json",
            "family_counts": (round20_family or {}).get("counts", {}),
            "source_two_phase_freeze":"experiments/post-v10-final-confirmation-round20-n454/TWO_PHASE.json",
            "confirmation_counts": (round20_two_phase or {}).get("counts", {}),
            "prediction_artifact":"experiments/post-v10-final-prediction-freeze-round20-n455/MANIFEST.json",
            "prediction_counts": (round20_predictions or {}).get("counts", {}),
            "oracle_manifest_artifact":"experiments/post-v10-final-oracle-freeze-round20-n461/ORACLE_MANIFEST.json",
            "oracle_labels_bound": (round20_oracle or {}).get("labels_bound", False),
            "runtime_plan":"experiments/post-v10-final-runtime-plan-round20-n460/PLAN.json",
            "runtime_plan_counts": (round20_runtime_plan or {}).get("counts", {}),
            "fixture_handoff":"experiments/post-v10-final-fixture-handoff-round20-n463/HANDOFF.json",
            "fixture_handoff_counts": (round20_handoff or {}).get("counts", {}),
            "fixture_task_packet":"experiments/post-v10-final-fixture-tasks-round20-n467/TASKS.json",
            "fixture_task_counts": (round20_fixture_tasks or {}).get("counts", {}),
            "fixture":"experiments/post-v10-final-fixture-proposals-round20-n470/RESULT.json",
            "llm_fixture_proposal_counts": (round20_fixture_proposals or {}).get("counts", {}),
            "artifact":"experiments/post-v10-final-ast-fixture-config-round20-n474/CONFIG.json",
            "ast_fixture_counts": (round20_ast_fixtures or {}).get("counts", {}),
            "validation_evidence":"experiments/post-v10-final-source-oracle-validation-round20-n476/RESULT.json",
            "runtime_validation_counts": (round20_runtime_validation or {}).get("counts", {}),
            "bound_manifest":"experiments/post-v10-final-bound-oracle-round20-n477/BOUND_MANIFEST.json",
            "known_behavior_labels": (round20_bound_oracle or {}).get("known_label_count", 0),
            "measurement":"experiments/post-v10-final-bound-metrics-round20-n478/RESULT.json",
            "weighted_metrics": (round20_metrics or {}).get("metrics", {}).get("overall", {}),
            "final_metrics_available": (round20_metrics or {}).get("final_metrics_available", False),
            "readiness_evidence":"experiments/post-v10-final-readiness-round20-n479/RESULT.json",
            "ready_for_final_p_r": (round20_readiness or {}).get("ready_for_final_p_r", False),
            "manifest_evidence":"experiments/post-v10-final-run-chain-audit-round20-n466/RESULT.json",
            "run_chain": (round20_run_chain or {}).get("counts", {}),
            "claim":"Post-v10 final evaluation inventory frozen after excluding 6,950 prior repositories. Twenty complete queries produced 263 unique pinned repositories with zero identity overlap; 261 materialized and two checkout timeouts remain source-unavailable. Family review quarantined 37 repositories and retains six unavailable units; the family-clean population yields a 263-unit stratified confirmation sample with predictions frozen before an independent oracle. No behavior labels, P/R or prevalence are yet claimed."
        },
        "post_v11_large_scale_evaluation": {
            "evidence":"experiments/large-scale-direct-census-post-v11-n502/CENSUS.json",
            "direct_repositories": (large_scale_direct or {}).get("counts", {}).get("direct_repositories", 0),
            "minimum_direct_repositories": (large_scale_direct or {}).get("counts", {}).get("minimum_direct_repositories", 0),
            "minimum_met": (large_scale_direct or {}).get("counts", {}).get("minimum_met", False),
            "partition_counts": (large_scale_direct or {}).get("counts", {}).get("by_partition", {}),
            "partition_overlap": (large_scale_direct or {}).get("counts", {}).get("repositories_in_multiple_partitions"),
            "family_audit":"experiments/large-scale-direct-family-audit-post-v11-n504/RESULT.json",
            "family_candidate_components": (large_scale_family or {}).get("counts", {}).get("known_family_candidate_components", 0),
            "family_fingerprint_coverage": (large_scale_family or {}).get("counts", {}).get("repositories_with_fingerprint_coverage", 0),
            "frame":"experiments/post-v11-final-candidate-census-round21-n495/FRAME.json",
            "prospective_identity_repositories": (round21_frame or {}).get("counts", {}).get("selected", 0),
            "materialization":"experiments/post-v11-final-materialization-round21-n497/MATERIALIZATION.json",
            "materialization_counts": (round21_material or {}).get("counts", {}),
            "validation_evidence":"experiments/post-v11-final-materialization-verification-round21-n499/RESULT.json",
            "materialization_validation": (round21_material_validation or {}).get("counts", {}),
            "source_static_artifact":"experiments/post-v11-final-static-round21-n500/RESULT.json",
            "prospective_guard_sites": (round21_static or {}).get("counts", {}).get("guard_sites", 0),
            "prospective_direct_repositories": (round21_static or {}).get("counts", {}).get("repositories_with_sites", 0),
            "prospective_effect_sites": (round21_static or {}).get("counts", {}).get("explicit_effect_sites", 0),
            "prospective_execution_incomplete_rows": (round21_static or {}).get("counts", {}).get("execution_incomplete_repository_rows", 0),
            "family_admission":"experiments/post-v11-final-family-admission-conservative-round21-n507/RESULT.json",
            "prospective_family_counts": (round21_family or {}).get("counts", {}),
            "source_two_phase_freeze":"experiments/post-v11-final-confirmation-round21-n508/TWO_PHASE.json",
            "confirmation_counts": (round21_two_phase or {}).get("counts", {}),
            "prediction_artifact":"experiments/post-v11-final-prediction-freeze-round21-n509/MANIFEST.json",
            "prediction_counts": (round21_predictions or {}).get("counts", {}),
            "oracle_manifest_artifact":"experiments/post-v11-final-oracle-freeze-round21-n510/ORACLE_MANIFEST.json",
            "oracle_labels_bound": (round21_oracle or {}).get("labels_bound", False),
            "runtime_plan":"experiments/post-v11-final-runtime-plan-round21-n511/PLAN.json",
            "runtime_plan_counts": (round21_runtime_plan or {}).get("counts", {}),
            "fixture_handoff":"experiments/post-v11-final-fixture-handoff-round21-n512/HANDOFF.json",
            "fixture_handoff_counts": (round21_handoff or {}).get("counts", {}),
            "fixture_task_packet":"experiments/post-v11-final-fixture-tasks-round21-n513/TASKS.json",
            "fixture_task_counts": (round21_fixture_tasks or {}).get("counts", {}),
            "artifact":"experiments/post-v11-final-registration-components-round21-n514/RESULT.json",
            "registration_component_counts": (round21_components or {}).get("counts", {}),
            "fixture":"experiments/post-v11-final-ast-fixture-config-round21-n517/CONFIG.json",
            "ast_fixture_counts": (round21_ast_fixtures or {}).get("counts", {}),
            "validation_evidence":"experiments/post-v11-final-source-oracle-validation-merged-round21-n542/RESULT.json",
            "runtime_validation_counts": (round21_runtime_validation or {}).get("counts", {}),
            "bound_manifest":"experiments/post-v11-final-bound-oracle-merged-round21-n543/BOUND_MANIFEST.json",
            "known_behavior_labels": (round21_bound_oracle or {}).get("known_label_count", 0),
            "measurement":"experiments/post-v11-final-bound-metrics-merged-round21-n544/RESULT.json",
            "weighted_metrics": (round21_metrics or {}).get("metrics", {}).get("overall", {}),
            "final_metrics_available": (round21_metrics or {}).get("final_metrics_available", False),
            "independent_trace_oracle":"experiments/post-v11-final-independent-trace-oracle-merged-round21-n547/RESULT.json",
            "independent_trace_known": (round21_independent_trace or {}).get("known_label_count", 0),
            "oracle_agreement_artifact":"experiments/post-v11-final-oracle-agreement-merged-round21-n548/RESULT.json",
            "oracle_agreement": (round21_oracle_agreement or {}).get("counts", {}),
            "readiness_evidence":"experiments/post-v11-final-readiness-merged-round21-n549/RESULT.json",
            "ready_for_final_p_r": (round21_readiness or {}).get("ready_for_final_p_r", False),
            "effect_supplement":"experiments/post-v11-final-effect-supplement-round21-n529/RESULT.json",
            "effect_supplement_counts": (round21_effect_supplement or {}).get("counts", {}),
            "effect_review_packet":"experiments/post-v11-final-effect-review-packet-round21-n532/PACKET.json",
            "effect_review_counts": (round21_effect_review or {}).get("counts", {}),
            "registration_binding":"experiments/post-v11-final-effect-registration-binding-round21-n533/RESULT.json",
            "registration_binding_counts": (round21_registration_binding or {}).get("counts", {}),
            "deny_unreachable_proof":"experiments/post-v11-final-deny-unreachable-proof-round21-n534/RESULT.json",
            "deny_unreachable_counts": (round21_deny_proof or {}).get("counts", {}),
            "mixed_issue_metrics":"experiments/post-v11-final-mixed-issue-metrics-merged-round21-n545/RESULT.json",
            "mixed_issue_counts": (round21_mixed_metrics or {}).get("counts", {}),
            "mixed_issue_overall": (round21_mixed_metrics or {}).get("metrics", {}).get("overall", {}),
            "manifest_evidence":"experiments/post-v11-large-scale-run-chain-audit-n550/RESULT.json",
            "run_chain": (round21_run_chain or {}).get("counts", {}),
            "claim":"The evidence-gated repository census contains 745 direct repositories: 686 retrospectively exposed development repositories with verified guard-API bindings and 59 disjoint post-v11 repositories with recovered guard registrations. All 745 have source fingerprints and conservatively collapse to 647 known family-candidate components. The 700-repository scale gate is met. Prediction-blind supplemental discovery found 107 production co-domain candidates, but shared registration binding retained only one guard-internal logging candidate. Twenty-five paired runtime labels plus eight source-proven no-DENY exclusions adjudicate thirty-three confirmation units; design-weighted behavior coverage is 15.08% and issue adjudication coverage is 18.12%. The two prediction-blind label implementations agree on all twenty-five known units. No true positive is yet observed, and final P/R remain unavailable."
        },
        "post_v11_effect_enriched_accuracy_and_repair": {
            "evidence":"experiments/post-v11-effect-enriched-static-round22-n561/RESULT.json",
            "study_role":"accuracy_error_repair_enrichment_not_prevalence",
            "static_counts": (round22_static or {}).get("counts", {}),
            "family_counts": (round22_family or {}).get("counts", {}),
            "confirmation_counts": (round22_two_phase or {}).get("counts", {}),
            "prediction_counts": (round22_predictions or {}).get("counts", {}),
            "component_evidence":"experiments/post-v11-effect-enriched-registration-components-round22-n584/RESULT.json",
            "component_counts": (round22_components or {}).get("counts", {}),
            "fixture_evidence":"experiments/post-v11-effect-enriched-ast-fixtures-round22-n585/CONFIG.json",
            "fixture_counts": (round22_fixtures or {}).get("counts", {}),
            "runtime_evidence":"experiments/post-v11-effect-enriched-source-oracle-round22-n586/RESULT.json",
            "runtime_counts": (round22_runtime or {}).get("counts", {}),
            "validation_evidence":"experiments/post-v11-effect-enriched-source-oracle-validation-round22-n587/RESULT.json",
            "validation_counts": (round22_validation or {}).get("counts", {}),
            "metric_evidence":"experiments/post-v11-effect-enriched-bound-metrics-round22-n589/RESULT.json",
            "weighted_metrics": (round22_metrics or {}).get("metrics", {}).get("overall", {}),
            "final_metrics_available": (round22_metrics or {}).get("final_metrics_available", False),
            "repair_queue_evidence":"experiments/post-v11-effect-enriched-verified-repair-queue-round22-n590/QUEUE.json",
            "repair_queue_counts": (round22_repair_queue or {}).get("counts", {}),
            "repair_model_runs": {
                "glm_4_5_flash":"experiments/post-v11-effect-enriched-llm-repair-proposals-round22-n594/RESULT.json",
                "glm_4_5_flash_counts": (round22_repair_glm45 or {}).get("counts", {}),
                "intern_s2_preview":"experiments/post-v11-effect-enriched-llm-repair-proposals-round22-n595/RESULT.json",
                "intern_s2_preview_counts": (round22_repair_intern or {}).get("counts", {}),
                "glm_z1_flash":"experiments/post-v11-effect-enriched-llm-repair-proposals-round22-n596/RESULT.json",
                "glm_z1_flash_counts": (round22_repair_glmz1 or {}).get("counts", {}),
                "gpt_5_6_terra":"experiments/post-v11-effect-enriched-llm-repair-proposals-round22-n607/RESULT.json",
                "gpt_5_6_terra_counts": (round22_repair_terra or {}).get("counts", {}),
            },
            "repair_correction_evidence":"experiments/post-v11-effect-enriched-llm-repair-correction-round22-n608/RESULT.json",
            "repair_correction_counts": (round22_repair_correction or {}).get("counts", {}),
            "repair_policy_evidence":"experiments/post-v11-effect-enriched-llm-repair-policy-validation-round22-n609/RESULT.json",
            "repair_policy_counts": (round22_repair_policy or {}).get("counts", {}),
            "repair_sdk_evidence":"experiments/post-v11-effect-enriched-llm-repair-sdk-validation-round22-n610/RESULT.json",
            "repair_sdk_counts": (round22_repair_sdk or {}).get("counts", {}),
            "v12_development_evidence":"experiments/post-v11-effect-enriched-static-v12-development-round22-n600/RESULT.json",
            "v12_development_counts": (round22_v12_static or {}).get("counts", {}),
            "v12_comparison_evidence":"experiments/post-v11-effect-enriched-static-v12-comparison-round22-n604/RESULT.json",
            "v12_comparison_counts": (round22_v12_comparison or {}).get("counts", {}),
            "model_catalog_evidence":"experiments/paratera-model-catalog-20260914-n613/MODEL_CATALOG.json",
            "model_catalog_count": (paratera_catalog or {}).get("count", 0),
            "selected_repair_model": (paratera_catalog or {}).get("selected_repair_model"),
            "manifest_evidence":"experiments/post-v11-large-scale-run-chain-audit-n614/RESULT.json",
            "run_chain": (round22_run_chain or {}).get("counts", {}),
            "claim":"Effect-enriched development evidence only. Four paired DENY/effect observations come from two repositories with two source variants each; known behavior coverage is 1.36%, so final P/R and prevalence remain unavailable. The shared v12 contextual import resolver changes exactly four of 150 stable site identities, all from unknown to resolved in the independently observed parallel-source-tree case; frozen v11 predictions remain unchanged. Two behavior-confirmed static repair candidates collapse to one repair family. A frontier-model correction produced one cleanly applying candidate that preserved the registered output guard and added two pre-tool guards, but the pinned openai-agents 0.0.16 wheel lacks both newly imported APIs, so the dependency gate rejects it and verified repair remains zero."
        },
        "post_v12_round23_query_exhaustion": {
            "query_config":"config/post-v12-effect-enriched-search-round23.json",
            "detector_freeze":"artifacts/development/detector-stability-freeze-v12-20260914.json",
            "exclusion_evidence":"experiments/repository-exclusion-set-round23-n616/EXCLUSIONS.json",
            "excluded_repositories": (round23_exclusions or {}).get("counts", {}).get("repositories", 0),
            "window_a":"experiments/post-v12-effect-enriched-raw-round23a-n617/RAW.json",
            "window_a_counts": (round23_raw_a or {}).get("counts", {}),
            "window_b":"experiments/post-v12-effect-enriched-raw-round23b-n618/RAW.json",
            "window_b_counts": (round23_raw_b or {}).get("counts", {}),
            "census_evidence":"experiments/post-v12-effect-enriched-census-round23-n620/FRAME.json",
            "census_counts": (round23_census or {}).get("counts", {}),
            "manifest_evidence":"experiments/post-v12-pause-run-chain-audit-n621/RESULT.json",
            "run_chain": (pause_run_chain or {}).get("counts", {}),
            "claim":"The reused twenty-query top-100 protocol completed without execution errors after excluding 7,607 prior repositories and yielded zero new identities. This is query-protocol exhaustion, not evidence that the public ecosystem has no additional relevant repositories. A future resumed round must preregister complementary structural and synonym queries."
        },
        "post_v12_round24_complementary_confirmation": {
            "evidence":"experiments/post-v12-complementary-census-round24-n631/FRAME.json",
            "study_role":"post_v12_accuracy_generalization_enrichment_not_prevalence",
            "frame_counts": (round24_frame or {}).get("counts", {}),
            "materialization":"experiments/post-v12-complementary-materialization-round24-n632/MATERIALIZATION.json",
            "materialization_counts": (round24_material or {}).get("counts", {}),
            "validation_evidence":"experiments/post-v12-complementary-materialization-verification-round24-n634/RESULT.json",
            "materialization_validation": (round24_material_validation or {}).get("counts", {}),
            "source_static_artifact":"experiments/post-v12-complementary-static-round24-n636/RESULT.json",
            "static_counts": (round24_static or {}).get("counts", {}),
            "family_admission":"experiments/post-v12-complementary-family-admission-round24-n640/RESULT.json",
            "family_counts": (round24_family or {}).get("counts", {}),
            "source_two_phase_freeze":"experiments/post-v12-complementary-confirmation-round24-n642/TWO_PHASE.json",
            "confirmation_counts": (round24_two_phase or {}).get("counts", {}),
            "prediction_artifact":"experiments/post-v12-complementary-prediction-freeze-round24-n643/MANIFEST.json",
            "prediction_counts": (round24_predictions or {}).get("counts", {}),
            "oracle_manifest_artifact":"experiments/post-v12-complementary-oracle-freeze-round24-n644/ORACLE_MANIFEST.json",
            "oracle_labels_bound": (round24_oracle or {}).get("labels_bound", False),
            "runtime_plan":"experiments/post-v12-complementary-runtime-plan-round24-n645/PLAN.json",
            "runtime_plan_counts": (round24_runtime_plan or {}).get("counts", {}),
            "fixture_task_packet":"experiments/post-v12-complementary-fixture-tasks-round24-n647/TASKS.json",
            "fixture_task_counts": (round24_tasks or {}).get("counts", {}),
            "component_evidence":"experiments/post-v12-complementary-registration-components-round24-n648/RESULT.json",
            "component_counts": (round24_components or {}).get("counts", {}),
            "fixture_evidence":"experiments/post-v12-complementary-ast-fixtures-round24-n660/CONFIG.json",
            "fixture_counts": (round24_fixtures or {}).get("counts", {}),
            "runtime_validation":"experiments/post-v12-complementary-source-oracle-validation-round24-n662/RESULT.json",
            "runtime_validation_counts": (round24_runtime_validation or {}).get("counts", {}),
            "bound_manifest":"experiments/post-v12-complementary-bound-oracle-round24-n663/BOUND_MANIFEST.json",
            "known_behavior_labels": (round24_bound or {}).get("known_label_count", 0),
            "metrics_evidence":"experiments/post-v12-complementary-bound-metrics-round24-n665/RESULT.json",
            "weighted_metrics": (round24_metrics or {}).get("metrics", {}).get("overall", {}),
            "final_metrics_available": (round24_metrics or {}).get("final_metrics_available", False),
            "deny_proof":"experiments/post-v12-complementary-deny-unreachable-proof-round24-n666/RESULT.json",
            "deny_proof_counts": (round24_deny_proof or {}).get("counts", {}),
            "mixed_issue_metrics":"experiments/post-v12-complementary-mixed-issue-metrics-round24-n667/RESULT.json",
            "mixed_issue_counts": (round24_mixed or {}).get("counts", {}),
            "mixed_issue_overall": (round24_mixed or {}).get("metrics", {}).get("overall", {}),
            "oracle_agreement_artifact":"experiments/post-v12-complementary-oracle-agreement-round24-n669/RESULT.json",
            "oracle_agreement": (round24_agreement or {}).get("counts", {}),
            "readiness_evidence":"experiments/post-v12-complementary-readiness-round24-n670/RESULT.json",
            "ready_for_final_p_r": (round24_readiness or {}).get("ready_for_final_p_r", False),
            "manifest_evidence":"experiments/post-v12-round24-run-chain-audit-n671/RESULT.json",
            "run_chain": (round24_run_chain or {}).get("counts", {}),
            "claim":"A preregistered page-2 plus structural-synonym search yielded 486 eligible rows and 355 unique post-v12 repository identities. Source verification retained 354 verified materializations and one explicit attrition. The family-clean confirmation frame contains 416 units across 17 strata with predictions frozen at present=7, absent=29 and unknown=380. Six predicted positives have prediction-blind paired runtime observations of DENY after a committed marker; twelve additional ADK-pre units have source-proven unreachable denial signals. Mixed issue coverage is 4.33%; precision and recall point estimates of 1.0 are supported by only six positives and final metrics remain unavailable. This enriched frame is not a prevalence sample."
        },
        "generic_source_oracle_burnin": {
            "evidence":"artifacts/development/post-stability-round12-source-guard-oracle-generic-v9-20260913.json",
            "validation_evidence":"artifacts/development/post-stability-round12-source-guard-oracle-generic-v9-validation-20260913.json",
            "counts": (generic_runtime_validation or {}).get("counts", {}),
            "valid": (generic_runtime_validation or {}).get("valid", False),
            "claim":"Development-only OpenAI-style source-guard replay after removing guard-name input dispatch; it does not validate the ADK, CrewAI or Pydantic adapters required for final labels."
        },
        "path_evidence": {"v2_status":"all prior candidate paths unverified","registration_group_candidates":2,"registration_group_artifact":"experiments/prospective-effect-selection-n307/REGISTRATION_PATH_AUDIT.json","retracted_artifacts":["n303/n304/n307/n311 v1 path audits","derived static oracle queues"],"claim":"Two n307 records have same-group registration evidence; joint runtime reachability remains unverified."}},
        "supplemental_frameworks":["langgraph","microsoft-agent-framework","vercel-ai-sdk"],
        "retracted": ["v1 path_supported based on name lookup alone","static candidates treated as runtime labels","fixed 1000 as an upper bound"],
        "claim_boundary":"This manifest is a writing aid. It does not upgrade any artifact, authorize public code execution, or prove the full research goal."}

if __name__=="__main__":
    result=build(); out=Path("experiments/paper-evidence-manifest-n327"); out.mkdir(exist_ok=True); (out/"MANIFEST.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps({"claims":len(result["claims"]),"supplemental":len(result["supplemental_frameworks"]),"verified_samples":0}))
