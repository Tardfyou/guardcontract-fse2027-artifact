"""Classify persisted project artifacts by development-exposure channel."""
def repositories(document,universe):
    found=set()
    def visit(value,key=None):
        if isinstance(value,dict):
            for name,child in value.items():visit(child,name)
        elif isinstance(value,list):
            for child in value:visit(child,key)
        elif isinstance(value,str) and key in {"repository","repository_id","repositories","eligible_repositories"}:
            name=value.rsplit("@",1)[0]
            if name in universe:found.add(name)
    visit(document);return found
def annotations_filled(document):
    samples=document.get("samples",[]) if isinstance(document,dict) else []
    for row in samples:
        annotation=row.get("annotation") if isinstance(row,dict) else None
        if isinstance(annotation,dict) and any(value not in (None,[],{}) for value in annotation.values()):return True
    return False
def manual_channel(document):
    if not isinstance(document,dict):return "identity_only"
    if document.get("frame_kind","").endswith("queue") or document.get("status")=="unannotated":return "identity_only"
    if "samples" in document and not annotations_filled(document) and not any(isinstance(r,dict) and "decisions" in r for r in document["samples"]):return "identity_only"
    if any(key in document for key in ("groups","cases","sites")) or any(isinstance(r,dict) and "decisions" in r for r in document.get("samples",[])):return "manual_source_or_label_exposure"
    return "identity_only"
def build(universe,model_documents,manual_documents,evaluation_documents):
    channels={"model_input_exposure":{},"manual_source_or_label_exposure":{},"identity_only":{}}
    for path,document in model_documents.items():
        names=sorted(repositories(document,universe))
        if names:channels["model_input_exposure"][path]=names
    for path,document in manual_documents.items():
        names=sorted(repositories(document,universe));channel=manual_channel(document)
        if names:channels[channel][path]=names
    for path,document in evaluation_documents.items():
        names=sorted(repositories(document,universe))
        if names:channels["identity_only"][path]=names
    definite=set().union(*(set(v) for key in ("model_input_exposure","manual_source_or_label_exposure") for v in channels[key].values()))
    identity=set().union(*(set(v) for v in channels["identity_only"].values()))-definite
    return {"schema_version":"historical-exposure-inventory-1","channels":channels,"definite_exposure_repositories":sorted(definite),"identity_only_repositories":sorted(identity),
        "counts":{"model_input_files":len(model_documents),"manual_candidate_files":len(manual_documents),"evaluation_plan_files":len(evaluation_documents),
            "model_input_exposure_repositories":len(set().union(*(set(v) for v in channels["model_input_exposure"].values()))),
            "manual_source_or_label_exposure_repositories":len(set().union(*(set(v) for v in channels["manual_source_or_label_exposure"].values()))),"identity_only_repositories":len(identity)},
        "project_persisted_inventory_complete":True,"private_session_context_inventory_complete":False,"holdout_admission_authorized":False,
        "blocking_gaps":["private_session_context_semantic_audit_incomplete","identity_only_does_not_prove_source_blindness","prospective_corpus_not_frozen"],
        "claim_boundary":"Persisted project model inputs and completed manual source/label artifacts are definite exposure. Queues, blank templates and evaluation identity lists are identity-only. Private session transcripts are not copied or semantically adjudicated, so no holdout is admitted."}
