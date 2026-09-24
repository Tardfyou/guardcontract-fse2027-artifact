"""Rebuild compact RQ table data from the anonymous artifact without network/model calls."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def read(path): return json.loads(Path(path).read_bytes())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rebuild(root: Path, layout="artifact"):
    paths={
        "verdict":root/"data/mechanism-matrix/results/VERDICT_ONLY.json",
        "baselines":root/"data/mechanism-matrix/results/FAIR_BASELINES_TEST.json",
        "async":root/"data/transfer/async/RESULT.json",
        "confirmation":root/"data/confirmation/bidirectional-canaries/RESULT.json",
        "compilation":root/"data/ecology/contracts/COMPILATION.json",
        "admission":root/"data/ecology/structural/ADMISSION.json",
        "structural":root/"data/ecology/structural/RESULT.json",
        "risk":root/"data/ecology/risk-candidates/RESULT.json",
        "dec":root/"data/ecology/dec/RESULT.json",
        "strict":root/"data/ecology/dec/STRICT_STATISTICS.json",
        "repair":root/"data/repair/real-repositories/RESULT.json",
    } if layout == "artifact" else {
        "verdict":root/"experiments/p0-verdict-only-counterfactual-round157-n1994/VERDICT_ONLY.json",
        "baselines":root/"experiments/p0-heldout-fair-baselines-round164-n2035/RESULT.json",
        "async":root/"experiments/p0-async-mechanism-extension-round164-n2033/RESULT.json",
        "confirmation":root/"experiments/p0-bidirectional-confirmation-round164-n2032/RESULT.json",
        "compilation":root/"experiments/p0-ecological-contract-compilation-final-round163-n2024/COMPILATION.json",
        "admission":root/"experiments/p0-ecological-contract-admission-round163-n2025/ADMISSION.json",
        "structural":root/"experiments/p0-ecological-contract-structural-round163-n2027/RESULT.json",
        "risk":root/"experiments/p0-ecological-risk-candidates-round163-n2028/RESULT.json",
        "dec":root/"experiments/p0-ecological-witness-only-dec-v2-round164-n2030/RESULT.json",
        "strict":root/"experiments/p0-ecological-strict-statistics-round164-n2031/RESULT.json",
        "repair":root/"experiments/p0-real-repository-repair-closure-round164-n2036/RESULT.json",
    }
    missing=[str(path.relative_to(root)) for path in paths.values() if not path.is_file()]
    if missing:raise ValueError("missing_table_inputs:"+",".join(missing))
    values={key:read(path) for key,path in paths.items()}
    return {"schema_version":"guardcontract-final-table-data-1",
            "rq1":{"verdict_only":values["verdict"]["verdict_only_baseline"],
                   "counterfactual":values["verdict"]["counterfactual"],
                   "async_extension":values["async"]["counts"]},
            "rq2":{"heldout_arms":values["baselines"]["arms"],
                   "bidirectional_confirmation":{k:v for k,v in values["confirmation"]["heldout"].items()
                                                   if k not in {"rows","ineligible_rows"}}},
            "rq3":{"compiled_new_contracts":len(values["compilation"]["new_contracts"]),
                   "legacy_contracts":len(values["compilation"]["inherited_contracts"]),
                   "admitted_counts":values["admission"]["counts"],
                   "structural_counts":values["structural"]["counts"],
                   "risk_candidate_counts":values["risk"]["counts"],
                   "strict_counts":values["strict"]["counts"],
                   "strict_contract_metrics":values["strict"]["contract_metrics"],
                   "strict_repository_metrics":values["strict"]["repository_metrics"],
                   "repair_closure":values["repair"]["counts"]},
            "inputs":{str(path.relative_to(root)):sha(path) for path in paths.values()},
            "claim_boundary":"Table data only; controlled and ecological denominators remain separate."}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--layout",choices=("artifact","project"),default="artifact")
    parser.add_argument("--out",type=Path,required=True);args=parser.parse_args();root=args.root.resolve();out=args.out.resolve()
    if out.exists() or not out.is_relative_to(root):parser.error("output must be new under artifact root")
    value=rebuild(root,args.layout);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"rq1":list(value["rq1"]),"rq2_arms":len(value["rq2"]["heldout_arms"]),"rq3":list(value["rq3"])}))


if __name__=="__main__":main()
