# Anonymous Artifact Completeness Ledger

Package root: this repository. The collection design was frozen September 19, 2026. `STATUS.json` is the machine-readable status record; `docs/REMAINING_EXPERIMENTS.md` gives final experimental closure. Status words distinguish populated evidence from development-only evidence, excluded material, and an empty eligible queue. A file's presence does not by itself validate a scientific claim.

| Requirement | Release status | Location and acceptance boundary |
| --- | --- | --- |
| 98 programs and stable IDs | Populated | `data/mechanism-matrix/generation/`; queue and generation manifest identify variants |
| Real SDK behavior and ground truth | Populated | `data/mechanism-matrix/sdk/` and `ground-truth/`; five frameworks, 98 labels, zero GT unknowns |
| Frozen split | Populated | `data/mechanism-matrix/SPLIT.json`; source-family-separated 60 development / 38 test |
| Verdict-only counterfactual | Populated | `data/mechanism-matrix/results/VERDICT_ONLY.json`; 40 before/after pairs, including 20 effect flips under unchanged verdict prediction |
| Static, LLM, full, adapted syntactic comparator | Populated | `data/mechanism-matrix/results/`; distinguish development outputs from held-out scoring and preserve each adaptation's scope |
| Held-out ablations | Populated | `FAIR_BASELINES_TEST.json`; common 38-program denominator; no test-feedback tuning |
| Breadth API census | Populated | `data/ecology/api-census/`; 745 repositories, separate from depth |
| Depth screening | Populated | `data/ecology/screening/`; 772 units, zero execution errors |
| Compiled contracts | Complete | `data/ecology/contracts/`; 456/456 new units, 2,025 new hypotheses, 107 legacy separate |
| Structural qualification | Populated | `data/ecology/structural/`; 875/875 results, 190 eligible, zero execution errors |
| Broad risk candidates | Populated | `data/ecology/risk-candidates/`; 137 source-backed candidates across 109 units and 102 repositories; not DEC prevalence |
| Strict witness-only DEC | Completed with zero decided coverage | `data/ecology/dec/`; 190 eligible `UNKNOWN`, zero VP/CWS; 107 legacy `EXCLUDED` |
| Bidirectional canaries | Populated for eligible held-out cases | `data/confirmation/bidirectional-canaries/`; 24 programs, 6 VP / 18 CWS; no strict real-repository queue |
| Independent async cases | Populated | `data/transfer/async/`; 5 owned cases, 3 VP / 2 CWS |
| Controlled repair | Development evidence | `data/repair/controlled/`; five-framework feasibility, not a public-repository repair rate |
| Real-repository repair | Closed empty queue | `data/repair/real-repositories/`; no strict independently confirmed VP, so repair rate is `null` |
| Prompts and model provenance | Partial | `environment/` and `scripts/`; embedded prompts can be tied to code hashes; complete provider revision/parameters/digests may be unavailable |
| Environment locks | Populated R2 inputs | `environment/requirements/` and `environment/locks/`; eight environments recorded, without an R3 provider-replay claim |
| Per-item output and aggregation | Populated | `data/` and `scripts/rebuild_guardcontract_final_tables.py`; R1 rebuilds RQ1--RQ3 table data offline |
| Exclusion and unknown reasons | Populated | `data/ecology/`; keep eligibility, proof gaps, and execution errors separate |
| Related-work matrix | Populated with verification limits | `docs/RELATED_WORK_CAPABILITY_MATRIX.md`; unverified neighbors remain unscored |

Legacy rolling-audit data under `data/development/legacy-contracts/` are retained only for provenance and protocol migration. The historical 11 present / 8 absent, six excluded, and roughly 40% decision rate used different rules, including model-consensus releases. The former `absent` label lacked the all-path proof required for CWS. A 3/3 review of historical present cases is small development evidence, not final real-world agreement. These records must not enter final precision/recall, coverage, or prevalence.

Release verification requires agreement of `MANIFEST.json` and `SHA256SUMS`, frozen run identities, offline reconstruction of final tables, scans for local paths and credentials, license review before redistributing third-party code, and separate review before including raw provider wires. R0/R1 checks validate the included snapshot; they do not silently complete the excluded R3 or policy gates.
