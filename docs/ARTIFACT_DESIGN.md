# GuardContract Anonymous Artifact: Design and Scope

Status: completed derived-data snapshot, September 24, 2026. The collection plan is `docs/ARTIFACT_PLAN.json`; machine-readable status is `STATUS.json`. This English release document describes the frozen package. Earlier planning notes are not evidence of current results.

## Reproduction levels

R0 verifies file hashes, the manifest, and denominators. R1 rebuilds final table data from per-item outputs without calling a model or accessing the network. The package also includes inputs and environment locks for deterministic stages. It does not promise full R3 replay of commercial endpoints, mutable upstream repositories, or source code that cannot be redistributed.

The breadth census, depth screening, risk candidates, strict DEC outcomes, controlled behavior labels, and real-repository repair queue have different units and must not be pooled.

| Dataset | Unit | Frozen result |
| --- | --- | --- |
| Mechanism matrix | owned program variant | 98 behavior labels; 60 development and 38 held-out programs; baseline and ablation outputs |
| API census | repository | 745 repositories; no repository overlap with the depth frame |
| Source screening | screening unit | 695 repositories / 772 units; 517 applicable, 215 not applicable, 40 unresolved |
| Contract compilation | compilation unit | 456/456 units; 2,025 new contract hypotheses; 107 legacy contracts separate |
| Structural qualification | admitted contract | 875/875 results; 190 eligible; zero execution errors |
| Broad risk candidates | source-backed candidate | 137 candidates in 109 units, 102 repositories, and 102 candidate source-family IDs |
| Strict witness-only DEC | eligible contract | 190 `UNKNOWN`, zero VP, zero CWS; 107 legacy contracts `EXCLUDED` |
| Independent confirmation | owned held-out program | 24 bidirectionally eligible: 6 VP, 18 CWS; no eligible real-repository queue |
| Async extension | owned async case | Five cases: 3 VP, 2 CWS |
| Real-repository repair | independently confirmed real VP | Empty eligible queue; repair rate is `null` |

`MANIFEST.json` records each release path, size, SHA-256, source file, and artifact class. `SHA256SUMS` provides a direct integrity check. Data are under `data/`, scripts under `scripts/`, and dependency records under `environment/`.

```bash
sha256sum -c SHA256SUMS
python3 scripts/rebuild_guardcontract_final_tables.py \
  --root . --out tables/R1_REBUILT.json
cmp tables/FINAL_TABLES.json tables/R1_REBUILT.json
```

The distributable snapshot excludes raw provider wires, copies of third-party repositories, vulnerability-disclosure files, virtual environments, local credentials, and full environment variables. R0 and R1 do not replace license, anonymity, or venue-policy review.

## English source-text views

Thirty-seven ecological JSON files contain English derived views of source-language descriptions, contract prose, and path labels. The original frozen records are retained privately. The derived views preserve JSON structure, keys, sample IDs, labels, and numeric values; they are not byte-identical source records or independent semantic adjudication. `docs/TRANSLATION_PROVENANCE.json` lists original and derived file hashes and hashes of the original non-English paths. Source paths shown in English are display labels, not literal checkout paths. Reproduction claims for these files are limited to the published English views and aggregate R1 computation; literal original-source replay requires the original records and upstream repository checkout.
