# GuardContract Ecological Measurement Protocol

Design frozen September 19, 2026; scope amended September 22. This protocol predates final results. The amendments did not change strict DEC labels, denominators, or prevalence-bound formulas. They added the descriptive `DEC-RISK-CANDIDATE` tier and retained the independent async mechanism extension. A separate fresh confirmatory set and sixth-framework transfer experiment were canceled. The previously frozen, development-unseen test split was revealed once.

## Sampling frames and units

The 745-repository API census describes guard API use across 23 ecosystems, framework distribution, and prominence. It cannot establish operation-level contracts or DEC prevalence. The 695-repository / 772-unit source-screening frame supports deeper contract recovery and DEC analysis. The frames have no repository overlap and cannot be combined into one denominator. Ecological conclusions are limited to the fixed, guard-enriched, five-framework depth frame, rather than all GitHub or agent applications. Historical 75-unit and newer GLM screening groups have distinct admission protocols and require `protocol_group` stratification.

Report each funnel level separately: case-normalized repository identity; frozen candidate source family (not proof of independent implementation lineage); 772 stable screening-unit IDs; compiled contracts deduplicated by repository commit, agent mediation, effect stratum, and guard/commit source identity; mechanically eligible contracts; four-state DEC outcome; and independent behavior labels obtained after prediction freeze. At each level retain planned, completed, eligible, excluded, unknown/error, and reasons. A model's `applicable` judgment creates a candidate, not mechanical eligibility.

## Broad risk candidates

`DEC-RISK-CANDIDATE` is a descriptive, source-backed triage category between structural qualification and strict witness-only DEC. It is not a vulnerability, confirmed violation, safety label, prevalence estimate, or precision/recall result. A candidate requires (1) a source-identifiable, agent-mediated protected operation or commit, (2) source evidence of guard registration or a forbidden condition, and (3) at least one located risk signal: a post-commit or ambiguous guard order; unresolved or mismatched request/resource/tool/attempt binding; unestablished coverage of an indirect, async, exceptional, or alternate commit path; or a source-bounded joint-reachability candidate without a mechanical witness. Absence of a CWS proof alone is insufficient. Generic unsupported cases, environment failures, and application guards without agent mediation do not qualify.

Each record must retain contract and sample IDs, repository, candidate source family, framework, effect stratum, agent mediation, risk reason codes, evidence, protocol group, and execution health. Report candidate counts by contract/item, screening unit (denominator 772), repository (denominator 695), candidate family ID, per-repository distribution, and predeclared strata. Do not silently turn these candidates into VP/CWS labels.

## Strict outcomes and denominators

The primary DEC denominator is mechanically eligible contracts. `EXCLUDED` and execution errors are reported separately, never as negatives. Retain `UNKNOWN` in coverage and bounds:

```text
decision coverage       = (VP + CWS) / (VP + CWS + UNKNOWN)
confirmed lower bound   = VP / (VP + CWS + UNKNOWN)
possible-positive upper = (VP + UNKNOWN) / (VP + CWS + UNKNOWN)
decided-set fraction    = VP / (VP + CWS), if defined
```

Repository lower and upper bounds respectively count repositories with at least one VP, and repositories with a VP or UNKNOWN, over repositories with a mechanically eligible contract. Contract duplicates do not count as independent repository replications; a candidate family name does not establish independent lineage. These bounds are identification bounds for the fixed frame, not sampling confidence intervals.

Precision/recall, selective accuracy, and risk-coverage require independent behavior labels. Model agreement, valid source quotations, AST order, or two reviewers' agreement are not gold labels. Keep development feedback and previously viewed records out of held-out evaluation. Where execution is feasible, bidirectional inert-canary confirmation checks both no protected commit under DENY and preserved function under ALLOW. Distinct inclusion probabilities require design weights; otherwise report conditional accuracy only for the labeled subset. For cells smaller than ten, show raw counts and uncertainty rather than an unstable percentage.

Predeclared strata are framework, effect stratum, agent mediation, protocol group, and repository prominence. Report the lowest decision-coverage cell among those with at least ten mechanically eligible contracts; report the highest selective-error cell only when it has at least ten independent behavior labels. Otherwise mark `insufficient_n`. A complete observed frame needs no invented sampling interval. If estimating confirmation-sample uncertainty, cluster by repository, preserve frozen strata, run 10,000 design-consistent resamples with seed `guardcontract-20260919`, and report effective repository and contract counts plus missing labels.

The controlled 98-program matrix supports mechanism and behavior-ground-truth results, not real-repository prevalence. Compare verdict-only, static-only, LLM-only, full, and frozen ablations on their stated common tasks; a real-repository baseline must receive the same contracts and evidence budget without leakage from full-method verification. Report static time, model calls, known tokens, unknown-usage calls, retries, environment setup, behavioral-oracle effort, and human review time. Provider, decoder, sandbox, grader, or harness failures are execution errors, not scientific negatives or ordinary `UNKNOWN` outcomes.
