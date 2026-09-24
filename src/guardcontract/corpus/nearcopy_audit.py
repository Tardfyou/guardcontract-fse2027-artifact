"""Find bounded lexical near-copy candidates in locally pinned observed files."""
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from guardcontract.paths import project_root
from collections import Counter, defaultdict
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = project_root()
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from guardcontract.corpus.nearcopy import LANGUAGES, fingerprint, similar_pairs
from guardcontract.evidence.repository_evidence import safe_path
from guardcontract.corpus.dependencies.validate_relevance_reviews import SourceVerifier


def run_pending_fingerprints(config, root):
    """Fingerprint pinned public files without persisting or exposing source text."""
    from concurrent.futures import ThreadPoolExecutor
    from urllib.parse import quote
    from urllib.request import Request, urlopen
    import re
    import subprocess
    import pygments

    if config.get("pygments_version", pygments.__version__) != pygments.__version__:
        raise ValueError("fingerprint_pygments_version_mismatch")

    transport = config.get("transport", "urllib")
    if transport not in {"urllib", "curl"}:
        raise ValueError("fingerprint_transport")

    inputs = {}
    def read(path):
        raw = safe_path(root, path).read_bytes()
        inputs[path] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)
    pending = read(config["pending_ledger"])
    baseline = read(config["baseline_fingerprints"])
    policy = read(config["fingerprint_policy"])
    if baseline["config_sha256"] != inputs[config["fingerprint_policy"]]:
        raise ValueError("baseline_fingerprint_policy_mismatch")
    tasks = {}
    for row in pending["pending_representatives"]:
        name, commit = row["full_name"], row["pinned_commit"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name) or not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError("pending_source_identity")
        for loc in row["matched_files"]:
            path, blob = loc["path"], loc["blob_sha"]
            if not path or path.startswith("/") or any(p in {"", ".", ".."} for p in path.split("/")) or not re.fullmatch(r"[0-9a-f]{40}", blob):
                raise ValueError("pending_source_location")
            key = (name, commit, path)
            if key in tasks and tasks[key] != blob:
                raise ValueError("conflicting_pending_blob")
            tasks[key] = blob
    if len(tasks) != config["expected_unique_files"]:
        raise ValueError("pending_file_inventory")

    def fetch(key):
        name, commit, path = key
        item = {"repository": name, "commit": commit, "path": path, "expected_git_blob": tasks[key]}
        language = LANGUAGES.get(path.rsplit(".", 1)[-1])
        if language is None:
            return {**item, "status": "unsupported_language"}
        try:
            url = "https://raw.githubusercontent.com/" + quote(name, safe="/") + "/" + commit + "/" + quote(path, safe="/")
            if transport == "curl":
                raw = subprocess.run(["curl", "--silent", "--show-error", "--fail", "--location",
                    "--proto", "=https", "--proto-redir", "=https", "--max-time", "30",
                    "--max-filesize", str(policy["max_file_bytes"]), url],
                    capture_output=True, check=True, timeout=35).stdout
            else:
                request = Request(url, headers={"User-Agent": "GuardContract-source-fingerprint-audit"})
                with urlopen(request, timeout=30) as response:
                    raw = response.read(policy["max_file_bytes"] + 1)
            if len(raw) > policy["max_file_bytes"]:
                return {**item, "status": "byte_budget_exceeded"}
            blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            item.update(source_file_sha256=hashlib.sha256(raw).hexdigest(), observed_git_blob=blob, bytes=len(raw))
            if blob != tasks[key]:
                return {**item, "status": "pinned_commit_blob_mismatch"}
            fp = fingerprint(raw.decode("utf-8-sig"), language, policy["max_tokens"])
            item.update({key: value for key, value in fp.items() if key != "shingles"})
            if config.get("compare_shingles"):
                item["_shingles"] = fp["shingles"]
            return {**item, "language": language, "status": "fingerprinted"}
        except Exception as exc:
            return {**item, "status": "unavailable", "error_kind": type(exc).__name__}

    records = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        for row in pool.map(fetch, sorted(tasks)):
            records.append(row)
            if len(records) % 25 == 0:
                print(json.dumps({"fingerprinted_or_error_files": len(records), "planned": len(tasks)}), flush=True)
    buckets = defaultdict(list)
    def eligible(row):
        return row.get("status") == "fingerprinted" and row["tokens"] >= policy["min_tokens"]
    for row in baseline["files"]:
        if eligible(row):
            buckets[(row["language"], row["identifier_normalized_sha256"])].append(row)
    pairs = []
    for row in records:
        if not eligible(row):
            continue
        key = (row["language"], row["identifier_normalized_sha256"])
        for other in buckets[key]:
            if other["repository"] == row["repository"]:
                continue
            pairs.append({"left_repository": other["repository"], "left_path": other["path"],
                          "right_repository": row["repository"], "right_path": row["path"],
                          "kind": "literal_tokens_equal" if other["literal_token_sha256"] == row["literal_token_sha256"] else "identifier_normalized_tokens_equal",
                          "review_status": "candidate_unreviewed"})
        buckets[key].append(row)
    shingle_audit = None
    if config.get("compare_shingles"):
        verifier = SourceVerifier(root, [read(path) for path in policy["materializations"]])
        comparison_files, shingle_sets, cache, baseline_status = {}, defaultdict(dict), {}, Counter()
        for index, row in enumerate(records):
            shingles = row.pop("_shingles", None)
            if eligible(row) and shingles is not None:
                key = "pending:" + str(index)
                shingle_sets[row["language"]][key] = shingles
                comparison_files[key] = row
        unavailable_baseline = []
        for index, row in enumerate(baseline["files"]):
            if row.get("status") != "fingerprinted":
                baseline_status["previously_unavailable"] += 1
                continue
            try:
                _, meta = verifier.source(row, row["path"])
                if meta["file_sha256"] != row["source_file_sha256"]:
                    raise ValueError("baseline_source_hash_changed")
                cache_key = (row["language"], row["source_file_sha256"])
                if cache_key not in cache:
                    raw = safe_path(safe_path(root, meta["destination"]), row["path"]).read_bytes()
                    if len(raw) > policy["max_file_bytes"] or hashlib.sha256(raw).hexdigest() != row["source_file_sha256"]:
                        raise ValueError("baseline_source_hash_or_size")
                    cache[cache_key] = fingerprint(raw.decode("utf-8-sig"), row["language"], policy["max_tokens"])
                fp = cache[cache_key]
                if any(fp[field] != row[field] for field in ("tokens", "literal_token_sha256", "identifier_normalized_sha256")):
                    raise ValueError("baseline_fingerprint_changed")
                baseline_status["revalidated"] += 1
                if fp["tokens"] >= policy["min_tokens"]:
                    key = "baseline:" + str(index)
                    shingle_sets[row["language"]][key] = fp["shingles"]
                    comparison_files[key] = row
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
                baseline_status["unavailable"] += 1
                unavailable_baseline.append({"file_id": row["file_id"], "error_kind": type(exc).__name__,
                                             "reason": str(exc)[:200]})
            finally:
                verifier.files.clear()
            if (index + 1) % 500 == 0:
                print(json.dumps({"baseline_files_processed": index + 1, "planned": len(baseline["files"])}), flush=True)
        comparisons, shingle_pairs = {}, []
        for language, entries in sorted(shingle_sets.items()):
            compared = similar_pairs(entries, pair_budget=policy["pair_budget_per_language"], min_shingles=policy["min_shingles"])
            comparisons[language] = {k: v for k, v in compared.items() if k != "pairs"}
            for pair in compared["pairs"]:
                if not any(pair[key].startswith("pending:") for key in ("left", "right")):
                    continue
                left, right = (comparison_files[pair[key]] for key in ("left", "right"))
                if left["repository"] == right["repository"]:
                    continue
                shingle_pairs.append({**pair, "left_repository": left["repository"], "left_path": left["path"],
                                      "right_repository": right["repository"], "right_path": right["path"],
                                      "review_status": "candidate_unreviewed"})
        shingle_audit = {"baseline_status": dict(baseline_status), "unavailable_baseline": unavailable_baseline,
                         "comparison_by_language": comparisons, "pairs_involving_pending": shingle_pairs,
                         "threshold": "identifier-normalized 5-token set Jaccard >= 0.90",
                         "baseline_below_min_tokens": baseline["counts"]["below_min_tokens"],
                         "below_min_shingles": sum(len(s) < policy["min_shingles"] for bucket in shingle_sets.values() for s in bucket.values()),
                         "source_content_persisted": False}
    return {"schema_version": "pending-normalized-fingerprint-audit-1", "files": records, "pairs": pairs,
            "shingle_audit": shingle_audit,
            "execution_health": "completed" if all(r["status"] == "fingerprinted" for r in records) else "partial",
            "inputs_sha256": inputs, "counts": {"planned_files": len(tasks), "file_status": dict(Counter(r["status"] for r in records)),
            "below_min_tokens": sum(r.get("status") == "fingerprinted" and r["tokens"] < policy["min_tokens"] for r in records),
            "cross_repository_equal_fingerprint_pairs": len(pairs)},
            "source_content_persisted": False, "source_content_returned_to_model": False,
            "transport": transport, "prior_incomplete_attempt": config.get("prior_incomplete_attempt"),
            "pygments_version": pygments.__version__, "python_version": sys.version.split()[0],
            "repository_code_executed": False, "holdout_admission_authorized": False, "nearcopy_complete": False,
            "claim_boundary": "Fixed-policy lexical candidates against prior fingerprinted files and within the pending pool. Shingle comparison is present only when shingle_audit is populated. Below-threshold and small-file copies remain uncovered. Similarity is not semantic equivalence or proof of development exposure. Missing files and blob mismatches remain unresolved."}


def run(config, root):
    inputs = {}
    def read(path):
        raw = safe_path(root, path).read_bytes(); inputs[path] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)
    evidence, family = read(config["evidence"]), read(config["exact_family_audit"])
    if family["inputs_sha256"].get(config["evidence"]) != inputs[config["evidence"]]:
        raise ValueError("family_evidence_lineage_mismatch")
    verifier = SourceVerifier(root, [read(p) for p in config["materializations"]])
    by_file = defaultdict(list)
    for row in evidence["records"]:
        if row["integrity"]["status"] == "verified":
            by_file[(row["repository"], row["commit"], row["tree"], row["path"])].append(row)
    ordered = sorted(by_file)
    if len(ordered) != config["expected_files"]: raise ValueError("file_count_mismatch")
    if config.get("file_limit") is not None:
        if type(config["file_limit"]) is not int or config["file_limit"] <= 0: raise ValueError("invalid_file_limit")
        ordered = ordered[:config["file_limit"]]
    records, fingerprints, cache = [], {}, {}
    started = time.perf_counter()
    for index, key in enumerate(ordered):
        row = by_file[key][0]
        file_id = "file:" + hashlib.sha256(json.dumps(key).encode()).hexdigest()
        item = {"file_id": file_id, "repository": key[0], "commit": key[1], "tree": key[2], "path": key[3],
                "source_file_sha256": row["integrity"]["file_sha256"], "source_record_ids": sorted(r["source_record_id"] for r in by_file[key])}
        try:
            language = LANGUAGES.get(key[3].rsplit(".", 1)[-1])
            if language is None: raise ValueError("unsupported_lexer")
            _, meta = verifier.source(row, key[3])
            raw = safe_path(safe_path(root, meta["destination"]), key[3]).read_bytes()
            if len(raw) > config["max_file_bytes"]: raise ValueError("byte_budget_exceeded")
            if hashlib.sha256(raw).hexdigest() != item["source_file_sha256"] or any(r["integrity"]["file_sha256"] != item["source_file_sha256"] for r in by_file[key]):
                raise ValueError("frozen_hash_mismatch")
            cache_key = (language, item["source_file_sha256"])
            if cache_key not in cache:
                cache[cache_key] = fingerprint(raw.decode("utf-8-sig"), language, config["max_tokens"])
            fp = cache[cache_key]
            item.update(status="fingerprinted", language=language, tokens=fp["tokens"], unique_shingles=len(fp["shingles"]),
                        literal_token_sha256=fp["literal_token_sha256"], identifier_normalized_sha256=fp["identifier_normalized_sha256"])
            fingerprints[file_id] = fp
        except (OSError, ValueError, TypeError, KeyError, IndexError, UnicodeError, RecursionError) as exc:
            item.update(status="unavailable", error_kind=type(exc).__name__, reason=str(exc)[:200])
        records.append(item); verifier.files.clear()
        if (index + 1) % 500 == 0: print(json.dumps({"fingerprinted_or_error_files": index + 1, "planned": len(ordered)}), flush=True)
    lookup = {r["file_id"]: r for r in records}
    buckets = defaultdict(dict)
    for row in records:
        if row["status"] == "fingerprinted" and row["tokens"] >= config["min_tokens"]:
            buckets[row["language"]][row["file_id"]] = fingerprints[row["file_id"]]["shingles"]
    comparisons, pairs = {}, []
    for language, entries in sorted(buckets.items()):
        result = similar_pairs(entries, pair_budget=config["pair_budget_per_language"], min_shingles=config["min_shingles"])
        comparisons[language] = {k: v for k, v in result.items() if k != "pairs"}
        for pair in result["pairs"]:
            left, right = lookup[pair["left"]], lookup[pair["right"]]
            if left["repository"] == right["repository"]: continue
            if left["source_file_sha256"] == right["source_file_sha256"]: continue
            kind = "tokens_equal_ignoring_format_comments" if left["literal_token_sha256"] == right["literal_token_sha256"] else "identifier_normalized_tokens_equal" if left["identifier_normalized_sha256"] == right["identifier_normalized_sha256"] else "identifier_normalized_shingle_similarity"
            pairs.append({**pair, "language": language, "kind": kind, "left_repository": left["repository"], "right_repository": right["repository"], "review_status": "candidate_unreviewed"})
    adjacent = defaultdict(set); previously_exposed = set()
    for component in family["components"]:
        names = component["repositories"]
        for name in names:
            adjacent[names[0]].add(name); adjacent[name].add(names[0])
        if component["status"] == "exclude_known_exposure": previously_exposed.update(names)
    for pair in pairs:
        a, b = pair["left_repository"], pair["right_repository"]
        adjacent[a].add(b); adjacent[b].add(a)
    reached, todo = set(), list(previously_exposed)
    while todo:
        repo = todo.pop()
        if repo in reached: continue
        reached.add(repo); todo.extend(adjacent[repo] - reached)
    extra = sorted(reached - previously_exposed)
    complete = len(ordered) == len(by_file) and all(r["status"] == "fingerprinted" for r in records) and all(x["candidate_generation_complete"] for x in comparisons.values())
    return {"task_version": "164-1", "execution_health": "completed" if complete else "partial", "scientific_outcome": "unscored",
            "counts": {"expected_files": len(by_file), "attempted_files": len(records), "fingerprinted_files": len(fingerprints),
                       "unavailable_files": sum(r["status"] == "unavailable" for r in records), "unique_fingerprint_computations": len(cache),
                       "below_min_tokens": sum(r["status"] == "fingerprinted" and r["tokens"] < config["min_tokens"] for r in records),
                       "below_min_shingles_after_token_gate": sum(r["status"] == "fingerprinted" and r["tokens"] >= config["min_tokens"] and r["unique_shingles"] < config["min_shingles"] for r in records),
                       "new_cross_repository_similarity_pairs": len(pairs), "additional_potential_exposure_repositories": len(extra)},
            "comparison_by_language": comparisons, "pair_kinds": dict(Counter(p["kind"] for p in pairs)),
            "files": records, "pairs": pairs, "potential_exposure_review_queue": extra, "inputs_sha256": inputs,
            "unverified_input_record_ids": [r["source_record_id"] for r in evidence["records"] if r["integrity"]["status"] != "verified"],
            "duration_seconds": time.perf_counter() - started, "holdout_admission_authorized": False,
            "claim_boundary": "Candidate lexical similarity only, based on observed files and fixed thresholds. Renaming normalization can merge unrelated code; small files and below-threshold copies remain uncovered. No label propagation, semantic family assertion, independent gold, precision/recall or saturation claim."}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, required=True); p.add_argument("--result", type=Path, required=True)
    a = p.parse_args(); raw = a.config.read_bytes()
    config = json.loads(raw)
    if config.get("mode") == "pending_normalized_fingerprints":
        result = run_pending_fingerprints(config, Path.cwd())
        result["implementation_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        result["fingerprint_implementation_sha256"] = hashlib.sha256((Path(__file__).parent / "nearcopy.py").read_bytes()).hexdigest()
    else:
        result = run(config, Path.cwd())
    result["config_sha256"] = hashlib.sha256(raw).hexdigest()
    with a.result.open("x") as output:
        json.dump(result, output, ensure_ascii=False, indent=2, sort_keys=True); output.write("\n")
    print(json.dumps(result["counts"]))
    return 2 if result.get("execution_health") == "partial" else 0


if __name__ == "__main__": raise SystemExit(main())
