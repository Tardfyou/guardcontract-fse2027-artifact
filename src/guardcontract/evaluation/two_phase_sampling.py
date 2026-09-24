"""Pre-register a two-phase behavior screening and confirmation sample.

Phase one retains the complete frozen frame. Phase two uses deterministic
stratified sampling with explicit inclusion probabilities; labels are never
read or generated here.
"""
import hashlib
import json


def _key(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def freeze(rows, *, seed, strata_fields=("framework", "lifecycle", "prediction"),
           target_per_stratum=5):
    if not isinstance(seed, str) or not seed:
        raise ValueError("sampling_seed_required")
    if type(target_per_stratum) is not int or target_per_stratum < 1:
        raise ValueError("sampling_target_required")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("sampling_rows_required")
    identities = [row.get("sample_id") or row.get("repository") for row in rows]
    if any(not isinstance(identity, str) or not identity for identity in identities):
        raise ValueError("sampling_identity_required")
    if len(set(identities)) != len(identities):
        raise ValueError("sampling_duplicate_identity")
    buckets = {}
    for row, identity in zip(rows, identities):
        values = []
        for field in strata_fields:
            value = row.get(field)
            values.append(value if value is not None else "unknown")
        stratum = _key(values)
        buckets.setdefault(stratum, []).append((identity, row))
    census = []
    selected = []
    for stratum in sorted(buckets):
        bucket = buckets[stratum]
        ordered = sorted(bucket, key=lambda item: hashlib.sha256(
            f"{seed}\0{stratum}\0{item[0]}".encode("utf-8")).hexdigest())
        take = min(target_per_stratum, len(ordered))
        probability = take / len(ordered)
        for identity, row in bucket:
            census.append({"sample_id": identity, "stratum": stratum,
                           "phase": "screening_census", "behavior_label": None})
        for identity, row in ordered[:take]:
            selected.append({"sample_id": identity, "stratum": stratum,
                             "phase": "confirmation_oracle", "inclusion_probability": probability,
                             "prediction": row.get("prediction"), "behavior_label": None})
    return {
        "schema_version": "two-phase-sampling-freeze-1",
        "seed": seed,
        "strata_fields": list(strata_fields),
        "target_per_stratum": target_per_stratum,
        "screening_census": sorted(census, key=lambda row: row["sample_id"]),
        "confirmation_sample": sorted(selected, key=lambda row: row["sample_id"]),
        "counts": {"screening_census": len(census), "confirmation_sample": len(selected),
                   "strata": len(buckets)},
        "labels_read": False,
        "holdout_admission_authorized": False,
        "claim_boundary": "Sampling freeze only; no behavior labels, prevalence, precision or recall claim.",
    }


def freeze_clustered(rows, *, seed, cluster_field="source_family",
                     strata_fields=("framework", "lifecycle"),
                     target_clusters_per_stratum=10, rows_per_prediction=1):
    """Freeze two-stage family-first sampling with exact row probabilities."""
    if not isinstance(seed, str) or not seed:
        raise ValueError("sampling_seed_required")
    if (type(target_clusters_per_stratum) is not int or target_clusters_per_stratum < 1
            or type(rows_per_prediction) is not int or rows_per_prediction < 1):
        raise ValueError("clustered_sampling_targets")
    if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
        raise ValueError("sampling_rows_required")
    identities = [row.get("sample_id") for row in rows]
    if any(not isinstance(identity, str) or not identity for identity in identities):
        raise ValueError("sampling_identity_required")
    if len(set(identities)) != len(identities):
        raise ValueError("sampling_duplicate_identity")
    clusters = {}
    for row in rows:
        cluster = row.get(cluster_field)
        prediction = row.get("prediction")
        if not isinstance(cluster, str) or not cluster:
            raise ValueError("sampling_cluster_identity")
        if prediction not in {"present", "absent", "unknown"}:
            raise ValueError("sampling_prediction")
        clusters.setdefault(cluster, []).append(row)

    cluster_strata = {}
    for cluster, members in clusters.items():
        values = []
        for field in strata_fields:
            observed = {row.get(field, "unknown") for row in members}
            values.append(next(iter(observed)) if len(observed) == 1 else "mixed")
        cluster_strata[cluster] = _key(values)
    buckets = {}
    for cluster, stratum in cluster_strata.items():
        buckets.setdefault(stratum, []).append(cluster)

    selected_clusters = []
    confirmation = []
    allocation = []
    for stratum in sorted(buckets):
        population = sorted(buckets[stratum])
        ranked = sorted(population, key=lambda cluster: hashlib.sha256(
            f"{seed}\0cluster\0{stratum}\0{cluster}".encode()).hexdigest())
        take = min(target_clusters_per_stratum, len(ranked))
        cluster_probability = take / len(ranked)
        chosen = ranked[:take]
        selected_clusters.extend({"source_family": cluster, "stratum": stratum,
                                  "cluster_inclusion_probability": cluster_probability}
                                 for cluster in chosen)
        allocation.append({"stratum": stratum, "cluster_population": len(ranked),
                           "clusters_selected": take,
                           "cluster_inclusion_probability": cluster_probability})
        for cluster in chosen:
            by_prediction = {}
            for row in clusters[cluster]:
                by_prediction.setdefault(row["prediction"], []).append(row)
            for prediction in sorted(by_prediction):
                candidates = sorted(by_prediction[prediction], key=lambda row: hashlib.sha256(
                    f"{seed}\0row\0{cluster}\0{prediction}\0{row['sample_id']}".encode()).hexdigest())
                row_take = min(rows_per_prediction, len(candidates))
                conditional_probability = row_take / len(candidates)
                for row in candidates[:row_take]:
                    confirmation.append({"sample_id": row["sample_id"],
                        "source_family": cluster, "stratum": stratum,
                        "prediction": prediction, "phase": "confirmation_oracle",
                        "cluster_inclusion_probability": cluster_probability,
                        "within_cluster_inclusion_probability": conditional_probability,
                        "inclusion_probability": cluster_probability * conditional_probability,
                        "behavior_label": None})
    census = [{"sample_id": row["sample_id"], "source_family": row[cluster_field],
               "stratum": cluster_strata[row[cluster_field]], "prediction": row["prediction"],
               "phase": "screening_census", "behavior_label": None}
              for row in rows]
    return {"schema_version": "clustered-two-phase-sampling-freeze-1",
            "seed": seed, "cluster_field": cluster_field,
            "strata_fields": list(strata_fields),
            "target_clusters_per_stratum": target_clusters_per_stratum,
            "rows_per_prediction": rows_per_prediction,
            "screening_census": sorted(census, key=lambda row: row["sample_id"]),
            "cluster_allocation": allocation,
            "selected_clusters": sorted(selected_clusters, key=lambda row: row["source_family"]),
            "confirmation_sample": sorted(confirmation, key=lambda row: row["sample_id"]),
            "counts": {"screening_census": len(census), "source_families": len(clusters),
                       "strata": len(buckets), "selected_families": len(selected_clusters),
                       "confirmation_sample": len(confirmation),
                       "selected_present": sum(row["prediction"] == "present" for row in confirmation),
                       "selected_absent": sum(row["prediction"] == "absent" for row in confirmation),
                       "selected_unknown": sum(row["prediction"] == "unknown" for row in confirmation)},
            "labels_read": False, "holdout_admission_authorized": False,
            "claim_boundary": "Family-first two-stage sampling freeze. Inclusion probabilities combine cluster and within-family prediction-stratum selection; no labels or outcome-driven selection are used."}


def freeze_multiarm_clustered(rows, *, seed, arms, cluster_field="source_family",
                              strata_fields=("framework", "lifecycle"),
                              target_clusters_per_stratum=30,
                              rows_per_prediction_vector=1):
    """Family-first sampling that preserves prediction classes across all arms."""
    if not isinstance(seed, str) or not seed or not isinstance(arms, (list, tuple)) or not arms:
        raise ValueError("multiarm_sampling_configuration")
    if len(set(arms)) != len(arms) or any(not isinstance(arm, str) or not arm for arm in arms):
        raise ValueError("multiarm_sampling_arms")
    if (type(target_clusters_per_stratum) is not int or target_clusters_per_stratum < 1
            or type(rows_per_prediction_vector) is not int or rows_per_prediction_vector < 1):
        raise ValueError("multiarm_sampling_targets")
    if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
        raise ValueError("sampling_rows_required")
    identities = [row.get("sample_id") for row in rows]
    if any(not isinstance(identity, str) or not identity for identity in identities):
        raise ValueError("sampling_identity_required")
    if len(set(identities)) != len(identities):
        raise ValueError("sampling_duplicate_identity")
    clusters = {}
    for row in rows:
        cluster = row.get(cluster_field)
        predictions = row.get("predictions")
        if not isinstance(cluster, str) or not cluster or not isinstance(predictions, dict):
            raise ValueError("multiarm_sampling_row")
        if set(predictions) != set(arms) or any(
                predictions[arm] not in {"present", "absent", "unknown"} for arm in arms):
            raise ValueError("multiarm_sampling_predictions")
        clusters.setdefault(cluster, []).append(row)
    cluster_strata = {}
    for cluster, members in clusters.items():
        values = []
        for field in strata_fields:
            observed = {row.get(field, "unknown") for row in members}
            values.append(next(iter(observed)) if len(observed) == 1 else "mixed")
        cluster_strata[cluster] = _key(values)
    buckets = {}
    for cluster, stratum in cluster_strata.items():
        buckets.setdefault(stratum, []).append(cluster)
    selected_clusters, allocation, confirmation = [], [], []
    for stratum in sorted(buckets):
        population = sorted(buckets[stratum])
        ranked = sorted(population, key=lambda cluster: hashlib.sha256(
            f"{seed}\0cluster\0{stratum}\0{cluster}".encode()).hexdigest())
        take = min(target_clusters_per_stratum, len(ranked))
        cluster_probability = take / len(ranked)
        chosen = ranked[:take]
        allocation.append({"stratum": stratum, "cluster_population": len(ranked),
                           "clusters_selected": take,
                           "cluster_inclusion_probability": cluster_probability})
        selected_clusters.extend({"source_family": cluster, "stratum": stratum,
                                  "cluster_inclusion_probability": cluster_probability}
                                 for cluster in chosen)
        for cluster in chosen:
            vectors = {}
            for row in clusters[cluster]:
                vector = _key([row["predictions"][arm] for arm in arms])
                vectors.setdefault(vector, []).append(row)
            for vector in sorted(vectors):
                candidates = sorted(vectors[vector], key=lambda row: hashlib.sha256(
                    f"{seed}\0row\0{cluster}\0{vector}\0{row['sample_id']}".encode()).hexdigest())
                row_take = min(rows_per_prediction_vector, len(candidates))
                conditional_probability = row_take / len(candidates)
                for row in candidates[:row_take]:
                    confirmation.append({"sample_id": row["sample_id"],
                        "source_family": cluster, "stratum": stratum,
                        "prediction_vector": dict(row["predictions"]),
                        "phase": "confirmation_oracle",
                        "cluster_inclusion_probability": cluster_probability,
                        "within_cluster_inclusion_probability": conditional_probability,
                        "inclusion_probability": cluster_probability * conditional_probability,
                        "behavior_label": None})
    census = [{"sample_id": row["sample_id"], "source_family": row[cluster_field],
               "stratum": cluster_strata[row[cluster_field]],
               "prediction_vector": dict(row["predictions"]),
               "phase": "screening_census", "behavior_label": None} for row in rows]
    return {"schema_version": "multiarm-clustered-two-phase-sampling-freeze-1",
            "seed": seed, "arms": list(arms), "cluster_field": cluster_field,
            "strata_fields": list(strata_fields),
            "target_clusters_per_stratum": target_clusters_per_stratum,
            "rows_per_prediction_vector": rows_per_prediction_vector,
            "screening_census": sorted(census, key=lambda row: row["sample_id"]),
            "cluster_allocation": allocation,
            "selected_clusters": sorted(selected_clusters, key=lambda row: row["source_family"]),
            "confirmation_sample": sorted(confirmation, key=lambda row: row["sample_id"]),
            "counts": {"screening_census": len(census), "source_families": len(clusters),
                       "strata": len(buckets), "selected_families": len(selected_clusters),
                       "confirmation_sample": len(confirmation),
                       "prediction_vectors": len({_key(list(row["prediction_vector"].values()))
                                                  for row in confirmation})},
            "labels_read": False, "holdout_admission_authorized": False,
            "claim_boundary": "Family-first multi-arm prediction-vector sampling with exact inclusion probabilities. No behavior labels or outcome-driven selection are used."}
