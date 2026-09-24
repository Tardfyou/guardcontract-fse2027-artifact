"""Design-based metrics for stratified confirmation samples."""
import math
import random


def _wilson(numerator, denominator, weight_square_sum):
    if not denominator or not weight_square_sum:
        return None
    value = numerator / denominator
    effective_n = denominator * denominator / weight_square_sum
    z = 1.96
    scale = 1 + z * z / effective_n
    center = (value + z * z / (2 * effective_n)) / scale
    margin = z * math.sqrt(value * (1 - value) / effective_n
                           + z * z / (4 * effective_n * effective_n)) / scale
    return {"lower": max(0.0, min(value, center - margin)),
            "upper": min(1.0, max(value, center + margin)),
            "effective_n": effective_n}


def weighted_metrics(rows):
    if not isinstance(rows, list) or not rows:
        raise ValueError("confirmation_rows_required")
    weighted = {"tp": 0.0, "fp": 0.0, "fn": 0.0, "known": 0.0, "total": 0.0,
                "known_w2": 0.0, "total_w2": 0.0, "predicted_positive_w2": 0.0,
                "actual_positive_w2": 0.0}
    by_stratum = {}
    for row in rows:
        probability = row.get("inclusion_probability")
        prediction = row.get("prediction")
        truth = row.get("behavior_label")
        if not isinstance(probability, (int, float)) or not 0 < probability <= 1:
            raise ValueError("confirmation_inclusion_probability")
        if prediction not in {"present", "absent", "unknown"}:
            raise ValueError("confirmation_prediction")
        if truth not in {"present", "absent", "unknown", None}:
            raise ValueError("confirmation_behavior_label")
        stratum = str(row.get("stratum", "unknown"))
        bucket = by_stratum.setdefault(stratum, {"tp": 0.0, "fp": 0.0, "fn": 0.0, "known": 0.0, "total": 0.0,
                                                 "known_w2": 0.0, "total_w2": 0.0,
                                                 "predicted_positive_w2": 0.0, "actual_positive_w2": 0.0})
        weight = 1.0 / probability
        weighted["total"] += weight
        weighted["total_w2"] += weight * weight
        bucket["total"] += weight
        bucket["total_w2"] += weight * weight
        if truth is None or truth == "unknown":
            continue
        weighted["known"] += weight
        weighted["known_w2"] += weight * weight
        bucket["known"] += weight
        bucket["known_w2"] += weight * weight
        if prediction == "present":
            weighted["predicted_positive_w2"] += weight * weight
            bucket["predicted_positive_w2"] += weight * weight
        if truth == "present":
            weighted["actual_positive_w2"] += weight * weight
            bucket["actual_positive_w2"] += weight * weight
        if prediction == "present" and truth == "present":
            weighted["tp"] += weight; bucket["tp"] += weight
        elif prediction == "present" and truth == "absent":
            weighted["fp"] += weight; bucket["fp"] += weight
        elif prediction in {"absent", "unknown"} and truth == "present":
            weighted["fn"] += weight; bucket["fn"] += weight

    def rates(cell):
        positive_predictions = cell["tp"] + cell["fp"]
        positives = cell["tp"] + cell["fn"]
        precision = cell["tp"] / positive_predictions if positive_predictions else None
        recall = cell["tp"] / positives if positives else None
        coverage = cell["known"] / cell["total"] if cell["total"] else None
        return {
            "precision": precision,
            "precision_interval": _wilson( cell["tp"], positive_predictions, cell["predicted_positive_w2"]),
            "recall": recall,
            "recall_interval": _wilson(cell["tp"], positives, cell["actual_positive_w2"]),
            "coverage": coverage,
            "coverage_interval": _wilson(cell["known"], cell["total"], cell["total_w2"]),
            "weighted_known": cell["known"],
            "weighted_total": cell["total"],
        }

    return {"overall": rates(weighted),
            "by_stratum": {key: rates(value) for key, value in sorted(by_stratum.items())},
            "interval_method": "Wilson interval with effective-n approximation; design/cluster uncertainty requires a later bootstrap or survey estimator.",
            "claim_boundary": "Inverse-probability weighted confirmation arithmetic only; an unknown prediction on a confirmed positive counts as a recall miss. Source independence and label correctness must be authenticated separately."}


def cluster_bootstrap(rows, *, cluster_field="repository", iterations=1000, seed="guardcontract-bootstrap-v1"):
    """Estimate weighted metric uncertainty by resampling whole clusters.

    This keeps repository/family dependence together. Rows with missing cluster
    identity are rejected instead of silently treated as independent samples.
    """
    if type(iterations) is not int or iterations < 100:
        raise ValueError("bootstrap_iterations")
    clusters = {}
    for row in rows:
        cluster = row.get(cluster_field) or row.get("source_family")
        if not isinstance(cluster, str) or not cluster:
            raise ValueError("bootstrap_cluster_identity")
        clusters.setdefault(cluster, []).append(row)
    if len(clusters) < 2:
        raise ValueError("bootstrap_clusters_required")
    rng = random.Random(seed)
    names = sorted(clusters)
    samples = {"precision": [], "recall": [], "coverage": []}
    for _ in range(iterations):
        chosen = [names[rng.randrange(len(names))] for _ in names]
        resampled = [row for name in chosen for row in clusters[name]]
        metrics = weighted_metrics(resampled)["overall"]
        for field in samples:
            value = metrics[field]
            if value is not None:
                samples[field].append(value)

    def percentile(values, fraction):
        if not values:
            return None
        values = sorted(values)
        index = (len(values) - 1) * fraction
        lower, upper = int(index), min(int(index) + 1, len(values) - 1)
        return values[lower] + (values[upper] - values[lower]) * (index - lower)

    return {
        "clusters": len(clusters),
        "iterations": iterations,
        "seed": seed,
        "intervals": {
            field: {"lower": percentile(values, 0.025), "upper": percentile(values, 0.975),
                    "replicates": len(values)}
            for field, values in samples.items()
        },
        "interval_method": "repository/family cluster bootstrap with inverse-probability weighted point metrics",
        "claim_boundary": "Uncertainty estimate only; source independence and oracle label correctness remain separate gates.",
    }
