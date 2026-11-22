
from datetime import datetime, timezone


# Transparent, provisional category weights.
# These represent investigation priority, not proven severity.
THREAT_WEIGHTS = {
    "botnet_c2": 40,
    "malware_download": 35,
    "phishing": 30,
}

DEFAULT_THREAT_WEIGHT = 10


def calculate_risk(record):

    threat_type = str(
        record.get("threat_type", "")
    ).strip().lower()

    # Factor 1: Threat category
    category_score = THREAT_WEIGHTS.get(
        threat_type,
        DEFAULT_THREAT_WEIGHT
    )

    # Factor 2: Confidence
    confidence = record.get("confidence")

    if confidence is None:
        confidence_score = 15
    else:
        confidence_score = round(
            max(0, min(100, int(confidence))) * 0.30
        )

    # Factor 3: Freshness
    first_seen = record.get("first_seen")
    freshness_score = 10

    if first_seen:
        try:
            if isinstance(first_seen, str):
                first_seen = datetime.fromisoformat(
                    first_seen.replace("Z", "+00:00")
                )

            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(
                    tzinfo=timezone.utc
                )

            age_days = (
                datetime.now(timezone.utc) - first_seen
            ).total_seconds() / 86400

            if age_days < 0:
                freshness_score = 0
            elif age_days <= 7:
                freshness_score = 20
            elif age_days <= 30:
                freshness_score = 15
            elif age_days <= 90:
                freshness_score = 8
            else:
                freshness_score = 3

        except (ValueError, TypeError):
            freshness_score = 10

    # Factor 4: Supporting evidence
    metadata = record.get("metadata", {})

    if not isinstance(metadata, dict):
        metadata = {}

    evidence_fields = [
        "urlhaus_reference",
        "reference",
        "reporter",
        "tags",
    ]

    has_evidence = any(
        metadata.get(field)
        for field in evidence_fields
    )

    evidence_score = 10 if has_evidence else 5

    # Combined risk score
    risk_score = min(
        100,
        category_score
        + confidence_score
        + freshness_score
        + evidence_score
    )

    # Provisional investigation-priority bands
    if risk_score >= 80:
        risk_level = "High"
    elif risk_score >= 60:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "category_score": category_score,
        "confidence_score": confidence_score,
        "freshness_score": freshness_score,
        "evidence_score": evidence_score,
    }
