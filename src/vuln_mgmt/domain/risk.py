from __future__ import annotations

from functools import cmp_to_key


ENVIRONMENT_MULTIPLIER = {
    "development": 0.8,
    "staging": 1.0,
    "production": 1.25,
}

CRITICALITY_MULTIPLIER = {
    1: 0.75,
    2: 0.9,
    3: 1.0,
    4: 1.15,
    5: 1.3,
}

SEVERITY_BANDS = (
    (85.0, "critical"),
    (65.0, "high"),
    (35.0, "medium"),
    (0.0, "low"),
)


def calculate_priority_score(
    cvss_score: float,
    environment: str,
    criticality: int,
    exploit_available: bool,
) -> float:
    normalized_score = max(0.0, min(cvss_score, 10.0)) * 10.0
    environment_factor = ENVIRONMENT_MULTIPLIER.get(environment, 1.0)
    criticality_factor = CRITICALITY_MULTIPLIER.get(criticality, 1.0)
    exploit_factor = 1.15 if exploit_available else 1.0
    score = normalized_score * environment_factor * criticality_factor * exploit_factor
    return round(min(score, 100.0), 2)


def classify_risk(score: float) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "low"


def _version_tuple(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for token in version.replace("-", ".").split("."):
        if token.isdigit():
            parts.append(int(token))
        else:
            break
    return tuple(parts)


def compare_versions(left: str, right: str) -> int:
    left_parts = _version_tuple(left)
    right_parts = _version_tuple(right)
    for left_part, right_part in zip(left_parts, right_parts, strict=False):
        if left_part < right_part:
            return -1
        if left_part > right_part:
            return 1
    if len(left_parts) < len(right_parts):
        return -1
    if len(left_parts) > len(right_parts):
        return 1
    if left == right:
        return 0
    return -1 if left < right else 1


def is_version_affected(asset_version: str, fixed_version: str | None) -> bool:
    if fixed_version is None or not fixed_version:
        return True
    return compare_versions(asset_version, fixed_version) < 0


def sort_versions(versions: list[str]) -> list[str]:
    return sorted(versions, key=cmp_to_key(compare_versions))

