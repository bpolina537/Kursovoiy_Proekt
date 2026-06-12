from __future__ import annotations

import pytest

from vuln_mgmt.domain.risk import (
    calculate_priority_score,
    classify_risk,
    is_version_affected,
    sort_versions,
)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (91.0, "critical"),
        (70.0, "high"),
        (40.0, "medium"),
        (10.0, "low"),
    ],
)
def test_classify_risk_uses_documented_bands(score: float, expected: str) -> None:
    assert classify_risk(score) == expected


def test_priority_score_increases_for_production_critical_asset() -> None:
    development_score = calculate_priority_score(7.5, "development", 2, False)
    production_score = calculate_priority_score(7.5, "production", 5, True)

    assert production_score > development_score
    assert production_score <= 100.0


@pytest.mark.parametrize(
    ("asset_version", "fixed_version", "expected"),
    [
        ("1.0.0", "1.1.0", True),
        ("1.1.0", "1.1.0", False),
        ("2.0.0", None, True),
    ],
)
def test_version_matching_handles_boundaries(
    asset_version: str,
    fixed_version: str | None,
    expected: bool,
) -> None:
    assert is_version_affected(asset_version, fixed_version) is expected


def test_sort_versions_uses_numeric_segments() -> None:
    assert sort_versions(["1.10.0", "1.2.0", "1.0.9"]) == ["1.0.9", "1.2.0", "1.10.0"]
