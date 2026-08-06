from datetime import UTC, datetime, timedelta

import pytest

from app.services.remediation import calculate_remediation_deadline, is_overdue
from app.services.risk_scoring import calculate_risk_score, risk_level


class TestRiskScoring:
    @pytest.mark.parametrize(
        "cvss,criticality,expected",
        [
            (8.0, "Critical", 10.0),  # 12.0 clamped to the ceiling
            (5.0, "Critical", 7.5),
            (5.0, "High", 6.0),
            (5.0, "Medium", 5.0),
            (5.0, "Low", 3.5),
        ],
    )
    def test_criticality_multiplier(self, cvss, criticality, expected):
        assert calculate_risk_score(cvss, criticality) == expected

    def test_unknown_criticality_is_neutral(self):
        assert calculate_risk_score(6.0, "Unheard-of") == 6.0

    def test_score_is_always_within_bounds(self):
        assert calculate_risk_score(10.0, "Critical") == 10.0
        assert calculate_risk_score(0.0, "Low") == 0.0
        assert calculate_risk_score(-5.0, "Critical") == 0.0

    def test_non_numeric_cvss_does_not_raise(self):
        assert calculate_risk_score("not-a-number", "High") == 0.0

    def test_accepts_enum_member(self):
        from app.models.asset import Criticality

        assert calculate_risk_score(5.0, Criticality.critical) == 7.5

    def test_overdue_findings_score_higher(self):
        now = datetime(2026, 7, 28, tzinfo=UTC)
        on_time = now + timedelta(days=10)
        overdue = now - timedelta(days=60)

        assert calculate_risk_score(5.0, "Medium", overdue, now) > calculate_risk_score(
            5.0, "Medium", on_time, now
        )

    def test_overdue_penalty_is_capped(self):
        now = datetime(2026, 7, 28, tzinfo=UTC)
        ancient = now - timedelta(days=3650)
        # 5.0 base + capped 1.5 penalty, never runaway.
        assert calculate_risk_score(5.0, "Medium", ancient, now) == 6.5

    def test_naive_deadline_is_treated_as_utc(self):
        now = datetime(2026, 7, 28, tzinfo=UTC)
        naive_overdue = datetime(2026, 6, 1)
        assert calculate_risk_score(5.0, "Medium", naive_overdue, now) > 5.0

    @pytest.mark.parametrize(
        "score,expected",
        [
            (9.5, "Critical"),
            (9.0, "Critical"),
            (7.0, "High"),
            (4.0, "Medium"),
            (1.0, "Low"),
        ],
    )
    def test_risk_level_buckets(self, score, expected):
        assert risk_level(score) == expected


class TestRemediationSLA:
    @pytest.mark.parametrize(
        "severity,days",
        [("Critical", 14), ("High", 30), ("Medium", 90), ("Low", 180)],
    )
    def test_sla_windows(self, severity, days):
        detected = datetime(2026, 1, 1, tzinfo=UTC)
        assert calculate_remediation_deadline(severity, detected) == detected + timedelta(
            days=days
        )

    def test_unknown_severity_falls_back_to_default(self):
        detected = datetime(2026, 1, 1, tzinfo=UTC)
        assert calculate_remediation_deadline("Bogus", detected) == detected + timedelta(
            days=90
        )

    def test_deadline_is_timezone_aware(self):
        assert calculate_remediation_deadline("High").tzinfo is not None

    def test_is_overdue(self):
        now = datetime(2026, 7, 28, tzinfo=UTC)
        assert is_overdue(now - timedelta(days=1), now) is True
        assert is_overdue(now + timedelta(days=1), now) is False
        assert is_overdue(None, now) is False
