from datetime import UTC, date, datetime, timedelta

import pytest

from app.services.remediation import (
    apply_kev_sla,
    calculate_remediation_deadline,
    is_overdue,
)
from app.services.risk_scoring import (
    RiskInputs,
    calculate_risk_score,
    compute_risk,
    epss_band,
    explain_risk,
    risk_level,
)


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


NOW = datetime(2026, 9, 25, tzinfo=UTC)


class TestThreatContext:
    """KEV, EPSS and exposure weigh how likely a CVE is to be exploited here."""

    @pytest.mark.parametrize("cvss", [0.0, 3.3, 5.0, 7.5, 9.8, 10.0])
    @pytest.mark.parametrize("criticality", ["Critical", "High", "Medium", "Low"])
    @pytest.mark.parametrize("days_late", [None, -10, 45, 400])
    def test_no_context_leaves_the_legacy_score_intact(
        self, cvss, criticality, days_late
    ):
        """Without intel, scores must not move: stored scores and every existing
        assertion rely on CVSS x criticality + the overdue penalty alone."""
        deadline = None if days_late is None else NOW - timedelta(days=days_late)
        multiplier = {"Critical": 1.5, "High": 1.2, "Medium": 1.0, "Low": 0.7}
        legacy = cvss * multiplier[criticality]
        if days_late and days_late > 0:
            legacy += min(1.5, days_late / 30 * 0.5)

        score = calculate_risk_score(cvss, criticality, deadline, NOW)

        assert score == min(10.0, round(legacy, 2))

    @pytest.mark.parametrize(
        "cvss,criticality,context,expected",
        [
            (9.8, "Medium", {"epss_score": 0.002}, 8.82),  # noise is dampened
            (7.5, "Medium", {"epss_score": 0.62}, 9.75),
            (7.5, "Medium", {"epss_score": 0.05}, 7.5),  # 1-10 % is neutral
            (5.0, "Low", {"in_kev": True}, 7.0),  # 4.55, raised to the floor
            (5.0, "Medium", {"internet_facing": True, "epss_score": 0.2}, 6.9),
            (6.0, "Medium", {"internet_facing": True, "in_kev": True}, 9.0),  # capped
            (7.5, "High", {"internet_facing": True, "in_kev": True}, 10.0),
        ],
    )
    def test_worked_examples(self, cvss, criticality, context, expected):
        assert calculate_risk_score(cvss, criticality, **context) == expected

    @pytest.mark.parametrize(
        "epss,band",
        [
            (None, None),
            (0.0, 3),
            (0.0099, 3),
            (0.01, 2),
            (0.0999, 2),
            (0.10, 1),
            (0.4999, 1),
            (0.50, 0),
            (1.0, 0),
        ],
    )
    def test_epss_band_boundaries(self, epss, band):
        assert epss_band(epss) == band

    def test_unknown_epss_is_neutral_not_low(self):
        """NULL means never scored: it must not be dampened like a 0.1 % CVE."""
        assert calculate_risk_score(8.0, "Medium", epss_score=None) == 8.0
        assert calculate_risk_score(8.0, "Medium", epss_score=0.001) < 8.0

    def test_a_higher_epss_never_lowers_the_score(self):
        probabilities = [i / 1000 for i in range(0, 1001, 5)]
        scores = [
            calculate_risk_score(6.0, "Medium", epss_score=p) for p in probabilities
        ]
        assert scores == sorted(scores)

    def test_kev_outweighs_any_epss(self):
        """Observed exploitation beats a prediction, whatever the prediction."""
        kev_low_epss = calculate_risk_score(6.0, "Medium", in_kev=True, epss_score=0.001)
        assert kev_low_epss == calculate_risk_score(6.0, "Medium", in_kev=True)

    def test_the_kev_floor_applies_on_a_low_criticality_host(self):
        assert calculate_risk_score(2.0, "Low", in_kev=True) == 7.0
        assert risk_level(calculate_risk_score(2.0, "Low", in_kev=True)) == "High"

    def test_the_context_multiplier_is_capped(self):
        capped = compute_risk(
            RiskInputs(6.0, "Medium", in_kev=True, internet_facing=True)
        )
        assert capped.score == 9.0
        assert "context_cap" in {f.code for f in capped.factors}


class TestRiskExplanation:
    def test_a_neutral_finding_has_no_factor(self):
        assert explain_risk(RiskInputs(6.0, "Medium", epss_score=0.05)) == []

    def test_lists_every_non_neutral_factor(self):
        factors = explain_risk(
            RiskInputs(
                6.0,
                "High",
                remediation_deadline=NOW - timedelta(days=60),
                in_kev=True,
                internet_facing=True,
                kev_date_added=date(2024, 3, 1),
                kev_ransomware=True,
            ),
            NOW,
        )
        by_code = {f["code"]: f for f in factors}

        assert set(by_code) == {
            "criticality",
            "kev",
            "kev_ransomware",
            "internet_facing",
            "context_cap",
            "overdue",
        }
        assert "2024-03-01" in by_code["kev"]["label"]
        assert by_code["overdue"]["points"] == 1.0
        assert by_code["kev_ransomware"]["multiplier"] is None

    def test_the_factors_rebuild_the_score(self):
        """The explanation is derived from the computation, not written beside it."""
        inputs = RiskInputs(
            5.0,
            "Critical",
            remediation_deadline=NOW - timedelta(days=30),
            epss_score=0.3,
        )
        breakdown = compute_risk(inputs, NOW)

        rebuilt = 5.0
        for factor in breakdown.factors:
            rebuilt *= factor.multiplier or 1.0
        rebuilt += sum(f.points or 0.0 for f in breakdown.factors)

        assert breakdown.score == round(rebuilt, 2)

    def test_the_floor_says_how_much_it_added(self):
        factors = {
            f["code"]: f for f in explain_risk(RiskInputs(5.0, "Low", in_kev=True))
        }
        assert factors["kev_floor"]["points"] == 2.45  # 7.0 - 3.5 * 1.3


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


class TestKevSLA:
    """A CVE exploited in the wild gets KEV_SLA_DAYS, never more than its window."""

    DETECTED = datetime(2026, 1, 1, tzinfo=UTC)

    def test_shortens_a_long_severity_window(self):
        medium = calculate_remediation_deadline("Medium", self.DETECTED)  # 90 days

        tightened = apply_kev_sla(medium, self.DETECTED, date(2025, 6, 1))

        assert tightened == self.DETECTED + timedelta(days=14)

    def test_never_extends_a_deadline(self):
        already_short = self.DETECTED + timedelta(days=3)
        assert apply_kev_sla(already_short, self.DETECTED, None) == already_short

    def test_counts_from_the_listing_when_it_came_after_detection(self):
        """Listed months after detection: 14 days from the listing, not an
        instant breach."""
        listed = date(2026, 5, 1)
        deadline = apply_kev_sla(None, self.DETECTED, listed)
        assert deadline == datetime(2026, 5, 15, tzinfo=UTC)

    def test_tolerates_naive_datetimes(self):
        naive = datetime(2026, 1, 1)
        deadline = apply_kev_sla(naive + timedelta(days=90), naive, None)
        assert deadline == self.DETECTED + timedelta(days=14)

    def test_can_be_disabled(self, monkeypatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "KEV_SLA_DAYS", 0)
        medium = calculate_remediation_deadline("Medium", self.DETECTED)
        assert apply_kev_sla(medium, self.DETECTED, None) == medium
