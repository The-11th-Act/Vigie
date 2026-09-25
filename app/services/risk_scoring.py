"""Risk scoring — the core of the RBVM model.

A raw CVSS score describes a vulnerability in the abstract. Risk is what that
vulnerability means *here*: a 9.8 on an isolated lab box matters less than a 7.5
on the production payment database. The score below contextualises CVSS with
business criticality and finding age so the backlog can be ordered by what
actually needs fixing first.

It also weighs how likely the vulnerability is to be exploited, which CVSS says
nothing about: whether it is exploited in the wild (CISA KEV), the predicted
probability of exploitation (FIRST EPSS), and whether the host is reachable from
the Internet. Without any of that context the score is exactly CVSS × criticality
plus the overdue penalty, as it always was.

    base  = CVSS × criticality multiplier
    ctx   = min(MAX_CONTEXT_MULTIPLIER, threat multiplier × exposure multiplier)
    score = base × ctx + overdue penalty, raised to KEV_RISK_FLOOR for a KEV entry,
            clamped to [0, 10]
"""

from dataclasses import dataclass
from datetime import UTC, date, datetime

# How much the business criticality of the host amplifies or dampens CVSS.
CRITICALITY_MULTIPLIERS = {
    "Critical": 1.5,
    "High": 1.2,
    "Medium": 1.0,
    "Low": 0.7,
}

# Additive penalty (in points) once a finding blows past its remediation SLA.
# Capped so an old low-severity issue never outranks a fresh critical one.
MAX_OVERDUE_PENALTY = 1.5
OVERDUE_PENALTY_PER_30_DAYS = 0.5

# Exploitation observed in the wild outweighs any prediction, so a KEV entry
# takes this multiplier instead of its EPSS band.
KEV_MULTIPLIER = 1.3
# A known-exploited vulnerability is at least "High" risk, whatever the host:
# this is the lower bound of the "High" level in ``risk_level``.
KEV_RISK_FLOOR = 7.0

# EPSS probability -> multiplier, by band, highest threshold first. Bands rather
# than a continuous factor keep the score explainable, and stable: EPSS drifts a
# little every day for almost every CVE, and a score should move only when a CVE
# changes band. Below 1 %, the score is dampened — separating the few likely
# exploits from the noise is the point of the model.
EPSS_BANDS = (
    (0.50, 1.30),
    (0.10, 1.15),
    (0.01, 1.00),
    (0.00, 0.90),
)

INTERNET_FACING_MULTIPLIER = 1.2

# Several multipliers stacked on a critical asset would push most of the top of
# the backlog to 10.0, where nothing can be told apart any more.
MAX_CONTEXT_MULTIPLIER = 1.5


@dataclass(frozen=True)
class RiskInputs:
    cvss_score: float
    business_criticality: str
    remediation_deadline: datetime | None = None
    in_kev: bool = False
    epss_score: float | None = None
    internet_facing: bool = False
    # Shown in the explanation only; they do not change the score.
    kev_date_added: date | None = None
    kev_ransomware: bool = False


@dataclass(frozen=True)
class RiskFactor:
    """One reason a score differs from plain CVSS, for the analyst reading it."""

    code: str
    label: str
    multiplier: float | None = None
    points: float | None = None

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "label": self.label,
            "multiplier": self.multiplier,
            "points": self.points,
        }


@dataclass(frozen=True)
class RiskBreakdown:
    score: float
    factors: tuple[RiskFactor, ...]


def compute_risk(inputs: RiskInputs, now: datetime | None = None) -> RiskBreakdown:
    """Score a finding and say why.

    The score and its explanation come out of the same computation, so the
    explanation can never describe a formula the score no longer follows.
    """
    factors: list[RiskFactor] = []

    criticality = _as_str(inputs.business_criticality)
    crit_multiplier = CRITICALITY_MULTIPLIERS.get(criticality, 1.0)
    if crit_multiplier != 1.0:
        factors.append(
            RiskFactor(
                "criticality",
                f"{criticality} business criticality",
                multiplier=crit_multiplier,
            )
        )
    base = _as_float(inputs.cvss_score) * crit_multiplier

    if inputs.in_kev:
        threat = KEV_MULTIPLIER
        added = (
            f", added {inputs.kev_date_added.isoformat()}"
            if inputs.kev_date_added
            else ""
        )
        factors.append(
            RiskFactor("kev", f"Known exploited (CISA KEV{added})", multiplier=threat)
        )
    else:
        threat = epss_multiplier(inputs.epss_score)
        if threat != 1.0:
            factors.append(
                RiskFactor(
                    "epss",
                    f"EPSS {inputs.epss_score:.1%} chance of exploitation in 30 days",
                    multiplier=threat,
                )
            )
    if inputs.kev_ransomware:
        factors.append(RiskFactor("kev_ransomware", "Known use in ransomware campaigns"))

    exposure = INTERNET_FACING_MULTIPLIER if inputs.internet_facing else 1.0
    if inputs.internet_facing:
        factors.append(
            RiskFactor("internet_facing", "Internet-facing asset", multiplier=exposure)
        )

    context = threat * exposure
    if context > MAX_CONTEXT_MULTIPLIER:
        context = MAX_CONTEXT_MULTIPLIER
        factors.append(
            RiskFactor(
                "context_cap",
                f"Threat context capped at ×{MAX_CONTEXT_MULTIPLIER}",
                multiplier=MAX_CONTEXT_MULTIPLIER,
            )
        )

    raw = base * context
    penalty = _overdue_penalty(inputs.remediation_deadline, now)
    if penalty:
        factors.append(
            RiskFactor(
                "overdue", "Past its remediation deadline", points=round(penalty, 2)
            )
        )
    raw += penalty

    if inputs.in_kev and raw < KEV_RISK_FLOOR:
        factors.append(
            RiskFactor(
                "kev_floor",
                f"Raised to {KEV_RISK_FLOOR}, the floor for a known exploited CVE",
                points=round(KEV_RISK_FLOOR - raw, 2),
            )
        )
        raw = KEV_RISK_FLOOR

    return RiskBreakdown(score=min(10.0, max(0.0, round(raw, 2))), factors=tuple(factors))


def calculate_risk_score(
    cvss_score: float,
    business_criticality: str,
    remediation_deadline: datetime | None = None,
    now: datetime | None = None,
    *,
    in_kev: bool = False,
    epss_score: float | None = None,
    internet_facing: bool = False,
) -> float:
    """Return a contextual risk score in the range [0.0, 10.0].

    ``remediation_deadline`` is optional: when supplied, findings past their SLA
    accrue an escalating penalty so they surface at the top of the backlog. The
    threat context defaults to neutral, which leaves CVSS × criticality intact.
    """
    inputs = RiskInputs(
        cvss_score=cvss_score,
        business_criticality=business_criticality,
        remediation_deadline=remediation_deadline,
        in_kev=in_kev,
        epss_score=epss_score,
        internet_facing=internet_facing,
    )
    return compute_risk(inputs, now).score


def explain_risk(inputs: RiskInputs, now: datetime | None = None) -> list[dict]:
    """The non-neutral factors behind a score, as API-ready dictionaries."""
    return [factor.as_dict() for factor in compute_risk(inputs, now).factors]


def epss_band(epss_score: float | None) -> int | None:
    """Index of the EPSS band a probability falls in; None when unknown.

    A CVE's score only depends on its band, so this is what tells the feed
    refresh whether a new EPSS value requires rescoring its findings.
    """
    if epss_score is None or epss_score < 0:
        return None
    for index, (threshold, _) in enumerate(EPSS_BANDS):
        if epss_score >= threshold:
            return index
    return None  # pragma: no cover - the last band starts at 0


def epss_multiplier(epss_score: float | None) -> float:
    band = epss_band(epss_score)
    return 1.0 if band is None else EPSS_BANDS[band][1]


def risk_level(risk_score: float) -> str:
    """Bucket a risk score into a label for dashboards and filtering."""
    if risk_score >= 9.0:
        return "Critical"
    if risk_score >= 7.0:
        return "High"
    if risk_score >= 4.0:
        return "Medium"
    return "Low"


def _overdue_penalty(
    remediation_deadline: datetime | None, now: datetime | None
) -> float:
    if remediation_deadline is None:
        return 0.0

    reference = now or datetime.now(UTC)
    deadline = remediation_deadline
    # Tolerate naive datetimes, which is what SQLite hands back in tests.
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=UTC)

    days_overdue = (reference - deadline).days
    if days_overdue <= 0:
        return 0.0

    penalty = (days_overdue / 30.0) * OVERDUE_PENALTY_PER_30_DAYS
    return min(MAX_OVERDUE_PENALTY, penalty)


def _as_str(value) -> str:
    """Accept either a raw string or a Criticality enum member."""
    return getattr(value, "value", value)


def _as_float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
