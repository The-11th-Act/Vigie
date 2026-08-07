"""Cohérence de la politique de risque.

Les seuils de sévérité vivent aujourd'hui à deux endroits indépendants :

- ``parsers/utils.severity_from_cvss`` : CVSS brut  -> libellé de sévérité
- ``services/risk_scoring.risk_level`` : score contextuel -> niveau de risque

Les deux jeux de bornes sont **numériquement identiques mais sans lien de code**.
Modifier l'un sans l'autre ne casse aucun test existant et ne lève aucune erreur :
la plateforme se met simplement à afficher un finding « High » dont le niveau de
risque est « Critical ». Personne ne le remarque avant un audit.

Ces tests existent pour transformer cette dérive silencieuse en échec bruyant.
Ils ne testent pas une implémentation, ils testent un invariant entre deux modules.
"""

import pytest

from app.models.vulnerability import Severity
from app.parsers.utils import severity_from_cvss
from app.services.remediation import DEFAULT_SLA_DAYS, SLA_DAYS
from app.services.risk_scoring import CRITICALITY_MULTIPLIERS, risk_level


class TestThresholdConsistency:
    """Les deux échelles doivent rester alignées."""

    @pytest.mark.parametrize("score", [0.0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0])
    def test_both_scales_agree_on_every_boundary(self, score):
        assert severity_from_cvss(score) == risk_level(score), (
            f"Divergence à {score} : severity_from_cvss dit "
            f"'{severity_from_cvss(score)}' et risk_level dit '{risk_level(score)}'. "
            "Les deux échelles doivent être modifiées ensemble."
        )

    def test_both_scales_cover_the_same_labels(self):
        labels_from_cvss = {severity_from_cvss(s / 10) for s in range(0, 101)}
        labels_from_risk = {risk_level(s / 10) for s in range(0, 101)}
        assert labels_from_cvss == labels_from_risk

    def test_every_label_is_a_valid_severity(self):
        """Un libellé absent de l'enum ferait échouer l'insertion en base."""
        valid = {s.value for s in Severity}
        for score in range(0, 101):
            assert severity_from_cvss(score / 10) in valid
            assert risk_level(score / 10) in valid


class TestPolicyCompleteness:
    """Chaque valeur d'enum doit avoir une politique associée."""

    def test_every_severity_has_an_sla(self):
        """Une sévérité sans SLA retombe silencieusement sur 90 jours, ce qui
        donnerait à une faille critique la même échéance qu'à une moyenne."""
        for severity in Severity:
            assert severity.value in SLA_DAYS, (
                f"'{severity.value}' n'a pas de fenêtre SLA et hériterait de "
                f"{DEFAULT_SLA_DAYS} jours par défaut."
            )

    def test_every_criticality_has_a_multiplier(self):
        from app.models.asset import Criticality

        for criticality in Criticality:
            assert criticality.value in CRITICALITY_MULTIPLIERS, (
                f"'{criticality.value}' n'a pas de multiplicateur et serait "
                "traité comme neutre (1.0), effaçant la contextualisation."
            )

    def test_slas_get_stricter_as_severity_rises(self):
        """Une politique où une faille critique aurait plus de temps qu'une
        faible serait une erreur de saisie, pas un choix."""
        ordered = ["Low", "Medium", "High", "Critical"]
        windows = [SLA_DAYS[s] for s in ordered]
        assert windows == sorted(
            windows, reverse=True
        ), f"Les fenêtres SLA ne décroissent pas avec la gravité : {dict(zip(ordered, windows, strict=True))}"

    def test_multipliers_grow_with_business_criticality(self):
        ordered = ["Low", "Medium", "High", "Critical"]
        multipliers = [CRITICALITY_MULTIPLIERS[c] for c in ordered]
        assert multipliers == sorted(multipliers), (
            "Un asset plus critique doit amplifier le risque, pas l'atténuer : "
            f"{dict(zip(ordered, multipliers, strict=True))}"
        )

    def test_a_critical_asset_amplifies_and_a_low_one_dampens(self):
        assert CRITICALITY_MULTIPLIERS["Critical"] > 1.0
        assert CRITICALITY_MULTIPLIERS["Low"] < 1.0
        # Medium est le point neutre : c'est la valeur attribuée par défaut à
        # tout asset créé par ingestion, elle ne doit pas biaiser le score.
        assert CRITICALITY_MULTIPLIERS["Medium"] == 1.0
