"""Client CrowdStrike Spotlight — intégration non terminée.

⚠️ Ce module n'est pas fonctionnel et n'est câblé à aucune tâche ni endpoint.

Il retournait auparavant des données de démonstration codées en dur. Dans une
plateforme de gestion de vulnérabilités, c'est le pire comportement possible :
un appelant qui le branche obtient des findings crédibles mais inventés, qui
entrent en base, remontent dans le backlog priorisé, et déclenchent des
décisions de remédiation sur des vulnérabilités qui n'existent pas. L'erreur ne
se voit qu'au moment où quelqu'un cherche l'hôte `win-prod-db-01` et ne le
trouve pas.

`fetch_vulnerabilities()` lève donc désormais `NotImplementedError`. Un module
inachevé doit refuser de servir, pas produire du plausible.

Pour terminer l'intégration (cf. point 5 de `TODO.md`) :
  - pagination de l'API Spotlight (`/spotlight/queries/vulnerabilities/v1`)
  - mise en cache du jeton OAuth2 et renouvellement avant expiration
  - gestion des 429 et 5xx avec backoff
  - normalisation vers le format décrit dans `app/parsers/utils.py`
  - configuration des identifiants via `Settings`

À défaut, supprimer ce module et la dépendance `requests`.
"""

import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)

FALCON_API_BASE = "https://api.crowdstrike.com"
REQUEST_TIMEOUT = 30


class CrowdstrikeClient:
    """Client de l'API CrowdStrike Spotlight. **Non implémenté.**"""

    def __init__(self, client_id: str, client_secret: str, base_url: str | None = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url or FALCON_API_BASE
        self._token: str | None = None

    def _authenticate(self) -> str:
        """Obtient un jeton OAuth2.

        Implémenté, mais sans mise en cache ni renouvellement : appeler cette
        méthode à chaque requête épuiserait le quota d'authentification.
        """
        response = requests.post(
            f"{self.base_url}/oauth2/token",
            data={"client_id": self.client_id, "client_secret": self.client_secret},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        self._token = response.json()["access_token"]
        return self._token

    def fetch_vulnerabilities(self) -> list[dict[str, Any]]:
        """Non implémenté : lève plutôt que de retourner des données inventées."""
        raise NotImplementedError(
            "L'intégration CrowdStrike Spotlight n'est pas terminée. "
            "Ce client retournait auparavant des données de démonstration, ce qui "
            "injectait des findings fictifs dans le backlog de remédiation. "
            "Voir le point 5 de TODO.md."
        )
