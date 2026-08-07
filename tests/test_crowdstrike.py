"""Tests du client CrowdStrike inachevé.

L'intérêt de ces tests n'est pas de couvrir du code mort : c'est de verrouiller
le fait qu'un module inachevé **refuse de servir** plutôt que de retourner des
données plausibles. Si quelqu'un réintroduit un jeu de données de démonstration
« en attendant », ces tests échouent.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.parsers.crowdstrike import CrowdstrikeClient


class TestUnimplementedIntegration:
    def test_fetching_raises_instead_of_returning_fake_data(self):
        """Le comportement dangereux serait de retourner des findings inventés :
        ils entreraient en base et déclencheraient des remédiations sur des
        vulnérabilités inexistantes."""
        client = CrowdstrikeClient("id", "secret")

        with pytest.raises(NotImplementedError) as exc:
            client.fetch_vulnerabilities()

        # Le message doit orienter vers le suivi, pas juste constater l'échec.
        assert "TODO.md" in str(exc.value)

    def test_it_never_returns_a_list(self):
        """Garde-fou explicite : toute réintroduction de données factices
        ferait passer ce test de vert à rouge."""
        client = CrowdstrikeClient("id", "secret")
        try:
            result = client.fetch_vulnerabilities()
        except NotImplementedError:
            return
        pytest.fail(
            f"fetch_vulnerabilities a retourné {result!r} au lieu de lever. "
            "Un client inachevé ne doit jamais produire de findings."
        )


class TestAuthentication:
    def test_authentication_stores_the_token(self):
        client = CrowdstrikeClient("id", "secret")
        response = MagicMock()
        response.json.return_value = {"access_token": "jeton-de-test"}

        with patch("app.parsers.crowdstrike.requests.post", return_value=response):
            token = client._authenticate()

        assert token == "jeton-de-test"
        assert client._token == "jeton-de-test"

    def test_authentication_propagates_an_http_error(self):
        """Des identifiants invalides doivent échouer bruyamment, pas produire
        un client silencieusement inutilisable."""
        client = CrowdstrikeClient("id", "mauvais-secret")
        response = MagicMock()
        response.raise_for_status.side_effect = RuntimeError("401 Unauthorized")

        with patch("app.parsers.crowdstrike.requests.post", return_value=response):
            with pytest.raises(RuntimeError):
                client._authenticate()

    def test_the_request_has_a_timeout(self):
        """Sans timeout, une API qui ne répond pas bloque un worker Celery
        indéfiniment."""
        client = CrowdstrikeClient("id", "secret")
        response = MagicMock()
        response.json.return_value = {"access_token": "t"}

        with patch(
            "app.parsers.crowdstrike.requests.post", return_value=response
        ) as post:
            client._authenticate()

        assert post.call_args.kwargs.get("timeout") is not None

    def test_the_base_url_is_configurable(self):
        """CrowdStrike expose plusieurs domaines régionaux (US-2, EU-1) : une
        URL codée en dur rend le client inutilisable hors de la région par
        défaut."""
        client = CrowdstrikeClient(
            "id", "secret", base_url="https://api.eu-1.crowdstrike.com"
        )
        assert client.base_url == "https://api.eu-1.crowdstrike.com"
