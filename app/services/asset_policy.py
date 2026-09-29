"""Policy applied to assets discovered by a scan.

Every asset used to be created as ``Medium``, which made the risk score of a
freshly discovered production host indistinguishable from a lab box until
somebody curated it by hand. Mapping subnets to a business criticality lets the
first scan already place findings in roughly the right order.
"""

import ipaddress
import logging

from app.core.config import settings
from app.models.asset import Criticality

logger = logging.getLogger(__name__)

DEFAULT_CRITICALITY = Criticality.medium


def criticality_for(ip_address: str | None) -> Criticality:
    """Business criticality for a newly discovered address.

    The most specific matching rule wins, so a broad ``10.0.0.0/8`` default can
    be overridden by a narrow ``10.0.5.0/24`` for the payment segment. Anything
    unmatched — or unparseable — falls back to Medium rather than guessing.
    """
    level = _most_specific(settings.CRITICALITY_RULES, ip_address, "CRITICALITY_RULES")
    return _as_criticality(level)


def owner_team_for(ip_address: str | None) -> str | None:
    """The team in charge of an address, from OWNER_TEAM_RULES; None if unmatched.

    It decides which team a remediation ticket goes to, so an address no rule
    covers stays unassigned rather than landing on a guessed team.
    """
    team = _most_specific(settings.OWNER_TEAM_RULES, ip_address, "OWNER_TEAM_RULES")
    team = str(team).strip() if team else ""
    return team[:128] or None


def _most_specific(rules: dict | None, ip_address: str | None, name: str):
    """The value of the most specific rule whose subnet holds the address.

    A broad ``10.0.0.0/8`` default can so be overridden by a narrow
    ``10.0.5.0/24``. Unparseable rules and addresses match nothing.
    """
    if not rules or not ip_address:
        return None

    try:
        address = ipaddress.ip_address(ip_address.strip())
    except ValueError:
        return None

    best_match: ipaddress._BaseNetwork | None = None
    best_value = None

    for cidr, value in rules.items():
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning("Ignoring malformed CIDR in %s: %r", name, cidr)
            continue

        if address.version != network.version or address not in network:
            continue

        if best_match is None or network.prefixlen > best_match.prefixlen:
            best_match = network
            best_value = value

    return best_value


def exposure_for(ip_address: str | None) -> bool:
    """Whether a newly discovered address sits in an Internet-facing subnet.

    Unset or unparseable means internal: marking a host exposed raises the risk
    of all its findings, so it is never guessed.
    """
    subnets = settings.INTERNET_FACING_SUBNETS or []
    if not subnets or not ip_address:
        return False

    try:
        address = ipaddress.ip_address(ip_address.strip())
    except ValueError:
        return False

    for cidr in subnets:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning("Ignoring malformed CIDR in INTERNET_FACING_SUBNETS: %r", cidr)
            continue
        if address.version == network.version and address in network:
            return True
    return False


def _as_criticality(level: str | None) -> Criticality:
    if not level:
        return DEFAULT_CRITICALITY
    try:
        return Criticality(str(level).strip().capitalize())
    except ValueError:
        logger.warning("Ignoring unknown criticality in CRITICALITY_RULES: %r", level)
        return DEFAULT_CRITICALITY
