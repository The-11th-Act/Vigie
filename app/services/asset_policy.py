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
    rules = settings.CRITICALITY_RULES or {}
    if not rules or not ip_address:
        return DEFAULT_CRITICALITY

    try:
        address = ipaddress.ip_address(ip_address.strip())
    except ValueError:
        return DEFAULT_CRITICALITY

    best_match: ipaddress._BaseNetwork | None = None
    best_level: str | None = None

    for cidr, level in rules.items():
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning("Ignoring malformed CIDR in CRITICALITY_RULES: %r", cidr)
            continue

        if address.version != network.version or address not in network:
            continue

        if best_match is None or network.prefixlen > best_match.prefixlen:
            best_match = network
            best_level = level

    return _as_criticality(best_level)


def _as_criticality(level: str | None) -> Criticality:
    if not level:
        return DEFAULT_CRITICALITY
    try:
        return Criticality(str(level).strip().capitalize())
    except ValueError:
        logger.warning("Ignoring unknown criticality in CRITICALITY_RULES: %r", level)
        return DEFAULT_CRITICALITY
