"""Policy applied to assets discovered by a scan or declared by an operator.

Every asset used to be created as ``Medium``, which made the risk score of a
freshly discovered production host indistinguishable from a lab box until
somebody curated it by hand.

Dynamic rules assign business criticality, owner team, environment and
Internet exposure based on a hierarchy:
1. Tags: explicit labels on the asset (highest precedence).
2. Hostname regex patterns: naming conventions (e.g. ^prd-.*, .*\\.corp).
3. Subnet CIDR ranges: network segment location (most specific CIDR wins).
4. Defaults (Medium criticality, unassigned team/env, internal exposure).
"""

import ipaddress
import json
import logging
import re
from typing import Any

from sqlalchemy import String, cast

from app.core.config import settings
from app.models.asset import Asset, Criticality

logger = logging.getLogger(__name__)

DEFAULT_CRITICALITY = Criticality.medium


def criticality_for(
    ip_address: str | None,
    hostname: str | None = None,
    tags: list[str] | None = None,
) -> Criticality:
    """Business criticality for an asset.

    Precedence:
    1. Tag rules (CRITICALITY_TAG_RULES)
    2. Hostname regex rules (CRITICALITY_HOSTNAME_RULES)
    3. Subnet CIDR rules (CRITICALITY_RULES, most specific prefix wins)
    4. Default: Medium
    """
    level = _match_tag(settings.CRITICALITY_TAG_RULES, tags, "CRITICALITY_TAG_RULES")
    if level is not None:
        return _as_criticality(level, "CRITICALITY_TAG_RULES")

    level = _match_hostname(
        settings.CRITICALITY_HOSTNAME_RULES, hostname, "CRITICALITY_HOSTNAME_RULES"
    )
    if level is not None:
        return _as_criticality(level, "CRITICALITY_HOSTNAME_RULES")

    level = _most_specific(settings.CRITICALITY_RULES, ip_address, "CRITICALITY_RULES")
    return _as_criticality(level, "CRITICALITY_RULES")


def owner_team_for(
    ip_address: str | None,
    hostname: str | None = None,
    tags: list[str] | None = None,
) -> str | None:
    """The team in charge of an asset; None if unmatched.

    Precedence:
    1. Tag rules (OWNER_TEAM_TAG_RULES)
    2. Hostname regex rules (OWNER_TEAM_HOSTNAME_RULES)
    3. Subnet CIDR rules (OWNER_TEAM_RULES, most specific prefix wins)
    """
    team = _match_tag(settings.OWNER_TEAM_TAG_RULES, tags, "OWNER_TEAM_TAG_RULES")
    if team is not None:
        team_str = str(team).strip()
        return team_str[:128] or None

    team = _match_hostname(
        settings.OWNER_TEAM_HOSTNAME_RULES, hostname, "OWNER_TEAM_HOSTNAME_RULES"
    )
    if team is not None:
        team_str = str(team).strip()
        return team_str[:128] or None

    team = _most_specific(settings.OWNER_TEAM_RULES, ip_address, "OWNER_TEAM_RULES")
    team_str = str(team).strip() if team else ""
    return team_str[:128] or None


def environment_for(
    ip_address: str | None,
    hostname: str | None = None,
    tags: list[str] | None = None,
) -> str | None:
    """The environment of an asset (production, staging...); None if unmatched.

    Precedence:
    1. Tag rules (ENVIRONMENT_TAG_RULES)
    2. Hostname regex rules (ENVIRONMENT_HOSTNAME_RULES)
    3. Subnet CIDR rules (ENVIRONMENT_RULES, most specific prefix wins)
    """
    value = _match_tag(settings.ENVIRONMENT_TAG_RULES, tags, "ENVIRONMENT_TAG_RULES")
    if value is not None:
        val_str = str(value).strip()
        return val_str[:32] or None

    value = _match_hostname(
        settings.ENVIRONMENT_HOSTNAME_RULES, hostname, "ENVIRONMENT_HOSTNAME_RULES"
    )
    if value is not None:
        val_str = str(value).strip()
        return val_str[:32] or None

    value = _most_specific(settings.ENVIRONMENT_RULES, ip_address, "ENVIRONMENT_RULES")
    val_str = str(value).strip() if value else ""
    return val_str[:32] or None


def exposure_for(
    ip_address: str | None,
    hostname: str | None = None,
    tags: list[str] | None = None,
) -> bool:
    """Whether an asset is exposed to the Internet.

    Precedence:
    1. Tag match (INTERNET_FACING_TAGS)
    2. Hostname regex match (INTERNET_FACING_HOSTNAME_PATTERNS)
    3. Subnet CIDR match (INTERNET_FACING_SUBNETS)
    """
    if tags and settings.INTERNET_FACING_TAGS:
        normalized_tags = {str(t).strip().lower() for t in tags if t}
        for exposed_tag in settings.INTERNET_FACING_TAGS:
            if str(exposed_tag).strip().lower() in normalized_tags:
                return True

    if hostname and settings.INTERNET_FACING_HOSTNAME_PATTERNS:
        hostname_clean = str(hostname).strip()
        for pattern in settings.INTERNET_FACING_HOSTNAME_PATTERNS:
            try:
                if re.search(pattern, hostname_clean, re.IGNORECASE):
                    return True
            except re.error:
                logger.warning(
                    "Ignoring malformed regex in INTERNET_FACING_HOSTNAME_PATTERNS: %r",
                    pattern,
                )
                continue

    return _exposure_by_subnet(ip_address)


def has_tag(tag: str):
    """SQL condition: the asset carries ``tag``, whatever its case.

    The tags are a JSON list, read as text: the quotes around the tag make it
    match a whole tag ("web", not "webapp"). Case is ignored as the rules
    ignore it, and the same on SQLite and PostgreSQL, whose LIKE differ there;
    % and _ in a tag are escaped, so "pci_dss" does not match "pciXdss".
    """
    return cast(Asset.tags, String).icontains(json.dumps(tag.strip()), autoescape=True)


def _match_tag(rules: dict | None, tags: list[str] | None, name: str) -> Any | None:
    """The value of the first rule matching any of the asset's tags."""
    if not rules or not tags:
        return None
    normalized_tags = {str(t).strip().lower() for t in tags if t}
    for tag_key, value in rules.items():
        if str(tag_key).strip().lower() in normalized_tags:
            return value
    return None


def _match_hostname(rules: dict | None, hostname: str | None, name: str) -> Any | None:
    """The value of the first rule whose regex pattern matches the hostname."""
    if not rules or not hostname:
        return None
    hostname_clean = str(hostname).strip()
    for pattern, value in rules.items():
        try:
            if re.search(pattern, hostname_clean, re.IGNORECASE):
                return value
        except re.error:
            logger.warning("Ignoring malformed regex pattern in %s: %r", name, pattern)
            continue
    return None


def _most_specific(rules: dict | None, ip_address: str | None, name: str) -> Any | None:
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


def _exposure_by_subnet(ip_address: str | None) -> bool:
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


def _as_criticality(
    level: str | None, source_name: str = "CRITICALITY_RULES"
) -> Criticality:
    if not level:
        return DEFAULT_CRITICALITY
    try:
        return Criticality(str(level).strip().capitalize())
    except ValueError:
        logger.warning("Ignoring unknown criticality in %s: %r", source_name, level)
        return DEFAULT_CRITICALITY
