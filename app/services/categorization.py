"""What kind of software a finding hits, and what kind of host it sits on.

Scanners each have their own families (Nessus alone has about fifty, and its
"Windows" family holds third-party Windows applications), which make a poor
axis for a matrix. Findings are folded into a short, fixed taxonomy instead,
from the words of the finding's title first and the scanner family second.
The rules are ordered: "Microsoft Edge" is a browser before it is Windows,
".NET Framework" a runtime before it is Microsoft.

Pure functions: the ingestion, the daily pass and the migration that
backfilled existing findings all use them.
"""

import re

UNCATEGORIZED = "uncategorized"

# Key -> label, in display order.
VULN_CATEGORIES = {
    "operating_system": "Operating system",
    "browser": "Browser",
    "office": "Office & productivity",
    "runtime": "Runtime & framework",
    "database": "Database",
    "web_server": "Web & application server",
    "network_device": "Network & security device",
    "remote_access": "Remote access & VPN",
    "application": "Other application",
    UNCATEGORIZED: "Uncategorized",
}


def _words(*patterns: str) -> re.Pattern:
    # Lookarounds rather than \b: \b needs a word character next to it, so it
    # would never match ".NET" after a space, nor "C++" before one.
    return re.compile(r"(?<!\w)(?:" + "|".join(patterns) + r")(?!\w)", re.IGNORECASE)


# Matched against the title, in this order.
TITLE_RULES: tuple[tuple[str, re.Pattern], ...] = (
    (
        "browser",
        _words(
            r"Google Chrome",
            r"Chromium",
            r"Microsoft Edge",
            r"Firefox",
            r"Safari",
            r"Internet Explorer",
            r"Opera",
            r"Brave",
        ),
    ),
    (
        "office",
        _words(
            r"Microsoft Office",
            r"Office",
            r"Excel",
            r"Word",
            r"Outlook",
            r"PowerPoint",
            r"SharePoint",
            r"Exchange",
            r"Visio",
            r"OneNote",
            r"LibreOffice",
            r"OpenOffice",
            r"Adobe (?:Acrobat|Reader)",
            r"Foxit",
            r"Teams",
            r"Zoom",
        ),
    ),
    (
        "runtime",
        _words(
            r"\.NET",
            r"ASP\.NET",
            r"Java",
            r"JDK",
            r"JRE",
            r"OpenJDK",
            r"Node\.js",
            r"PHP",
            r"Python",
            r"Ruby",
            r"Perl",
            r"OpenSSL",
            r"Log4j",
            r"Spring",
            r"Visual C\+\+",
            r"Struts",
        ),
    ),
    (
        "database",
        _words(
            r"MySQL",
            r"MariaDB",
            r"PostgreSQL",
            r"SQL Server",
            r"Oracle Database",
            r"MongoDB",
            r"Redis",
            r"Elasticsearch",
            r"SQLite",
            r"Cassandra",
            r"DB2",
        ),
    ),
    (
        "web_server",
        _words(
            r"Apache HTTP",
            r"Apache httpd",
            r"Apache",
            r"httpd",
            r"nginx",
            r"IIS",
            r"Tomcat",
            r"JBoss",
            r"WildFly",
            r"WebLogic",
            r"WebSphere",
            r"Jetty",
            r"lighttpd",
            r"Confluence",
            r"Jira",
            r"GitLab",
            r"WordPress",
            r"Drupal",
        ),
    ),
    (
        "network_device",
        _words(
            r"Cisco",
            r"IOS XE",
            r"Juniper",
            r"Junos",
            r"Fortinet",
            r"FortiOS",
            r"FortiGate",
            r"PAN-OS",
            r"Palo Alto",
            r"F5",
            r"BIG-IP",
            r"MikroTik",
            r"SonicWall",
            r"Check Point",
            r"Aruba",
            r"Ubiquiti",
            r"Arista",
        ),
    ),
    (
        "remote_access",
        _words(
            r"VPN",
            r"Citrix",
            r"NetScaler",
            r"Remote Desktop",
            r"RDP",
            r"OpenSSH",
            r"SSH",
            r"VNC",
            r"TeamViewer",
            r"AnyConnect",
            r"GlobalProtect",
            r"Ivanti",
            r"Pulse Secure",
            r"AnyDesk",
        ),
    ),
    (
        "operating_system",
        _words(
            r"Windows",
            r"Linux kernel",
            r"kernel",
            r"macOS",
            r"Mac OS X",
            r"glibc",
            r"systemd",
            r"sudo",
            r"Ubuntu",
            r"Debian",
            r"Red Hat",
            r"RHEL",
            r"CentOS",
            r"SUSE",
            r"Fedora",
            r"AIX",
            r"Solaris",
            r"FreeBSD",
            r"ESXi",
        ),
    ),
)

# Scanner families, when the title said nothing recognisable.
FAMILY_RULES: tuple[tuple[str, re.Pattern], ...] = (
    ("web_server", _words(r"Web Servers", r"CGI abuses", r"Web application abuses")),
    ("database", _words(r"Databases")),
    (
        "network_device",
        _words(
            r"CISCO",
            r"Firewalls",
            r"Junos Local Security Checks",
            r"F5 Networks Local Security Checks",
            r"Palo Alto Local Security Checks",
            r"Fortinet",
            r"Huawei",
        ),
    ),
    # Not the bare "Windows" family: Nessus files third-party Windows
    # programs (7-Zip, Notepad++) there, which are applications.
    (
        "operating_system",
        _words(
            r"Local Security Checks",
            r"Microsoft Bulletins",
            r"Gain a shell remotely",
            r"Operating system",
        ),
    ),
)


def classify_finding(title: str | None, families=()) -> str:
    """The category of a finding, from its title and its scanner families."""
    text = title or ""
    for category, pattern in TITLE_RULES:
        if pattern.search(text):
            return category
    for family in families:
        if not family:
            continue
        for category, pattern in FAMILY_RULES:
            if pattern.search(family):
                return category
    if any(families) or (text and not text.upper().startswith("CVE-")):
        # Something named, just not in the taxonomy: a third-party program.
        return "application"
    return UNCATEGORIZED


# --- asset types --------------------------------------------------------------

ASSET_TYPES = {
    "server": "Server",
    "workstation": "Workstation",
    "network": "Network device",
    "cloud": "Cloud resource",
    "ot": "OT / industrial",
    "other": "Other",
}

_NETWORK_OS = _words(
    r"Cisco",
    r"IOS XE",
    r"IOS XR",
    r"NX-OS",
    r"Junos",
    r"FortiOS",
    r"PAN-OS",
    r"MikroTik",
    r"RouterOS",
    r"BIG-IP",
    r"SonicOS",
    r"Arista",
    r"switch",
    r"router",
    r"firewall",
)
_SERVER_OS = _words(
    r"Windows Server",
    r"Server",
    r"ESXi",
    r"VMware",
    r"Ubuntu",
    r"Debian",
    r"Red Hat",
    r"RHEL",
    r"CentOS",
    r"Rocky",
    r"AlmaLinux",
    r"SUSE",
    r"Oracle Linux",
    r"Amazon Linux",
    r"Linux",
    r"AIX",
    r"Solaris",
    r"FreeBSD",
)
_WORKSTATION_OS = _words(r"Windows", r"macOS", r"Mac OS X", r"ChromeOS")


def asset_type_for(operating_system: str | None) -> str | None:
    """A host's type from its operating system; None when it cannot tell.

    Network equipment first (its OS names often contain "Server" nowhere, but
    a Cisco box must not pass for a Linux server), then servers, then desktops:
    "Windows Server 2019" is a server before it is Windows.
    """
    if not operating_system:
        return None
    if _NETWORK_OS.search(operating_system):
        return "network"
    if _SERVER_OS.search(operating_system):
        return "server"
    if _WORKSTATION_OS.search(operating_system):
        return "workstation"
    return None


# Answers that say little: any named category is preferred to them.
_VAGUE = {None, UNCATEGORIZED, "application"}


def more_specific(current: str | None, new: str | None) -> str | None:
    """Keep a precise category against a vaguer one from another check."""
    if new in _VAGUE and current not in _VAGUE:
        return current
    if new is None:
        return current
    if current == "application" and new == UNCATEGORIZED:
        return current
    return new


def categorize_missing(db, batch_size: int = 5_000) -> int:
    """Categorize findings that have no category yet, from what is stored.

    Findings ingested before categories existed, or by a path that set none,
    get one from their CVE title and their fixes' scanner families.
    """
    from app.models.remediation import FindingRemediation, RemediationAction
    from app.models.vulnerability import AssetVulnerability, Vulnerability

    done = 0
    while True:
        rows = (
            db.query(AssetVulnerability, Vulnerability.title)
            .join(Vulnerability, Vulnerability.id == AssetVulnerability.vulnerability_id)
            .filter(AssetVulnerability.category.is_(None))
            .limit(batch_size)
            .all()
        )
        if not rows:
            return done
        ids = [finding.id for finding, _ in rows]
        families: dict[int, list[str]] = {}
        for finding_id, family in (
            db.query(FindingRemediation.finding_id, RemediationAction.family)
            .join(RemediationAction, RemediationAction.id == FindingRemediation.action_id)
            .filter(FindingRemediation.finding_id.in_(ids))
        ):
            families.setdefault(finding_id, []).append(family)
        for finding, title in rows:
            finding.category = classify_finding(title, families.get(finding.id, ()))
        # The production session does not autoflush: without this, the next
        # batch would select the same rows again.
        db.flush()
        done += len(rows)
