"""The security headers reach every response Nginx serves.

Nginx drops the server's ``add_header`` directives in any location that
declares one of its own. ``location /`` set Cache-Control, and index.html
went out without CSP or X-Frame-Options (audit of 09/10/2026). The headers
now live in one file, included by the server and again by every location
that adds a header. Read statically: no Nginx is needed. The production
stack test (scripts/smoke_prod_stack.sh) checks the real responses.
"""

import re
from pathlib import Path

FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
SNIPPET_PATH = "/etc/nginx/vigie-security-headers.conf"
INCLUDE = f"include {SNIPPET_PATH};"
HEADERS = (
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def blocks(text: str, keyword: str) -> list[tuple[str, str]]:
    """(header line, body) of each ``keyword ... { ... }`` block, braces matched."""
    found = []
    for match in re.finditer(rf"^\s*{keyword}\b([^{{]*)\{{", text, re.M):
        depth, start = 1, match.end()
        position = start
        while depth:
            char = text[position]
            depth += {"{": 1, "}": -1}.get(char, 0)
            position += 1
        found.append((match.group(1).strip(), text[start : position - 1]))
    return found


def strip_comments(text: str) -> str:
    return re.sub(r"#.*", "", text)


def test_the_snippet_sets_every_security_header_always():
    snippet = strip_comments((FRONTEND / "security-headers.conf").read_text())

    for header in HEADERS:
        assert re.search(rf'^add_header {header} ".+" always;$', snippet, re.M), header


def test_the_image_installs_the_snippet_where_nginx_conf_includes_it():
    dockerfile = (FRONTEND / "Dockerfile.prod").read_text()

    assert f"COPY security-headers.conf {SNIPPET_PATH}" in dockerfile


def test_the_server_includes_the_headers():
    config = strip_comments((FRONTEND / "nginx.conf").read_text())
    [(_, server)] = blocks(config, "server")
    # The server's own directives: its body without the location blocks.
    own = re.sub(r"location\b[^{]*\{[^{}]*\}", "", server)

    assert INCLUDE in own
    # Headers set here directly would not reach the locations either.
    assert "add_header" not in own


def test_every_location_adding_a_header_includes_them_again():
    config = strip_comments((FRONTEND / "nginx.conf").read_text())
    locations = blocks(config, "location")

    assert locations, "no location block found"
    for where, body in locations:
        if "add_header" in body:
            assert INCLUDE in body, f"location {where} drops the security headers"
