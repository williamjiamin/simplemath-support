"""Property-oriented regression tests; no live host or learner data needed."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

# Test imports work both inside the source patch and once copied to repo root.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from audit_site import audit_site, load_contract, normalize, parse_page, resolve_link  # noqa: E402


@pytest.fixture
def contract() -> dict:
    return load_contract(ROOT / "site_contract.json")


@pytest.fixture
def site(tmp_path: Path, contract: dict) -> Path:
    routes = contract["canonical_routes"]
    links = "\n".join(f'<a href="{route}">{route}</a>' for route in routes)
    for route in routes:
        claims = "\n".join(f"<p>{phrase}</p>" for phrase in contract["required_claims"][route].values())
        if route in ("privacy-policy.html", "terms-of-use.html"):
            claims += "\n<p>Last updated: November 22, 2026</p>"
        text = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Original Learning Support — {route}</title>
<style>body {{ margin: 0; }}</style></head>
<body><header><nav aria-label="Pages">{links}</nav></header>
<main id="main"><h1>{route}</h1><h2 id="faq">Help</h2>{claims}</main>
<footer><a href="index.html#main">Home</a></footer></body></html>
"""
        (tmp_path / route).write_text(text, encoding="utf-8")
    # Contact buttons are click-only and do not create site telemetry.
    for route in contract["contact_routes"]:
        path = tmp_path / route
        html = path.read_text(encoding="utf-8")
        path.write_text(html.replace("</main>", '<p><a href="mailto:help@example.invalid">Contact</a></p></main>'), encoding="utf-8")
    return tmp_path


def update(site: Path, route: str, before: str, after: str) -> None:
    path = site / route
    original = path.read_text(encoding="utf-8")
    assert before in original, before
    path.write_text(original.replace(before, after, 1), encoding="utf-8")


def codes(site: Path, contract: dict) -> set[str]:
    return {finding.code for finding in audit_site(site, contract)}


def test_complete_offline_site_passes(site: Path, contract: dict) -> None:
    assert audit_site(site, contract) == []


def test_cli_success_and_machine_readable_result(site: Path) -> None:
    command = [sys.executable, str(ROOT / "tools" / "audit_site.py"),
               "--root", str(site), "--json"]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(completed.stdout) == {"all": True, "findings": []}


@pytest.mark.parametrize("href", [
    "support", "/support.html", "./support.html", "../support.html",
    "support.html?tracking=1", "support.HTML", "missing.html", "//example.invalid/hit",
    "javascript:alert(1)", "http://example.invalid", "data:text/plain,hi",
    "%2e%2e/support.html", "%252e%252e/support.html", "support.html\\file",
])
def test_noncanonical_or_dangerous_links_rejected(href: str, contract: dict) -> None:
    _, failure = resolve_link("index.html", href, set(contract["canonical_routes"]))
    assert failure, href


@pytest.mark.parametrize("href", [
    "index.html", "support.html", "#main", "privacy-policy.html#policy",
    "https://example.invalid/legal", "mailto:help@example.invalid", "tel:+10000000000",
])
def test_safe_local_or_click_only_links(href: str, contract: dict) -> None:
    _, failure = resolve_link("index.html", href, set(contract["canonical_routes"]))
    assert failure is None, href


def test_missing_canonical_file_fails(site: Path, contract: dict) -> None:
    (site / "support.html").unlink()
    assert "missing_route" in codes(site, contract)


def test_broken_link_fails(site: Path, contract: dict) -> None:
    update(site, "index.html", 'href="support.html"', 'href="not-a-page.html"')
    assert "link" in codes(site, contract)


def test_direct_navigation_guard(site: Path, contract: dict) -> None:
    update(site, "index.html", '<a href="support.html">support.html</a>', '')
    assert "direct_navigation" in codes(site, contract)


def test_contact_link_required(site: Path, contract: dict) -> None:
    update(site, "support.html", 'href="mailto:help@example.invalid"', 'href="support.html"')
    assert "contact" in codes(site, contract)


def test_missing_fragment_fails(site: Path, contract: dict) -> None:
    update(site, "index.html", 'href="support.html"', 'href="support.html#missing"')
    assert "fragment" in codes(site, contract)


def test_cross_page_fragment_resolves(site: Path, contract: dict) -> None:
    update(site, "index.html", 'href="support.html"', 'href="support.html#faq"')
    assert "fragment" not in codes(site, contract)


def test_unreachable_route_fails(site: Path, contract: dict) -> None:
    # Remove links to terms from every page except the terms page itself.
    for route in contract["canonical_routes"]:
        if route != "terms-of-use.html":
            update(site, route, '<a href="terms-of-use.html">terms-of-use.html</a>', '')
    assert "unreachable" in codes(site, contract)


@pytest.mark.parametrize(("original", "replacement", "expected"), [
    ('<html lang="en">', '<html>', "language"),
    ('<meta charset="utf-8">', '', "charset"),
    ('<meta name="viewport" content="width=device-width, initial-scale=1">', '', "viewport"),
    ('<title>Original Learning Support — index.html</title>', '<title></title>', "title"),
    ('<main id="main">', '<div id="main">', "main"),
    ('<h1>index.html</h1>', '<h2>index.html</h2>', "h1"),
    ('<h2 id="faq">Help</h2>', '<h4 id="faq">Help</h4>', "heading_order"),
    ('id="faq"', 'id="main"', "duplicate_or_empty_id"),
    ('<nav aria-label="Pages">', '<nav aria-labelledby="unknown">', "aria_reference"),
    ('<a href="support.html">', '<a href="support.html" onclick="send()">', "event_handler"),
    ('<style>body { margin: 0; }</style>', '<style>@import "https://example.invalid/x";</style>', "css_network"),
    ('<style>body { margin: 0; }</style>', '<style>body { background: url(track.gif) }</style>', "css_network"),
    ('<h1>index.html</h1>', '<h1>index.html</h1><iframe src="https://example.invalid"></iframe>', "active_element"),
    ('<h1>index.html</h1>', '<h1>index.html</h1><script>fetch("/hit")</script>', "active_element"),
    ('<h1>index.html</h1>', '<h1>index.html</h1><img src="https://example.invalid/1">', "image_alt"),
    ('<h1>index.html</h1>', '<h1>index.html</h1><link rel="preconnect" href="https://example.invalid">', "resource_link"),
])
def test_semantic_and_telemetry_breaches_fail(site: Path, contract: dict,
                                               original: str, replacement: str,
                                               expected: str) -> None:
    update(site, "index.html", original, replacement)
    assert expected in codes(site, contract)


@pytest.mark.parametrize("route,key", [
    ("index.html", "no_tracking"),
    ("support.html", "offline_learning"),
    ("privacy-policy.html", "no_collection"),
    ("terms-of-use.html", "adult_gate"),
])
def test_missing_or_weakened_claim_fails(site: Path, contract: dict,
                                           route: str, key: str) -> None:
    text = contract["required_claims"][route][key]
    update(site, route, text, "Policy text removed for review")
    assert "missing_claim" in codes(site, contract)


@pytest.mark.parametrize("sentence", [
    "We collect personal data.",
    "We use third-party analytics.",
    "The app displays targeted ads.",
    "You must create an account.",
])
def test_affirmative_policy_contradictions_fail(site: Path, contract: dict, sentence: str) -> None:
    update(site, "privacy-policy.html", "</main>", f"<p>{sentence}</p></main>")
    assert "policy_contradiction" in codes(site, contract)


def test_explicit_external_link_is_click_only(site: Path, contract: dict) -> None:
    update(site, "terms-of-use.html", "</main>",
           '<p><a href="https://example.invalid/license">External terms</a></p></main>')
    assert codes(site, contract) == set()


def test_blank_target_needs_safe_rel(site: Path, contract: dict) -> None:
    update(site, "index.html", 'href="support.html"', 'href="support.html" target="_blank"')
    assert "external_blank" in codes(site, contract)
    update(site, "index.html", 'target="_blank"', 'target="_blank" rel="noopener noreferrer"')
    assert "external_blank" not in codes(site, contract)


def test_audit_never_uses_network(site: Path, contract: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    import socket
    def abort(*args: object, **kwargs: object) -> None:
        raise AssertionError("Network access forbidden in offline audit")
    monkeypatch.setattr(socket, "create_connection", abort)
    monkeypatch.setattr(socket, "socket", abort)
    assert audit_site(site, contract) == []


def test_invalid_contract_rejected(tmp_path: Path, contract: dict) -> None:
    contract["canonical_routes"].append("../unexpected.html")
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(contract), encoding="utf-8")
    with pytest.raises(ValueError, match="Canonical routes"):
        load_contract(path)


def test_contract_and_text_normalization(contract: dict) -> None:
    assert set(contract["required_claims"]) == set(contract["canonical_routes"])
    assert set(contract["required_claims"]["privacy-policy.html"]) >= {
        "no_collection", "no_ads_analytics_accounts", "no_learning_network",
        "adult_store_exception", "child_information", "local_progress"
    }
    assert contract["required_direct_links"]["index.html"] == [
        "support.html", "privacy-policy.html", "terms-of-use.html"
    ]
    assert normalize("No   tracking!  Child’s progress.") == "no tracking child s progress"


def test_unclosed_structure_fails() -> None:
    p = parse_page("index.html", '<!doctype html><html lang="en"><head></head><body><main><h1>Hi</h1>')
    assert "tag_balance" in {f.code for f in p.findings}
