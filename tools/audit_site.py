#!/usr/bin/env python3
"""Offline, fail-closed support-site link, privacy-text and semantic audit.

Run from a checked-out site: python tools/audit_site.py --root .
This checks *website files and stated policies only*. It cannot prove an app's
network behavior, server logging behavior, purchase integrations, or legal compliance.
No file is uploaded and no URL is fetched by this tool.
"""
from __future__ import annotations

import argparse
from collections import defaultdict, deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

HTML_END_TAGS = frozenset({
    "html", "head", "body", "main", "header", "footer", "nav", "section",
    "article", "aside", "h1", "h2", "h3", "h4", "h5", "h6", "p",
    "a", "div", "span", "ul", "ol", "li", "strong", "em", "blockquote",
    "style", "title", "table", "tr", "td", "th", "button", "label",
})
VOID_TAGS = frozenset({"meta", "link", "br", "hr", "img", "input", "area", "source", "wbr"})
FORBIDDEN_ACTIVE_TAGS = frozenset({
    "script", "iframe", "form", "object", "embed", "video", "audio", "source",
    "track", "canvas", "svg", "base", "meta-http-equiv",
})
NETWORK_CSS = re.compile(r"@import\b|\burl\s*\(", re.IGNORECASE)
# Positive statements about tracking/collection that contradict the published
# negative assurances. The phrase contract provides the stricter primary check.
CONTRADICTIONS = (
    ("affirmative_data_collection", re.compile(r"\bwe\s+(?:collect|sell|share|track|transmit|upload)\s+(?:personal|learner|child|user)\s+(?:data|information)\b", re.I)),
    ("affirmative_analytics", re.compile(r"\b(?:we\s+(?:use|run|enable)|the\s+(?:app|site)\s+(?:uses|runs|enables))\s+(?:third.party\s+)?analytics\b", re.I)),
    ("affirmative_advertising", re.compile(r"\b(?:we\s+(?:use|run|display)|the\s+(?:app|site)\s+(?:uses|displays))\s+(?:targeted\s+)?(?:ads|advertising)\b", re.I)),
    ("affirmative_account", re.compile(r"\b(?:accounts\s+are\s+required|you\s+must\s+create\s+an\s+account)\b", re.I)),
)


def normalize(text: str) -> str:
    """Normalize punctuation, case and whitespace without changing word order."""
    return " ".join(re.findall(r"\w+", text.casefold(), re.UNICODE))


@dataclass(frozen=True, order=True)
class Finding:
    route: str
    code: str
    detail: str


@dataclass
class ParsedPage:
    route: str
    html: str
    title: str = ""
    text: str = ""
    html_lang: str = ""
    meta_charset: bool = False
    viewport: bool = False
    main_count: int = 0
    h1_count: int = 0
    headings: list[int] = field(default_factory=list)
    ids: set[str] = field(default_factory=set)
    refs: list[tuple[str, str]] = field(default_factory=list)
    anchors: list[tuple[str, str, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def fail(self, code: str, detail: str) -> None:
        self.findings.append(Finding(self.route, code, detail))


class PageParser(HTMLParser):
    """Purpose-built semantic HTML inspector (not a full HTML5 conformance parser)."""

    def __init__(self, route: str, html: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page = ParsedPage(route=route, html=html)
        self._stack: list[str] = []
        self._texts: list[str] = []
        self._title_parts: list[str] = []
        self._styles: list[str] = []
        self._in_title = False
        self._in_style = False
        self._in_head = False
        self._in_main = False

    def handle_decl(self, decl: str) -> None:
        if decl.strip().lower() != "doctype html":
            self.page.fail("doctype", "Unexpected document declaration")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if len(attr) != len(attrs):
            self.page.fail("duplicate_attribute", f"<{tag}> repeats an attribute")
        if tag == "html":
            self.page.html_lang = attr.get("lang", "") or ""
        elif tag == "head":
            self._in_head = True
        elif tag == "main":
            self.page.main_count += 1
            self._in_main = True
        elif tag == "title":
            self._in_title = True
        elif tag == "style":
            self._in_style = True
        elif tag == "meta":
            if (attr.get("charset") or "").casefold() == "utf-8":
                self.page.meta_charset = True
            if (attr.get("name") or "").casefold() == "viewport" and attr.get("content"):
                self.page.viewport = True
            if attr.get("http-equiv"):
                self.page.fail("active_meta", "HTTP-equivalent meta directives require manual review")
        elif tag == "link":
            # External links in <a> are click-only; external dependencies are not.
            href = attr.get("href") or ""
            rels = set((attr.get("rel") or "").lower().split())
            if "canonical" in rels:
                self.page.fail("canonical_metadata", "Use canonical file routes, not remote canonical metadata")
            elif href or any(rel in rels for rel in ("preconnect", "dns-prefetch", "preload", "prefetch")):
                self.page.fail("resource_link", "External or automatic link resources are not part of this static contract")
        elif tag == "img":
            if "alt" not in attr:
                self.page.fail("image_alt", "Image has no alt attribute")
            src = attr.get("src") or ""
            if src.startswith(("https:", "http:", "//", "data:")):
                self.page.fail("remote_resource", "Image uses an external or data URI")
            elif src:
                self.page.refs.append(("image", src))
        elif tag == "a":
            self.page.anchors.append((attr.get("href") or "", attr.get("target") or "", attr.get("rel") or ""))
            if not attr.get("href"):
                self.page.fail("empty_link", "Anchor has no href")
        elif tag in FORBIDDEN_ACTIVE_TAGS:
            self.page.fail("active_element", f"<{tag}> is disallowed on the zero-telemetry site")
        if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            n = int(tag[1])
            self.page.headings.append(n)
            if n == 1:
                self.page.h1_count += 1
            if not self._in_main:
                self.page.fail("heading_outside_main", f"<{tag}> must be inside <main>")
        identifier = attr.get("id")
        if identifier is not None:
            if not identifier.strip() or identifier in self.page.ids:
                self.page.fail("duplicate_or_empty_id", f"Invalid or duplicate id: {identifier!r}")
            self.page.ids.add(identifier)
        for name in ("aria-labelledby", "aria-describedby"):
            if name in attr:
                for ref in (attr[name] or "").split():
                    self.page.refs.append((name, ref))
        for k, value in attrs:
            if k.startswith("on") and len(k) > 2:
                self.page.fail("event_handler", f"Event attribute {k!r} is disallowed")
            if k == "style" and value and NETWORK_CSS.search(value):
                self.page.fail("style_network", "Inline style has URL/import usage")
        if tag not in VOID_TAGS:
            self._stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in HTML_END_TAGS:
            if tag not in self._stack:
                self.page.fail("tag_balance", f"Unmatched closing </{tag}>")
            elif self._stack[-1] == tag:
                self._stack.pop()
            else:
                self.page.fail("tag_balance", f"Non-nested closing </{tag}>")
                # Recover so subsequent structure can still be inspected.
                while self._stack and self._stack[-1] != tag:
                    self._stack.pop()
                if self._stack:
                    self._stack.pop()
        if tag == "head":
            self._in_head = False
        elif tag == "main":
            self._in_main = False
        elif tag == "title":
            self._in_title = False
        elif tag == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)
        elif self._in_style:
            self._styles.append(data)
        elif not self._in_head:
            self._texts.append(data)

    def finish(self) -> ParsedPage:
        page = self.page
        page.title = " ".join(self._title_parts).strip()
        page.text = " ".join(self._texts)
        if not re.match(r"\s*<!doctype\s+html\s*>", page.html, flags=re.I):
            page.fail("doctype", "Missing HTML5 doctype")
        if not page.html_lang.strip():
            page.fail("language", "Missing <html lang>")
        if not page.meta_charset:
            page.fail("charset", "Missing UTF-8 charset")
        if not page.viewport:
            page.fail("viewport", "Missing viewport declaration")
        if not page.title:
            page.fail("title", "Empty <title>")
        if page.main_count != 1:
            page.fail("main", f"Expected exactly one <main>, got {page.main_count}")
        if page.h1_count != 1:
            page.fail("h1", f"Expected exactly one <h1>, got {page.h1_count}")
        prev = 0
        for level in page.headings:
            if prev and level > prev + 1:
                page.fail("heading_order", f"Heading jumps from h{prev} to h{level}")
            prev = level
        for style in self._styles:
            if NETWORK_CSS.search(style):
                page.fail("css_network", "CSS import/url reference not allowed in offline support pages")
        for typ, ref in page.refs:
            if typ.startswith("aria-") and ref not in page.ids:
                page.fail("aria_reference", f"Unknown {typ} target: {ref!r}")
        if any(t in self._stack for t in ("html", "body", "head", "main")):
            page.fail("tag_balance", "Structural element not closed")
        return page


def parse_page(route: str, contents: str) -> ParsedPage:
    parser = PageParser(route, contents)
    try:
        parser.feed(contents)
        parser.close()
    except (ValueError, AssertionError) as exc:
        parser.page.fail("parse", str(exc))
    return parser.finish()


def resolve_link(route: str, href: str, canonical: set[str]) -> tuple[str | None, str | None]:
    """Return (canonical destination, error). Never touches disk or network."""
    if any(ord(c) < 32 for c in href) or "\\" in href:
        return None, "Control or backslash in href"
    if href.startswith("//"):
        return None, "Protocol-relative destination disallowed"
    parts = urlsplit(href)
    if parts.scheme:
        if parts.scheme == "https" and parts.netloc:
            return None, None  # Explicit user-click navigation only.
        if parts.scheme in ("mailto", "tel") and parts.path:
            return None, None
        return None, f"Unsupported or insecure link scheme {parts.scheme!r}"
    if parts.netloc:
        return None, "Network destination disallowed"
    if parts.query:
        return None, "Query parameters are not canonical static routes"
    path = unquote(parts.path)
    if "%" in path or path.startswith("/") or "\\" in path or "?" in path or "#" in path:
        return None, "Unsafe or noncanonical destination"
    segments = path.split("/")
    if any(segment in ("..", ".") for segment in segments):
        return None, "Dot-segment or parent traversal disallowed"
    if path and path not in canonical:
        return None, f"Unknown canonical file route {path!r}"
    return path or route, None


def load_contract(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported site contract schema version")
    routes = data.get("canonical_routes")
    if not isinstance(routes, list) or len(routes) != len(set(routes)) or not routes:
        raise ValueError("canonical_routes must be a nonempty unique list")
    if any(not isinstance(r, str) or not re.fullmatch(r"[a-z0-9-]+\.html", r) for r in routes):
        raise ValueError("Canonical routes must be simple lowercase HTML filenames")
    if data.get("entrypoint") not in routes:
        raise ValueError("Entrypoint must be canonical")
    direct = data.get("required_direct_links")
    if not isinstance(direct, dict) or any(
        source not in routes or not isinstance(targets, list) or
        not targets or any(target not in routes or target == source for target in targets)
        for source, targets in direct.items()
    ):
        raise ValueError("Invalid required_direct_links")
    contacts = data.get("contact_routes")
    if not isinstance(contacts, list) or not contacts or any(route not in routes for route in contacts):
        raise ValueError("Invalid contact_routes")
    claims = data.get("required_claims")
    if not isinstance(claims, dict) or set(claims) != set(routes):
        raise ValueError("Claim groups must match canonical routes")
    for route, group in claims.items():
        if not isinstance(group, dict) or not group:
            raise ValueError(f"Missing claim group for {route}")
        if any(not isinstance(k, str) or not isinstance(v, str) or not v.strip() for k, v in group.items()):
            raise ValueError(f"Invalid claim in {route}")
    concepts = data.get("required_privacy_policy_concepts", [])
    if any(k not in claims.get("privacy-policy.html", {}) for k in concepts):
        raise ValueError("A required privacy policy concept is missing")
    return data


def audit_site(root: Path, contract: dict) -> list[Finding]:
    """Audit a local copy only; all errors are returned as structured findings."""
    root = root.resolve()
    routes = contract["canonical_routes"]
    canonical = set(routes)
    findings: list[Finding] = []
    pages: dict[str, ParsedPage] = {}
    edge_map: dict[str, set[str]] = defaultdict(set)

    for route in routes:
        target = root / route
        if not target.is_file() or target.is_symlink():
            findings.append(Finding(route, "missing_route", "Canonical page missing or is a symlink"))
            continue
        try:
            page = parse_page(route, target.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as exc:
            findings.append(Finding(route, "unreadable_route", type(exc).__name__))
            continue
        pages[route] = page
        findings.extend(page.findings)
        page_text = normalize(page.text)
        for key, claim in contract["required_claims"][route].items():
            if normalize(claim) not in page_text:
                findings.append(Finding(route, "missing_claim", f"{key}: published assurance missing/changed"))
        for key, pattern in CONTRADICTIONS:
            if pattern.search(page.text):
                findings.append(Finding(route, "policy_contradiction", key))
        if route in ("privacy-policy.html", "terms-of-use.html") and "last updated" not in page_text:
            findings.append(Finding(route, "revision_date", "Legal page lacks a revision label"))
        if route in contract["contact_routes"] and not any(
            href.startswith("mailto:") for href, _, _ in page.anchors
        ):
            findings.append(Finding(route, "contact", "Required contact mail link missing"))
        for href, target_blank, rel in page.anchors:
            destination, error = resolve_link(route, href, canonical)
            if error:
                findings.append(Finding(route, "link", f"{href!r}: {error}"))
                continue
            if target_blank == "_blank" and not {"noopener", "noreferrer"} <= set(rel.lower().split()):
                findings.append(Finding(route, "external_blank", "New-window link must have noopener noreferrer"))
            if destination:
                edge_map[route].add(destination)
                parts = urlsplit(href)
                if parts.fragment and destination in pages:
                    if unquote(parts.fragment) not in pages[destination].ids:
                        findings.append(Finding(route, "fragment", f"Unresolved fragment {href!r}"))
        for typ, ref in page.refs:
            if typ == "image":
                findings.append(Finding(route, "image_dependency", "Non-HTML resources need explicit offline review"))

    # Check fragment targets again after all pages have been parsed; this also
    # covers forward references to pages appearing later in the contract.
    for route, page in pages.items():
        for href, _, _ in page.anchors:
            destination, error = resolve_link(route, href, canonical)
            if not error and destination and urlsplit(href).fragment:
                fragment = unquote(urlsplit(href).fragment)
                if destination in pages and fragment not in pages[destination].ids:
                    finding = Finding(route, "fragment", f"Unresolved fragment {href!r}")
                    if finding not in findings:
                        findings.append(finding)

    for source, targets in contract["required_direct_links"].items():
        if source in pages:
            for target in targets:
                if target not in edge_map[source]:
                    findings.append(Finding(source, "direct_navigation", f"Missing direct link to {target}"))

    entry = contract["entrypoint"]
    reached = {entry}
    queue = deque([entry])
    while queue:
        current = queue.popleft()
        for dest in edge_map[current] - reached:
            reached.add(dest)
            queue.append(dest)
    for route in sorted(canonical - reached):
        findings.append(Finding(route, "unreachable", "No navigation path from the canonical entrypoint"))
    return sorted(set(findings))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline canonical-route, policy and semantic HTML auditor")
    parser.add_argument("--root", type=Path, default=Path("."), help="Local site checkout")
    parser.add_argument("--contract", type=Path, default=Path(__file__).resolve().parents[1] / "site_contract.json")
    parser.add_argument("--json", action="store_true", help="Print machine-readable findings")
    args = parser.parse_args(argv)
    try:
        contract = load_contract(args.contract)
        results = audit_site(args.root, contract)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"FAIL CONTRACT: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"all": not results, "findings": [vars(f) for f in results]}, indent=2, ensure_ascii=False))
    else:
        for f in results:
            print(f"FAIL {f.route}: {f.code}: {f.detail}")
        print(f"ALL={'true' if not results else 'false'}")
    return 1 if results else 0


if __name__ == "__main__":
    raise SystemExit(main())
