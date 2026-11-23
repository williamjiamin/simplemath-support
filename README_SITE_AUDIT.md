# Offline support-site audit

This private-draft patch adds a **read-only** audit to an existing four-page static support site. It does not replace the pages, fetch remote content, modify the app, create a user account, or deploy anything.

## Canonical routes

The only local HTML destinations are `index.html`, `support.html`, `privacy-policy.html`, and `terms-of-use.html`. The site contract is in `site_contract.json`; edit it and the corresponding user-facing text together, then review the resulting policy change before release.

Relative links, fragments, contact links, and explicitly clicked secure external links are supported. Local aliases, query parameters, missing files, unsafe schemes, path traversal, broken anchors, and unreachable required pages fail the audit. Click-only external destinations cannot be verified offline.

## Run from the site checkout

```sh
python tools/audit_site.py --root .
python tools/audit_site.py --root . --json
python -m pytest tests/test_audit_site.py -q
```

The command returns exit status `0` when all checks pass, `1` for website findings, or `2` for a broken audit configuration. Human-readable output ends in `ALL=true` or `ALL=false` on a valid configuration. The test suite creates its own small temporary site, so it can run without network access.

## What is checked

- Exact canonical local routes and internal navigation reachability.
- Homepage direct links to support, privacy, and terms; support links to privacy and terms.
- Each legal/support page's contact link, accessible heading structure, the HTML5 doctype, language, viewport, title, unique IDs, referenced labels, and image descriptions.
- Absence of active scripts, forms, embedded frames, automatic resource links, inline event handlers, and CSS URL imports in the static pages.
- Presence of the existing published statements about on-device progress, child information, account-free learning, no advertising/analytics/tracking, the limited parent-initiated store exception, and the adult purchase gate.
- Explicit positive statements that contradict privacy assurances are also rejected.

## Scope and limits

This is a **static consistency and regression audit**, not a network or legal certification. Policy words are only checked for presence and selected contradictions. The audit **does not** prove that the separate app honors those words, that servers retain no request logs, that transactions never contact a purchase service, or that all applicable children's privacy requirements are satisfied. Those questions require independent app binary/network inspection and legal review.

No game code or runtime website markup changes are included. Thus no game-feature flag, kill switch, rendering comparison, or game test-hub registration applies. Site rendering remains identical because the four existing HTML pages are left untouched.
