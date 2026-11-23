.DEFAULT_GOAL := check
.PHONY: check test audit

check: test audit

test:
	python -m pytest -q tests/test_audit_site.py

audit:
	python tools/audit_site.py --root .
