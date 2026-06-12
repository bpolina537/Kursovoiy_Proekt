.PHONY: test lint format security run

test:
\tpytest

lint:
\truff check src tests

security:
\tbandit -r src

format:
\tblack src tests

run:
\tuvicorn vuln_mgmt.main:app --reload
