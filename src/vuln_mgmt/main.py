"""ASGI entrypoint."""

from vuln_mgmt.app import create_app

app = create_app()

