"""Shared pytest setup.

The application module builds a module-level app for WSGI/CLI compatibility.
Redirect that import-time database initialization to a temporary location so
the test suite never touches the development database.
"""

import tempfile
from pathlib import Path

import config


_TEST_STARTUP_DIRECTORY = tempfile.TemporaryDirectory(
    prefix="identitytrail-test-startup-"
)

config.Config.DATABASE_PATH = str(
    Path(_TEST_STARTUP_DIRECTORY.name) / "identitytrail-startup.db"
)
