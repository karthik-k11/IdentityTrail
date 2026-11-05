"""SQLite database foundation for IdentityTrail.

This module owns connection management and schema initialization. Flask route
handlers should use :func:`get_db` rather than creating connections directly.
"""

import sqlite3
from pathlib import Path

from flask import current_app, g


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS datasets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    file_size INTEGER NOT NULL DEFAULT 0 CHECK (file_size >= 0),
    total_events INTEGER NOT NULL DEFAULT 0 CHECK (total_events >= 0),
    parsed_events INTEGER NOT NULL DEFAULT 0 CHECK (parsed_events >= 0),
    failed_events INTEGER NOT NULL DEFAULT 0 CHECK (failed_events >= 0)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id INTEGER NOT NULL,
    event_id TEXT,
    event_time TEXT,
    event_name TEXT,
    event_source TEXT,
    aws_region TEXT,
    account_id TEXT,
    username TEXT,
    principal_arn TEXT,
    access_key_id TEXT,
    source_ip TEXT,
    user_agent TEXT,
    raw_event_json TEXT,
    normalized_event_json TEXT,
    FOREIGN KEY (dataset_id) REFERENCES datasets (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_events_dataset_event_id
    ON events (dataset_id, event_id)
    WHERE event_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_events_dataset_id
    ON events (dataset_id);

CREATE INDEX IF NOT EXISTS idx_events_event_time
    ON events (event_time);

CREATE INDEX IF NOT EXISTS idx_events_event_name
    ON events (event_name);

CREATE INDEX IF NOT EXISTS idx_events_username
    ON events (username);
"""


def get_connection(database_path):
    """Open a SQLite connection configured for IdentityTrail.

    The parent directory is created when missing. Foreign-key enforcement is a
    per-connection SQLite setting, so it is enabled for every new connection.
    """
    path = Path(database_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(path), timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db(database_path):
    """Create the IdentityTrail schema if it does not already exist."""
    connection = get_connection(database_path)
    try:
        connection.executescript(SCHEMA_SQL)
        connection.commit()
    finally:
        connection.close()


def get_db():
    """Return the request-scoped database connection, opening it if needed."""
    if "db" not in g:
        g.db = get_connection(current_app.config["DATABASE_PATH"])
    return g.db


def close_db(exception=None):
    """Close the request-scoped database connection, if one was opened."""
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_app(app):
    """Register database lifecycle hooks and initialize the configured DB."""
    app.teardown_appcontext(close_db)
    init_db(app.config["DATABASE_PATH"])


def insert_dataset(
    connection,
    filename,
    file_size=0,
    total_events=0,
    parsed_events=0,
    failed_events=0,
):
    """Insert dataset metadata and return the new dataset ID."""
    with connection:
        cursor = connection.execute(
            """
            INSERT INTO datasets (
                filename,
                file_size,
                total_events,
                parsed_events,
                failed_events
            )
            VALUES (
                :filename,
                :file_size,
                :total_events,
                :parsed_events,
                :failed_events
            )
            """,
            {
                "filename": filename,
                "file_size": file_size,
                "total_events": total_events,
                "parsed_events": parsed_events,
                "failed_events": failed_events,
            },
        )
    return cursor.lastrowid


def insert_event(
    connection,
    dataset_id,
    event_id=None,
    event_time=None,
    event_name=None,
    event_source=None,
    aws_region=None,
    account_id=None,
    username=None,
    principal_arn=None,
    access_key_id=None,
    source_ip=None,
    user_agent=None,
    raw_event_json=None,
    normalized_event_json=None,
):
    """Insert a CloudTrail event and return the new event ID.

    Optional CloudTrail attributes are stored as NULL when not supplied.
    """
    with connection:
        cursor = connection.execute(
            """
            INSERT INTO events (
                dataset_id,
                event_id,
                event_time,
                event_name,
                event_source,
                aws_region,
                account_id,
                username,
                principal_arn,
                access_key_id,
                source_ip,
                user_agent,
                raw_event_json,
                normalized_event_json
            )
            VALUES (
                :dataset_id,
                :event_id,
                :event_time,
                :event_name,
                :event_source,
                :aws_region,
                :account_id,
                :username,
                :principal_arn,
                :access_key_id,
                :source_ip,
                :user_agent,
                :raw_event_json,
                :normalized_event_json
            )
            """,
            {
                "dataset_id": dataset_id,
                "event_id": event_id,
                "event_time": event_time,
                "event_name": event_name,
                "event_source": event_source,
                "aws_region": aws_region,
                "account_id": account_id,
                "username": username,
                "principal_arn": principal_arn,
                "access_key_id": access_key_id,
                "source_ip": source_ip,
                "user_agent": user_agent,
                "raw_event_json": raw_event_json,
                "normalized_event_json": normalized_event_json,
            },
        )
    return cursor.lastrowid
