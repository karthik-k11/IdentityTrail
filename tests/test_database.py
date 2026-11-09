"""Tests for the IdentityTrail SQLite database foundation."""

import sqlite3

import pytest
from flask import Flask

import database


OPTIONAL_EVENT_COLUMNS = (
    "event_id",
    "event_time",
    "event_name",
    "event_source",
    "aws_region",
    "account_id",
    "username",
    "principal_arn",
    "access_key_id",
    "source_ip",
    "user_agent",
    "raw_event_json",
    "normalized_event_json",
)


@pytest.fixture
def db_path(tmp_path):
    """Provide a temporary database path; never touch the development DB."""
    return tmp_path / "identitytrail-test.db"


@pytest.fixture
def connection(db_path):
    """Initialize a temporary database and yield an open connection."""
    database.init_db(db_path)
    connection = database.get_connection(db_path)
    try:
        yield connection
    finally:
        connection.close()


def test_init_db_creates_database_file(db_path):
    assert not db_path.exists()

    database.init_db(db_path)

    assert db_path.is_file()
    assert db_path.stat().st_size > 0


def test_init_db_is_idempotent(db_path):
    database.init_db(db_path)
    database.init_db(db_path)

    connection = database.get_connection(db_path)
    try:
        table_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM sqlite_master
            WHERE type = 'table' AND name IN ('datasets', 'events')
            """
        ).fetchone()[0]
    finally:
        connection.close()

    assert table_count == 2


def test_init_db_migrates_existing_data_without_recreating_database(db_path):
    legacy = sqlite3.connect(db_path)
    legacy.executescript(
        """
        CREATE TABLE datasets (
            id INTEGER PRIMARY KEY,
            filename TEXT NOT NULL,
            uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            file_size INTEGER NOT NULL DEFAULT 0,
            total_events INTEGER NOT NULL DEFAULT 0,
            parsed_events INTEGER NOT NULL DEFAULT 0,
            failed_events INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE events (
            id INTEGER PRIMARY KEY,
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
            FOREIGN KEY (dataset_id) REFERENCES datasets (id)
        );
        INSERT INTO datasets (id, filename, total_events, parsed_events)
        VALUES (7, 'existing.json', 1, 1);
        INSERT INTO events (
            id, dataset_id, event_id, username, principal_arn,
            normalized_event_json
        )
        VALUES (
            19, 7, 'existing-event', 'alice',
            'arn:aws:iam::111122223333:user/alice',
            '{"principal_id":"AIDAEXAMPLEALICE","identity_type":"IAMUser"}'
        );
        """
    )
    legacy.commit()
    legacy.close()

    database.init_db(db_path)

    connection = database.get_connection(db_path)
    try:
        dataset = database.get_dataset(connection, 7)
        event = connection.execute(
            "SELECT * FROM events WHERE id = 19"
        ).fetchone()
        assert dataset["filename"] == "existing.json"
        assert event["event_id"] == "existing-event"
        assert event["identity_type"] == "IAMUser"
        assert event["principal_id"] == "AIDAEXAMPLEALICE"
        assert event["identity_key"] == (
            "arn|arn:aws:iam::111122223333:user/alice"
        )
    finally:
        connection.close()


def test_expected_tables_are_created(connection):
    tables = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }

    assert {"datasets", "events"} <= tables


def test_expected_indexes_are_created(connection):
    indexes = {
        row["name"]
        for row in connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'index' AND name NOT LIKE 'sqlite_%'
            """
        )
    }

    assert {
        "uq_events_dataset_event_id",
        "idx_events_dataset_id",
        "idx_events_event_time",
        "idx_events_event_name",
        "idx_events_username",
    } <= indexes


def test_connection_configuration(connection):
    assert connection.row_factory is sqlite3.Row
    assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_foreign_keys_are_enforced(connection):
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO events (dataset_id, event_name) VALUES (?, ?)",
            (99999, "ConsoleLogin"),
        )

    connection.rollback()


def test_dataset_insertion(connection):
    dataset_id = database.insert_dataset(
        connection,
        filename="cloudtrail.json",
        file_size=2048,
        total_events=10,
        parsed_events=8,
        failed_events=2,
    )

    row = connection.execute(
        "SELECT * FROM datasets WHERE id = ?", (dataset_id,)
    ).fetchone()

    assert row is not None
    assert row["filename"] == "cloudtrail.json"
    assert row["uploaded_at"]
    assert row["file_size"] == 2048
    assert row["total_events"] == 10
    assert row["parsed_events"] == 8
    assert row["failed_events"] == 2


def test_event_insertion(connection):
    dataset_id = database.insert_dataset(
        connection, filename="cloudtrail.json", total_events=1, parsed_events=1
    )

    event_id = database.insert_event(
        connection,
        dataset_id=dataset_id,
        event_id="event-001",
        event_time="2026-11-04T12:00:00Z",
        event_name="AssumeRole",
        event_source="sts.amazonaws.com",
        aws_region="us-east-1",
        account_id="123456789012",
        username="analyst",
        principal_arn="arn:aws:iam::123456789012:user/analyst",
        access_key_id="AKIAEXAMPLE",
        source_ip="203.0.113.10",
        user_agent="aws-cli/2.0",
        raw_event_json='{"eventId": "event-001"}',
        normalized_event_json='{"event_name": "AssumeRole"}',
    )

    row = connection.execute(
        "SELECT * FROM events WHERE id = ?", (event_id,)
    ).fetchone()

    assert row is not None
    assert row["dataset_id"] == dataset_id
    assert row["event_id"] == "event-001"
    assert row["event_time"] == "2026-11-04T12:00:00Z"
    assert row["event_name"] == "AssumeRole"
    assert row["event_source"] == "sts.amazonaws.com"
    assert row["aws_region"] == "us-east-1"
    assert row["account_id"] == "123456789012"
    assert row["username"] == "analyst"
    assert row["principal_arn"] == "arn:aws:iam::123456789012:user/analyst"
    assert row["access_key_id"] == "AKIAEXAMPLE"
    assert row["source_ip"] == "203.0.113.10"
    assert row["user_agent"] == "aws-cli/2.0"
    assert row["raw_event_json"] == '{"eventId": "event-001"}'
    assert row["normalized_event_json"] == '{"event_name": "AssumeRole"}'


def test_cascade_deletion(connection):
    dataset_id = database.insert_dataset(
        connection, filename="cloudtrail.json", total_events=2, parsed_events=2
    )
    database.insert_event(connection, dataset_id, event_id="event-001")
    database.insert_event(connection, dataset_id, event_id="event-002")

    with connection:
        connection.execute("DELETE FROM datasets WHERE id = ?", (dataset_id,))

    remaining = connection.execute(
        "SELECT COUNT(*) FROM events WHERE dataset_id = ?", (dataset_id,)
    ).fetchone()[0]

    assert remaining == 0


def test_duplicate_event_id_rejected_within_dataset(connection):
    dataset_id = database.insert_dataset(
        connection, filename="cloudtrail.json", total_events=2, parsed_events=2
    )
    database.insert_event(connection, dataset_id, event_id="duplicate-event")

    with pytest.raises(sqlite3.IntegrityError):
        database.insert_event(connection, dataset_id, event_id="duplicate-event")

    event_count = connection.execute(
        "SELECT COUNT(*) FROM events WHERE dataset_id = ?", (dataset_id,)
    ).fetchone()[0]

    assert event_count == 1


def test_same_event_id_allowed_across_datasets(connection):
    first_dataset = database.insert_dataset(connection, filename="first.json")
    second_dataset = database.insert_dataset(connection, filename="second.json")

    database.insert_event(connection, first_dataset, event_id="shared-event")
    database.insert_event(connection, second_dataset, event_id="shared-event")

    event_count = connection.execute(
        "SELECT COUNT(*) FROM events WHERE event_id = ?", ("shared-event",)
    ).fetchone()[0]

    assert event_count == 2


def test_optional_event_fields_accept_null(connection):
    dataset_id = database.insert_dataset(connection, filename="cloudtrail.json")

    first_event_id = database.insert_event(connection, dataset_id)
    second_event_id = database.insert_event(connection, dataset_id)

    for event_id in (first_event_id, second_event_id):
        row = connection.execute(
            "SELECT * FROM events WHERE id = ?", (event_id,)
        ).fetchone()
        assert row is not None
        for column in OPTIONAL_EVENT_COLUMNS:
            assert row[column] is None


def test_flask_init_app_uses_configured_database_path(tmp_path):
    flask_db_path = tmp_path / "flask-identitytrail.db"
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = str(flask_db_path)

    database.init_app(app)

    assert flask_db_path.is_file()

    with app.app_context():
        connection = database.get_db()
        assert connection is database.get_db()
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1

    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")
