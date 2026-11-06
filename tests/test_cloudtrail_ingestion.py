"""Tests for CloudTrail validation and transactional ingestion."""

import json
import sqlite3

import pytest

import database
from services.cloudtrail_ingestion import (
    SUPPORTED_IDENTITY_TYPES,
    IngestionPersistenceError,
    IngestionValidationError,
    ingest_cloudtrail,
    validate_cloudtrail_event,
)


@pytest.fixture
def connection(tmp_path):
    database.init_db(tmp_path / "ingestion-test.db")
    connection = database.get_connection(tmp_path / "ingestion-test.db")
    try:
        yield connection
    finally:
        connection.close()


def make_event(
    event_id="event-001",
    event_name="DescribeInstances",
    event_source="ec2.amazonaws.com",
    event_time="2026-11-05T10:00:00Z",
):
    return {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLEALICE",
            "arn": "arn:aws:iam::111122223333:user/alice",
            "accountId": "111122223333",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "userName": "alice",
        },
        "eventTime": event_time,
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": "192.0.2.10",
        "userAgent": "aws-cli/2.15.0",
        "requestParameters": {"instancesSet": {}},
        "responseElements": None,
        "eventID": event_id,
        "readOnly": True,
        "managementEvent": True,
        "recipientAccountId": "111122223333",
    }


def records_content(events):
    return json.dumps({"Records": events}).encode("utf-8")


def count_rows(connection, table):
    return connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_ingest_cloudtrail_persists_dataset_and_events(connection):
    first = make_event("event-001")
    second = make_event("event-002", event_name="DescribeVolumes")
    content = records_content([first, second])

    result = ingest_cloudtrail(
        connection,
        filename="cloudtrail.json",
        content=content,
        max_events=10,
    )

    assert result.dataset_id == 1
    assert result.filename == "cloudtrail.json"
    assert result.file_size == len(content)
    assert result.uploaded_at
    assert result.total_records == 2
    assert result.parsed_records == 2
    assert result.failed_records == 0
    assert result.duplicate_records == 0
    assert result.inserted_records == 2
    assert result.errors == []

    dataset = connection.execute(
        "SELECT * FROM datasets WHERE id = ?", (result.dataset_id,)
    ).fetchone()
    assert dataset["filename"] == "cloudtrail.json"
    assert dataset["file_size"] == len(content)
    assert dataset["total_events"] == 2
    assert dataset["parsed_events"] == 2
    assert dataset["failed_events"] == 0

    events = connection.execute(
        "SELECT * FROM events WHERE dataset_id = ? ORDER BY id",
        (result.dataset_id,),
    ).fetchall()
    assert len(events) == 2
    assert events[0]["event_id"] == "event-001"
    assert events[0]["event_name"] == "DescribeInstances"
    assert events[0]["event_source"] == "ec2.amazonaws.com"
    assert events[0]["aws_region"] == "us-east-1"
    assert events[0]["account_id"] == "111122223333"
    assert events[0]["username"] == "alice"
    assert events[0]["principal_arn"] == (
        "arn:aws:iam::111122223333:user/alice"
    )
    assert events[0]["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
    assert events[0]["source_ip"] == "192.0.2.10"
    assert events[0]["user_agent"] == "aws-cli/2.15.0"

    raw_event = json.loads(events[0]["raw_event_json"])
    normalized_event = json.loads(events[0]["normalized_event_json"])
    assert raw_event == first
    assert normalized_event["event_name"] == "DescribeInstances"
    assert normalized_event["identity_type"] == "IAMUser"
    assert normalized_event["raw_event"] == first


def test_ingest_cloudtrail_handles_mixed_valid_and_invalid_records(connection):
    valid_one = make_event("event-001")
    valid_two = make_event("event-002", event_name="DescribeVolumes")
    content = records_content(
        [
            valid_one,
            "not-an-object",
            valid_two,
            {"eventName": "IncompleteEvent"},
        ]
    )

    result = ingest_cloudtrail(
        connection,
        filename="mixed.json",
        content=content,
        max_events=10,
    )

    assert result.total_records == 4
    assert result.parsed_records == 2
    assert result.failed_records == 2
    assert result.duplicate_records == 0
    assert result.inserted_records == 2
    assert len(result.errors) == 2
    assert result.errors[0].position == 2
    assert "not a JSON object" in result.errors[0].message
    assert "not a valid CloudTrail event" in result.errors[1].message
    assert "eventSource" in result.errors[1].message
    assert "eventTime" in result.errors[1].message

    dataset = connection.execute(
        "SELECT * FROM datasets WHERE id = ?", (result.dataset_id,)
    ).fetchone()
    assert dataset["total_events"] == 4
    assert dataset["parsed_events"] == 2
    assert dataset["failed_events"] == 2
    assert count_rows(connection, "events") == 2


def test_ingest_cloudtrail_skips_duplicate_event_ids(connection):
    first = make_event("duplicate-id", event_name="DescribeInstances")
    duplicate = make_event("duplicate-id", event_name="DescribeVolumes")
    unique = make_event("unique-id", event_name="DescribeSnapshots")
    content = records_content([first, duplicate, unique])

    result = ingest_cloudtrail(
        connection,
        filename="duplicates.json",
        content=content,
        max_events=10,
    )

    assert result.total_records == 3
    assert result.parsed_records == 3
    assert result.failed_records == 0
    assert result.duplicate_records == 1
    assert result.inserted_records == 2

    dataset = connection.execute(
        "SELECT * FROM datasets WHERE id = ?", (result.dataset_id,)
    ).fetchone()
    assert dataset["total_events"] == 3
    assert dataset["parsed_events"] == 3
    assert dataset["failed_events"] == 0

    rows = connection.execute(
        "SELECT event_id, event_name FROM events WHERE dataset_id = ?",
        (result.dataset_id,),
    ).fetchall()
    assert len(rows) == 2
    assert {row["event_id"] for row in rows} == {
        "duplicate-id",
        "unique-id",
    }
    assert next(
        row["event_name"] for row in rows if row["event_id"] == "duplicate-id"
    ) == "DescribeInstances"


def test_ingest_cloudtrail_allows_multiple_null_event_ids(connection):
    first = make_event(None)
    second = make_event(None, event_name="DescribeVolumes")

    result = ingest_cloudtrail(
        connection,
        filename="null-ids.json",
        content=records_content([first, second]),
        max_events=10,
    )

    assert result.duplicate_records == 0
    assert result.inserted_records == 2
    assert count_rows(connection, "events") == 2


def test_ingest_cloudtrail_rejects_no_valid_events(connection):
    content = records_content([{"not": "cloudtrail"}])

    with pytest.raises(
        IngestionValidationError,
        match="does not contain valid CloudTrail events",
    ) as exc_info:
        ingest_cloudtrail(
            connection,
            filename="invalid.json",
            content=content,
            max_events=10,
        )

    assert exc_info.value.errors
    assert count_rows(connection, "datasets") == 0
    assert count_rows(connection, "events") == 0


def test_ingest_cloudtrail_rejects_empty_records_array(connection):
    with pytest.raises(IngestionValidationError, match="no CloudTrail records"):
        ingest_cloudtrail(
            connection,
            filename="empty.json",
            content=b'{"Records": []}',
            max_events=10,
        )

    assert count_rows(connection, "datasets") == 0


def test_ingest_cloudtrail_rejects_malformed_json(connection):
    with pytest.raises(IngestionValidationError, match="Malformed JSON"):
        ingest_cloudtrail(
            connection,
            filename="malformed.json",
            content=b'{"Records": [}',
            max_events=10,
        )

    assert count_rows(connection, "datasets") == 0


def test_ingest_cloudtrail_rejects_excessive_event_count(connection):
    events = [make_event(f"event-{index}") for index in range(3)]

    with pytest.raises(IngestionValidationError, match="exceeds the maximum"):
        ingest_cloudtrail(
            connection,
            filename="too-many.json",
            content=records_content(events),
            max_events=2,
        )

    assert count_rows(connection, "datasets") == 0


def test_ingest_cloudtrail_rolls_back_on_database_failure(connection):
    connection.execute(
        """
        CREATE TRIGGER fail_event_insert
        BEFORE INSERT ON events
        WHEN NEW.event_name = 'FailMe'
        BEGIN
            SELECT RAISE(ABORT, 'simulated event insertion failure');
        END;
        """
    )
    connection.commit()

    events = [
        make_event("event-001"),
        make_event("event-002", event_name="FailMe"),
    ]

    with pytest.raises(
        IngestionPersistenceError,
        match="could not be saved",
    ):
        ingest_cloudtrail(
            connection,
            filename="rollback.json",
            content=records_content(events),
            max_events=10,
        )

    assert count_rows(connection, "datasets") == 0
    assert count_rows(connection, "events") == 0


def test_validate_cloudtrail_event_requires_core_fields():
    valid_event = make_event("event-001")
    assert validate_cloudtrail_event(valid_event) == []

    invalid_event = {
        "eventName": "",
        "eventSource": None,
        "eventTime": "2026-11-05T10:00:00Z",
    }
    assert validate_cloudtrail_event(invalid_event) == [
        "eventVersion",
        "userIdentity",
        "eventName",
        "eventSource",
    ]


def test_validate_cloudtrail_event_rejects_three_field_arbitrary_json():
    arbitrary_event = {
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "eventTime": "2026-11-05T10:00:00Z",
    }

    assert validate_cloudtrail_event(arbitrary_event) == [
        "eventVersion",
        "userIdentity",
    ]


def test_validate_cloudtrail_event_rejects_invalid_event_version():
    event = make_event("event-001")
    event["eventVersion"] = "not-a-version"

    assert validate_cloudtrail_event(event) == ["eventVersion"]

    event["eventVersion"] = 1.09
    assert validate_cloudtrail_event(event) == ["eventVersion"]


@pytest.mark.parametrize("identity_type", sorted(SUPPORTED_IDENTITY_TYPES))
def test_validate_cloudtrail_event_accepts_supported_identity_types(identity_type):
    event = make_event("event-001")
    event["userIdentity"]["type"] = identity_type

    assert validate_cloudtrail_event(event) == []


def test_validate_cloudtrail_event_rejects_unknown_identity_type():
    event = make_event("event-001")
    event["userIdentity"]["type"] = "Anonymous"

    assert validate_cloudtrail_event(event) == ["userIdentity"]


def test_validate_cloudtrail_event_rejects_non_object_user_identity():
    event = make_event("event-001")
    event["userIdentity"] = "IAMUser"

    assert validate_cloudtrail_event(event) == ["userIdentity"]

    event["userIdentity"] = {"principalId": "AIDAEXAMPLEALICE"}
    assert validate_cloudtrail_event(event) == ["userIdentity"]


def test_ingest_cloudtrail_rejects_three_field_arbitrary_json(connection):
    arbitrary_event = {
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "eventTime": "2026-11-05T10:00:00Z",
    }

    with pytest.raises(
        IngestionValidationError,
        match="does not contain valid CloudTrail events",
    ) as exc_info:
        ingest_cloudtrail(
            connection,
            filename="arbitrary.json",
            content=records_content([arbitrary_event]),
            max_events=10,
        )

    assert len(exc_info.value.errors) == 1
    assert "eventVersion" in exc_info.value.errors[0].message
    assert "userIdentity" in exc_info.value.errors[0].message
    assert count_rows(connection, "datasets") == 0
    assert count_rows(connection, "events") == 0


def test_ingest_cloudtrail_accepts_event_without_optional_fields(connection):
    minimal_event = {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "IAMUser",
            "accountId": "111122223333",
            "userName": "alice",
        },
        "eventTime": "2026-11-05T10:00:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
    }

    result = ingest_cloudtrail(
        connection,
        filename="minimal.json",
        content=records_content([minimal_event]),
        max_events=10,
    )

    assert result.total_records == 1
    assert result.parsed_records == 1
    assert result.failed_records == 0
    assert result.inserted_records == 1

    event = connection.execute(
        "SELECT * FROM events WHERE dataset_id = ?",
        (result.dataset_id,),
    ).fetchone()
    assert event["event_id"] is None
    assert event["source_ip"] is None
    assert event["user_agent"] is None

    normalized = json.loads(event["normalized_event_json"])
    assert normalized["request_parameters"] == {}
    assert normalized["response_elements"] == {}
    assert normalized["resources"] == []
    assert normalized["raw_event"] == minimal_event
