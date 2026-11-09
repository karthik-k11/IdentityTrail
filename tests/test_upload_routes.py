"""Route-level tests for CloudTrail upload and dataset history."""

import io
import json
import re
import sqlite3
from contextlib import closing

import pytest

import database
from app import create_app


def make_app(tmp_path, **overrides):
    config = {
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "MAX_CONTENT_LENGTH": 10 * 1024 * 1024,
        "MAX_EVENT_COUNT": 10000,
        "DATABASE_PATH": str(tmp_path / "identitytrail-test.db"),
    }
    config.update(overrides)
    return create_app(type("TestConfig", (), config))


@pytest.fixture
def app(tmp_path):
    return make_app(tmp_path)


@pytest.fixture
def client(app):
    return app.test_client()


def make_event(event_id="event-001", event_name="DescribeInstances"):
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
        "eventTime": "2026-11-05T10:00:00Z",
        "eventSource": "ec2.amazonaws.com",
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


def upload(client, content, filename="cloudtrail.json"):
    token = csrf_token(client)
    return client.post(
        "/upload",
        data={
            "_csrf_token": token,
            "file": (io.BytesIO(content), filename),
        },
        content_type="multipart/form-data",
    )


def csrf_token(client):
    page = client.get("/upload")
    token = re.search(
        rb'name="_csrf_token" value="([^"]+)"', page.data
    )
    if token is None:
        raise AssertionError("Upload page did not render a CSRF token")
    return token.group(1).decode("ascii")


def query_all(app, sql, parameters=()):
    with closing(
        database.get_connection(app.config["DATABASE_PATH"])
    ) as connection:
        return connection.execute(sql, parameters).fetchall()


def query_one(app, sql, parameters=()):
    rows = query_all(app, sql, parameters)
    assert len(rows) == 1
    return rows[0]


def test_existing_routes_still_work(client):
    home = client.get("/")
    health = client.get("/health")

    assert home.status_code == 200
    assert home.get_json()["application"] == "IdentityTrail"
    assert home.get_json()["status"] == "running"
    assert health.status_code == 200
    assert health.get_json() == {"status": "healthy"}


def test_upload_page_loads(client):
    response = client.get("/upload")

    assert response.status_code == 200
    assert b"Upload CloudTrail logs" in response.data
    assert b'name="file"' in response.data


def test_successful_upload_persists_dataset_and_events(app, client):
    first = make_event("event-001")
    second = make_event("event-002", event_name="DescribeVolumes")
    content = records_content([first, second])

    response = upload(client, content)

    assert response.status_code == 200
    assert b"Import complete." in response.data
    assert b"cloudtrail.json" in response.data
    assert b"Successfully parsed" in response.data

    dataset = query_one(app, "SELECT * FROM datasets")
    assert dataset["filename"] == "cloudtrail.json"
    assert dataset["file_size"] == len(content)
    assert dataset["total_events"] == 2
    assert dataset["parsed_events"] == 2
    assert dataset["failed_events"] == 0
    assert dataset["uploaded_at"].encode() in response.data

    events = query_all(app, "SELECT * FROM events ORDER BY id")
    assert len(events) == 2
    assert events[0]["dataset_id"] == dataset["id"]
    assert events[0]["event_id"] == "event-001"
    assert events[0]["event_name"] == "DescribeInstances"
    assert events[0]["username"] == "alice"
    assert json.loads(events[0]["raw_event_json"]) == first
    normalized = json.loads(events[0]["normalized_event_json"])
    assert normalized["event_name"] == "DescribeInstances"
    assert normalized["raw_event"] == first


def test_upload_missing_file(client):
    response = client.post(
        "/upload",
        data={"_csrf_token": csrf_token(client)},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"Please select a CloudTrail JSON file" in response.data


def test_state_changing_post_requires_csrf_token(client):
    response = client.post(
        "/upload",
        data={},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"could not be validated" in response.data


def test_state_changing_post_rejects_cross_origin(client):
    response = client.post(
        "/upload",
        data={"_csrf_token": csrf_token(client)},
        headers={"Origin": "https://attacker.example"},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"could not be validated" in response.data


def test_state_changing_post_accepts_opaque_origin_with_valid_csrf(client):
    response = client.post(
        "/analysis/run-all",
        data={"_csrf_token": csrf_token(client)},
        headers={"Origin": "null"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Analysis complete for 0 dataset(s)" in response.data


def test_state_changing_post_rejects_cross_site_fetch(client):
    response = client.post(
        "/upload",
        data={"_csrf_token": csrf_token(client)},
        headers={"Sec-Fetch-Site": "cross-site"},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"could not be validated" in response.data


def test_upload_invalid_extension(client):
    response = upload(
        client,
        records_content([make_event()]),
        filename="cloudtrail.txt",
    )

    assert response.status_code == 400
    assert b"Only .json CloudTrail files are supported" in response.data


def test_upload_empty_file(client):
    response = upload(client, b"", filename="cloudtrail.json")

    assert response.status_code == 400
    assert b"The uploaded file is empty" in response.data


def test_upload_malformed_json(client):
    response = upload(client, b'{"Records": [}')

    assert response.status_code == 400
    assert b"Malformed JSON" in response.data
    assert b"Traceback" not in response.data


def test_upload_invalid_cloudtrail_structure(app, client):
    response = upload(
        client,
        records_content([{"not": "a cloudtrail event"}]),
    )

    assert response.status_code == 400
    assert b"does not contain valid CloudTrail events" in response.data
    assert b"not a valid CloudTrail event" in response.data
    assert query_all(app, "SELECT * FROM datasets") == []


def test_upload_rejects_oversized_file(tmp_path):
    app = make_app(tmp_path, MAX_CONTENT_LENGTH=512)
    client = app.test_client()

    response = upload(client, b"x" * 600)

    assert response.status_code == 413
    assert b"too large" in response.data
    assert query_all(app, "SELECT * FROM datasets") == []


def test_upload_rejects_excessive_event_count(tmp_path):
    app = make_app(tmp_path, MAX_EVENT_COUNT=2)
    client = app.test_client()
    events = [make_event(f"event-{index}") for index in range(3)]

    response = upload(client, records_content(events))

    assert response.status_code == 400
    assert b"exceeds the maximum of 2" in response.data
    assert query_all(app, "SELECT * FROM datasets") == []


def test_upload_handles_mixed_valid_and_invalid_records(app, client):
    first = make_event("event-001")
    second = make_event("event-002", event_name="DescribeVolumes")
    content = records_content(
        [first, "not-an-object", {"eventName": "Incomplete"}, second]
    )

    response = upload(client, content)

    assert response.status_code == 200
    assert b"Import completed with warnings" in response.data
    assert b"Records not imported" in response.data
    assert b"not a JSON object" in response.data
    assert b"not a valid CloudTrail event" in response.data

    dataset = query_one(app, "SELECT * FROM datasets")
    assert dataset["total_events"] == 4
    assert dataset["parsed_events"] == 2
    assert dataset["failed_events"] == 2
    assert len(query_all(app, "SELECT * FROM events")) == 2


def test_upload_handles_duplicate_event_ids(app, client):
    content = records_content(
        [
            make_event("duplicate-id", event_name="DescribeInstances"),
            make_event("duplicate-id", event_name="DescribeVolumes"),
            make_event("unique-id", event_name="DescribeSnapshots"),
        ]
    )

    response = upload(client, content)

    assert response.status_code == 200
    assert b"Duplicate records" in response.data

    dataset = query_one(app, "SELECT * FROM datasets")
    assert dataset["total_events"] == 3
    assert dataset["parsed_events"] == 3
    assert dataset["failed_events"] == 0

    events = query_all(app, "SELECT * FROM events ORDER BY id")
    assert len(events) == 2
    assert {event["event_id"] for event in events} == {
        "duplicate-id",
        "unique-id",
    }


def test_upload_database_failure_returns_safe_error(app, client, monkeypatch):
    def fail_insert(*args, **kwargs):
        raise sqlite3.OperationalError("internal database detail")

    monkeypatch.setattr(
        "services.cloudtrail_ingestion.database.insert_dataset_with_events",
        fail_insert,
    )

    response = upload(client, records_content([make_event()]))

    assert response.status_code == 500
    assert b"could not be saved to the database" in response.data
    assert b"No data was committed" in response.data
    assert b"internal database detail" not in response.data
    assert b"Traceback" not in response.data
    assert query_all(app, "SELECT * FROM datasets") == []


def test_dataset_history_empty(client):
    response = client.get("/datasets")

    assert response.status_code == 200
    assert b"No datasets yet" in response.data


def test_dataset_history_lists_uploaded_datasets(app, client):
    first = upload(
        client,
        records_content([make_event("event-001")]),
        filename="first.json",
    )
    second = upload(
        client,
        records_content(
            [
                make_event("event-002"),
                make_event("event-003", event_name="DescribeVolumes"),
            ]
        ),
        filename="second.json",
    )

    assert first.status_code == 200
    assert second.status_code == 200

    response = client.get("/datasets")

    assert response.status_code == 200
    assert b"Dataset history" in response.data
    assert b"first.json" in response.data
    assert b"second.json" in response.data
    assert len(query_all(app, "SELECT * FROM datasets")) == 2
    assert len(query_all(app, "SELECT * FROM events")) == 3
