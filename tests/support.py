"""Shared fixtures and synthetic CloudTrail data for the test suite."""

from __future__ import annotations

import io
import json
import re

import database
from app import create_app
from services.cloudtrail_ingestion import ingest_cloudtrail


def make_event(
    event_id="event-001",
    event_name="DescribeInstances",
    event_source="ec2.amazonaws.com",
    event_time="2026-11-05T10:00:00Z",
    source_ip="192.0.2.10",
    identity_type="IAMUser",
    username="alice",
    principal_id="AIDAEXAMPLEALICE",
    principal_arn="arn:aws:iam::111122223333:user/alice",
    access_key_id="AKIAIOSFODNN7EXAMPLE",
    request_parameters=None,
    response_elements=None,
    error_code=None,
    error_message=None,
    resources=None,
    aws_region="us-east-1",
    account_id="111122223333",
):
    """Return a structurally valid CloudTrail event with optional context."""
    identity = {
        "type": identity_type,
        "accountId": account_id,
        "accessKeyId": access_key_id,
    }
    if username is not None:
        identity["userName"] = username
    if principal_id is not None:
        identity["principalId"] = principal_id
    if principal_arn is not None:
        identity["arn"] = principal_arn

    event = {
        "eventVersion": "1.09",
        "userIdentity": identity,
        "eventTime": event_time,
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": aws_region,
        "sourceIPAddress": source_ip,
        "userAgent": "aws-cli/2.15.0",
        "requestParameters": request_parameters,
        "responseElements": response_elements,
        "eventID": event_id,
        "readOnly": False,
        "managementEvent": True,
        "recipientAccountId": account_id,
    }
    if resources is not None:
        event["resources"] = resources
    if error_code is not None:
        event["errorCode"] = error_code
    if error_message is not None:
        event["errorMessage"] = error_message
    return event


def records_content(events):
    return json.dumps({"Records": events}).encode("utf-8")


def ingest(connection, events, filename="synthetic.json", max_events=10000):
    return ingest_cloudtrail(
        connection,
        filename=filename,
        content=records_content(events),
        max_events=max_events,
    )


def connect(tmp_path, name="identitytrail-test.db"):
    path = tmp_path / name
    database.init_db(path)
    return database.get_connection(path)


def make_app(tmp_path, **overrides):
    config_values = {
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "MAX_CONTENT_LENGTH": 10 * 1024 * 1024,
        "MAX_EVENT_COUNT": 10000,
        "DATABASE_PATH": str(tmp_path / "identitytrail-route-test.db"),
        "PAGE_SIZE": 50,
        "DETECTION_CONSOLE_FAILURE_THRESHOLD": 3,
        "DETECTION_CONSOLE_FAILURE_WINDOW_MINUTES": 15,
        "DETECTION_FAILURE_SUCCESS_WINDOW_MINUTES": 30,
        "DETECTION_ACCESS_KEY_ACTIVITY_WINDOW_HOURS": 24,
        "DETECTION_TIMELINE_GAP_MINUTES": 60,
        "REPORT_EVENT_LIMIT": 500,
    }
    config_values.update(overrides)
    return create_app(type("TestConfig", (), config_values))


def upload(client, events, filename="cloudtrail.json"):
    page = client.get("/upload")
    token = re.search(
        rb'name="_csrf_token" value="([^"]+)"', page.data
    )
    if token is None:
        raise AssertionError("Upload page did not render a CSRF token")
    return client.post(
        "/upload",
        data={
            "_csrf_token": token.group(1).decode("ascii"),
            "file": (io.BytesIO(records_content(events)), filename),
        },
        content_type="multipart/form-data",
    )
