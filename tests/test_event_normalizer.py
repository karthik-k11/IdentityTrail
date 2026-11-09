"""Tests for CloudTrail event normalization."""

from pathlib import Path

import pytest

from services.cloudtrail_parser import parse_cloudtrail
from services.event_normalizer import normalize_event


SAMPLE_PATH = (
    Path(__file__).resolve().parents[1]
    / "sample_data"
    / "cloudtrail_sample.json"
)

EXPECTED_KEYS = {
    "event_id",
    "event_name",
    "event_source",
    "event_time",
    "aws_region",
    "account_id",
    "username",
    "principal_arn",
    "principal_id",
    "identity_type",
    "access_key_id",
    "source_ip",
    "user_agent",
    "resources",
    "request_parameters",
    "response_elements",
    "error_code",
    "error_message",
    "read_only",
    "management_event",
    "raw_event",
}

IAM_USER_IDENTITY = {
    "type": "IAMUser",
    "principalId": "AIDAEXAMPLEALICE",
    "arn": "arn:aws:iam::111122223333:user/alice",
    "accountId": "111122223333",
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "userName": "alice",
}

ASSUMED_ROLE_IDENTITY = {
    "type": "AssumedRole",
    "principalId": "AROAEXAMPLE:session-001",
    "arn": (
        "arn:aws:sts::111122223333:"
        "assumed-role/IncidentResponse/session-001"
    ),
    "accountId": "111122223333",
    "accessKeyId": "ASIAIOSFODNN7EXAMPLE",
    "sessionContext": {
        "sessionIssuer": {
            "type": "Role",
            "principalId": "AROAEXAMPLE",
            "arn": "arn:aws:iam::111122223333:role/IncidentResponse",
            "accountId": "111122223333",
            "userName": "IncidentResponse",
        }
    },
}

ROOT_IDENTITY = {
    "type": "Root",
    "principalId": "111122223333",
    "arn": "arn:aws:iam::111122223333:root",
    "accountId": "111122223333",
}

FEDERATED_IDENTITY = {
    "type": "FederatedUser",
    "principalId": "AROAEXAMPLE:federated.analyst",
    "arn": (
        "arn:aws:sts::111122223333:"
        "federated-user/federated.analyst"
    ),
    "accountId": "111122223333",
    "accessKeyId": "ASIAEXAMPLEFEDERATED",
    "userName": "federated.analyst",
}

AWS_SERVICE_IDENTITY = {
    "type": "AWSService",
    "invokedBy": "ec2.amazonaws.com",
}

AWS_ACCOUNT_IDENTITY = {
    "type": "AWSAccount",
    "principalId": "111122223333",
    "accountId": "111122223333",
    "arn": "arn:aws:iam::111122223333:root",
}


def make_event(identity=IAM_USER_IDENTITY, **overrides):
    event = {
        "eventID": "event-001",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "eventTime": "2026-11-04T09:15:00Z",
        "awsRegion": "us-east-1",
        "recipientAccountId": "111122223333",
        "sourceIPAddress": "192.0.2.10",
        "userAgent": "Mozilla/5.0",
        "userIdentity": identity,
        "requestParameters": {"userName": "alice"},
        "responseElements": {"ConsoleLogin": "Success"},
        "resources": [
            {
                "accountId": "111122223333",
                "type": "AWS::IAM::User",
                "ARN": "arn:aws:iam::111122223333:user/alice",
            }
        ],
        "readOnly": False,
        "managementEvent": True,
    }
    event.update(overrides)
    return event


def test_normalize_complete_event():
    event = make_event()

    normalized = normalize_event(event)

    assert set(normalized) == EXPECTED_KEYS
    assert normalized["event_id"] == "event-001"
    assert normalized["event_name"] == "ConsoleLogin"
    assert normalized["event_source"] == "signin.amazonaws.com"
    assert normalized["event_time"] == "2026-11-04T09:15:00Z"
    assert normalized["aws_region"] == "us-east-1"
    assert normalized["account_id"] == "111122223333"
    assert normalized["username"] == "alice"
    assert normalized["principal_arn"] == "arn:aws:iam::111122223333:user/alice"
    assert normalized["principal_id"] == "AIDAEXAMPLEALICE"
    assert normalized["identity_type"] == "IAMUser"
    assert normalized["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
    assert normalized["source_ip"] == "192.0.2.10"
    assert normalized["user_agent"] == "Mozilla/5.0"
    assert normalized["resources"] == event["resources"]
    assert normalized["request_parameters"] == {"userName": "alice"}
    assert normalized["response_elements"] == {"ConsoleLogin": "Success"}
    assert normalized["error_code"] is None
    assert normalized["error_message"] is None
    assert normalized["read_only"] is False
    assert normalized["management_event"] is True
    assert normalized["raw_event"] == event


def test_normalize_event_time_to_utc_without_changing_raw_record():
    event = make_event(eventTime="2026-11-04T14:15:00+05:00")

    normalized = normalize_event(event)

    assert normalized["event_time"] == "2026-11-04T09:15:00Z"
    assert normalized["raw_event"]["eventTime"] == "2026-11-04T14:15:00+05:00"


def test_normalize_naive_event_time_as_utc():
    event = make_event(eventTime="2026-11-04T09:15:00")

    normalized = normalize_event(event)

    assert normalized["event_time"] == "2026-11-04T09:15:00Z"


def test_normalize_iam_user_identity():
    normalized = normalize_event(make_event(identity=IAM_USER_IDENTITY))

    assert normalized["identity_type"] == "IAMUser"
    assert normalized["username"] == "alice"
    assert normalized["principal_arn"] == "arn:aws:iam::111122223333:user/alice"
    assert normalized["principal_id"] == "AIDAEXAMPLEALICE"
    assert normalized["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"


def test_normalize_assumed_role_identity():
    normalized = normalize_event(make_event(identity=ASSUMED_ROLE_IDENTITY))

    assert normalized["identity_type"] == "AssumedRole"
    assert normalized["username"] is None
    assert normalized["principal_arn"] == (
        "arn:aws:sts::111122223333:"
        "assumed-role/IncidentResponse/session-001"
    )
    assert normalized["principal_id"] == "AROAEXAMPLE:session-001"
    assert normalized["access_key_id"] == "ASIAIOSFODNN7EXAMPLE"


def test_normalize_root_identity():
    normalized = normalize_event(make_event(identity=ROOT_IDENTITY))

    assert normalized["identity_type"] == "Root"
    assert normalized["username"] is None
    assert normalized["principal_arn"] == "arn:aws:iam::111122223333:root"
    assert normalized["principal_id"] == "111122223333"
    assert normalized["access_key_id"] is None
    assert normalized["username"] not in {"anonymous", "unauthenticated"}


def test_normalize_federated_identity():
    normalized = normalize_event(make_event(identity=FEDERATED_IDENTITY))

    assert normalized["identity_type"] == "FederatedUser"
    assert normalized["username"] == "federated.analyst"
    assert normalized["principal_arn"] == (
        "arn:aws:sts::111122223333:"
        "federated-user/federated.analyst"
    )
    assert normalized["principal_id"] == "AROAEXAMPLE:federated.analyst"
    assert normalized["access_key_id"] == "ASIAEXAMPLEFEDERATED"


def test_normalize_aws_service_identity():
    normalized = normalize_event(make_event(identity=AWS_SERVICE_IDENTITY))

    assert normalized["identity_type"] == "AWSService"
    assert normalized["username"] is None
    assert normalized["principal_arn"] is None
    assert normalized["principal_id"] is None
    assert normalized["access_key_id"] is None


def test_normalize_aws_account_identity():
    normalized = normalize_event(make_event(identity=AWS_ACCOUNT_IDENTITY))

    assert normalized["identity_type"] == "AWSAccount"
    assert normalized["username"] is None
    assert normalized["principal_arn"] == "arn:aws:iam::111122223333:root"
    assert normalized["principal_id"] == "111122223333"


def test_normalize_missing_user_identity():
    event = make_event()
    event.pop("userIdentity")

    normalized = normalize_event(event)

    assert normalized["identity_type"] is None
    assert normalized["username"] is None
    assert normalized["principal_arn"] is None
    assert normalized["principal_id"] is None
    assert normalized["access_key_id"] is None
    assert normalized["username"] not in {"anonymous", "unauthenticated"}


def test_normalize_missing_source_ip():
    event = make_event()
    event.pop("sourceIPAddress")

    assert normalize_event(event)["source_ip"] is None

    event["sourceIPAddress"] = None
    assert normalize_event(event)["source_ip"] is None


def test_normalize_missing_access_key():
    identity = dict(IAM_USER_IDENTITY)
    identity.pop("accessKeyId")

    normalized = normalize_event(make_event(identity=identity))

    assert normalized["access_key_id"] is None


def test_normalize_missing_resources():
    event = make_event()
    event.pop("resources")

    assert normalize_event(event)["resources"] == []

    event["resources"] = None
    assert normalize_event(event)["resources"] == []


def test_normalize_missing_request_and_response_parameters():
    event = make_event()
    event.pop("requestParameters")
    event.pop("responseElements")

    normalized = normalize_event(event)

    assert normalized["request_parameters"] == {}
    assert normalized["response_elements"] == {}


def test_normalize_failed_api_event():
    event = make_event(
        eventName="CreateAccessKey",
        errorCode="AccessDenied",
        errorMessage="User is not authorized to perform iam:CreateAccessKey",
    )

    normalized = normalize_event(event)

    assert normalized["event_name"] == "CreateAccessKey"
    assert normalized["error_code"] == "AccessDenied"
    assert normalized["error_message"] == (
        "User is not authorized to perform iam:CreateAccessKey"
    )


def test_normalize_read_only_and_management_fields():
    event = make_event(readOnly=True, managementEvent=False)

    normalized = normalize_event(event)

    assert normalized["read_only"] is True
    assert normalized["management_event"] is False


def test_normalize_missing_classification_fields():
    event = make_event()
    event.pop("readOnly")
    event.pop("managementEvent")

    normalized = normalize_event(event)

    assert normalized["read_only"] is None
    assert normalized["management_event"] is None


def test_normalize_optional_fields_with_unexpected_types():
    event = make_event(
        eventName=None,
        eventSource=None,
        eventTime=None,
        awsRegion=None,
        userAgent=None,
        requestParameters="not-a-mapping",
        responseElements=None,
        resources=None,
        readOnly="true",
        managementEvent=1,
    )

    normalized = normalize_event(event)

    assert normalized["event_name"] is None
    assert normalized["event_source"] is None
    assert normalized["event_time"] is None
    assert normalized["aws_region"] is None
    assert normalized["user_agent"] is None
    assert normalized["request_parameters"] == {}
    assert normalized["response_elements"] == {}
    assert normalized["resources"] == []
    assert normalized["read_only"] is None
    assert normalized["management_event"] is None


def test_normalize_preserves_raw_event():
    event = make_event(
        eventVersion="1.09",
        eventType="AwsApiCall",
        sharedEventID="shared-event-001",
        customField={"nested": [1, 2, 3]},
    )

    normalized = normalize_event(event)

    assert normalized["raw_event"] == event
    assert normalized["raw_event"]["eventVersion"] == "1.09"
    assert normalized["raw_event"]["eventType"] == "AwsApiCall"
    assert normalized["raw_event"]["sharedEventID"] == "shared-event-001"
    assert normalized["raw_event"]["customField"] == {"nested": [1, 2, 3]}


def test_normalize_account_id_falls_back_to_identity_account():
    event = make_event()
    event.pop("recipientAccountId")

    normalized = normalize_event(event)

    assert normalized["account_id"] == "111122223333"


def test_normalize_event_id_falls_back_to_lowercase_d():
    event = make_event()
    event.pop("eventID")
    event["eventId"] = "lowercase-event-id"

    normalized = normalize_event(event)

    assert normalized["event_id"] == "lowercase-event-id"


def test_normalize_rejects_non_mapping_event():
    with pytest.raises(TypeError, match="mapping"):
        normalize_event(["not", "an", "event"])


def test_sample_dataset_normalizes_with_expected_fields():
    content = SAMPLE_PATH.read_text(encoding="utf-8")
    parsed = parse_cloudtrail(content)

    assert parsed.ok is True

    normalized_events = [normalize_event(event) for event in parsed.events]

    assert len(normalized_events) == 6
    assert all(set(event) == EXPECTED_KEYS for event in normalized_events)

    console_success = next(
        event
        for event in normalized_events
        if event["event_name"] == "ConsoleLogin"
        and event["response_elements"].get("ConsoleLogin") == "Success"
    )
    assert console_success["identity_type"] == "IAMUser"
    assert console_success["username"] == "alice"

    console_failure = next(
        event
        for event in normalized_events
        if event["event_name"] == "ConsoleLogin"
        and event["response_elements"].get("ConsoleLogin") == "Failure"
    )
    assert console_failure["error_code"] == "Failed authentication"
    assert console_failure["username"] == "bob"

    assumed_role = next(
        event
        for event in normalized_events
        if event["event_name"] == "DescribeInstances"
    )
    assert assumed_role["identity_type"] == "AssumedRole"
    assert assumed_role["username"] is None
    assert assumed_role["read_only"] is True
    assert assumed_role["management_event"] is True

    for normalized, original in zip(normalized_events, parsed.events):
        assert normalized["raw_event"] == original
