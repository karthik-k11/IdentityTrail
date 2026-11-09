"""Tests for the CloudTrail JSON parser."""

import json
from pathlib import Path

import pytest

from services.cloudtrail_parser import (
    CloudTrailParseError,
    parse_cloudtrail,
)


SAMPLE_PATH = (
    Path(__file__).resolve().parents[1]
    / "sample_data"
    / "cloudtrail_sample.json"
)


def make_event(event_id):
    return {
        "eventID": event_id,
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "us-east-1",
    }


def test_parse_records_array():
    first = make_event("event-001")
    second = make_event("event-002")

    result = parse_cloudtrail(json.dumps({"Records": [first, second]}))

    assert result.total_records == 2
    assert result.parsed_records == 2
    assert result.failed_records == 0
    assert result.errors == []
    assert result.ok is True
    assert result.events == [first, second]


def test_parse_single_event_object():
    event = make_event("event-001")

    result = parse_cloudtrail(json.dumps(event))

    assert result.total_records == 1
    assert result.parsed_records == 1
    assert result.failed_records == 0
    assert result.events == [event]


def test_parse_list_of_events():
    first = make_event("event-001")
    second = make_event("event-002")

    result = parse_cloudtrail(json.dumps([first, second]))

    assert result.total_records == 2
    assert result.parsed_records == 2
    assert result.failed_records == 0
    assert result.events == [first, second]


def test_parse_bytes_input_with_utf8_bom():
    event = make_event("event-001")
    content = b"\xef\xbb\xbf" + json.dumps({"Records": [event]}).encode("utf-8")

    result = parse_cloudtrail(content)

    assert result.parsed_records == 1
    assert result.events == [event]


def test_parse_empty_records_array():
    result = parse_cloudtrail('{"Records": []}')

    assert result.total_records == 0
    assert result.parsed_records == 0
    assert result.failed_records == 0
    assert result.errors == []
    assert result.events == []
    assert result.ok is True


@pytest.mark.parametrize("content", ["", "   ", "\n\t"])
def test_parse_empty_input_rejected(content):
    with pytest.raises(CloudTrailParseError, match="empty"):
        parse_cloudtrail(content)


def test_parse_malformed_json_rejected():
    with pytest.raises(CloudTrailParseError, match="Malformed JSON"):
        parse_cloudtrail('{"Records": [}')


def test_parse_invalid_utf8_rejected():
    with pytest.raises(CloudTrailParseError, match="valid UTF-8"):
        parse_cloudtrail(b"\xff\xfe\xfd")


@pytest.mark.parametrize(
    "content",
    ['"a string"', "42", "null", "true"],
)
def test_parse_invalid_top_level_structure_rejected(content):
    with pytest.raises(CloudTrailParseError, match="top-level structure"):
        parse_cloudtrail(content)


def test_parse_records_field_must_be_an_array():
    with pytest.raises(CloudTrailParseError, match="Records"):
        parse_cloudtrail('{"Records": {"eventID": "event-001"}}')


def test_parse_non_object_records_are_reported():
    valid_event = make_event("event-001")
    payload = {
        "Records": [
            valid_event,
            "not-an-object",
            123,
            None,
            ["nested"],
        ]
    }

    result = parse_cloudtrail(json.dumps(payload))

    assert result.total_records == 5
    assert result.parsed_records == 1
    assert result.failed_records == 4
    assert result.ok is False
    assert result.events == [valid_event]
    assert [error.position for error in result.errors] == [2, 3, 4, 5]
    assert all("not a JSON object" in error.message for error in result.errors)


def test_parse_mixed_valid_and_invalid_list_records():
    valid_event = make_event("event-001")

    result = parse_cloudtrail(json.dumps([valid_event, "invalid", 7]))

    assert result.total_records == 3
    assert result.parsed_records == 1
    assert result.failed_records == 2
    assert result.events == [valid_event]
    assert [error.position for error in result.errors] == [2, 3]


def test_parse_preserves_original_event_dictionaries():
    event = make_event("event-001")
    event["requestParameters"] = {"instancesSet": {}}
    event["resources"] = [{"ARN": "arn:aws:ec2:us-east-1:111122223333:instance/i-123"}]

    result = parse_cloudtrail(json.dumps({"Records": [event]}))

    assert result.events[0] == event
    assert result.events[0]["requestParameters"] == {"instancesSet": {}}
    assert result.events[0]["resources"] == event["resources"]


def test_parse_unsupported_input_type_rejected():
    with pytest.raises(TypeError, match="string or bytes"):
        parse_cloudtrail(123)


def test_parse_sample_dataset():
    content = SAMPLE_PATH.read_text(encoding="utf-8")

    result = parse_cloudtrail(content)

    assert result.ok is True
    assert result.total_records == 6
    assert result.parsed_records == 6
    assert result.failed_records == 0
    assert result.errors == []
    assert {
        event["eventName"] for event in result.events
    } == {
        "ConsoleLogin",
        "AssumeRole",
        "CreateAccessKey",
        "AttachUserPolicy",
        "DescribeInstances",
    }
