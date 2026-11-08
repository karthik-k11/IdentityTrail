"""Validation and transactional ingestion for CloudTrail uploads."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import database
from services.cloudtrail_parser import CloudTrailParseError, parse_cloudtrail
from services.event_normalizer import normalize_event
from services.identity_keys import build_identity_key


REQUIRED_EVENT_FIELDS = (
    "eventVersion",
    "userIdentity",
    "eventName",
    "eventSource",
    "eventTime",
)

SUPPORTED_IDENTITY_TYPES = frozenset({
    "IAMUser",
    "AssumedRole",
    "Root",
    "FederatedUser",
    "AWSService",
    "AWSAccount",
})

_EVENT_VERSION_PATTERN = re.compile(r"\d+\.\d+")


@dataclass(frozen=True)
class IngestionIssue:
    """A safe, user-facing description of a failed record."""

    position: int | None
    message: str


@dataclass(frozen=True)
class IngestionResult:
    """Summary of a successful or partially successful ingestion."""

    dataset_id: int
    filename: str
    file_size: int
    uploaded_at: str
    total_records: int
    parsed_records: int
    failed_records: int
    duplicate_records: int
    inserted_records: int
    errors: list[IngestionIssue]


class IngestionError(Exception):
    """Base class for expected ingestion failures."""

    def __init__(
        self,
        message: str,
        errors: list[IngestionIssue] | None = None,
    ):
        super().__init__(message)
        self.errors = errors or []


class IngestionValidationError(IngestionError):
    """Raised when uploaded content is not a valid CloudTrail dataset."""


class IngestionPersistenceError(IngestionError):
    """Raised when the database rejects or cannot complete an ingestion."""


def ingest_cloudtrail(
    connection,
    filename,
    content,
    max_events,
):
    """Parse, normalize, and persist a CloudTrail upload atomically.

    The dataset and all event inserts commit together. If any database
    insertion fails, the transaction is rolled back by the database helper and
    :class:`IngestionPersistenceError` is raised with a safe message.
    """
    file_size = _content_size(content)

    try:
        parsed = parse_cloudtrail(content)
    except CloudTrailParseError as exc:
        raise IngestionValidationError(str(exc)) from exc

    if parsed.total_records > max_events:
        raise IngestionValidationError(
            f"The upload contains {parsed.total_records} records, which "
            f"exceeds the maximum of {max_events}."
        )

    if parsed.total_records == 0:
        raise IngestionValidationError(
            "The uploaded file contains no CloudTrail records."
        )

    errors = [
        IngestionIssue(position=error.position, message=error.message)
        for error in parsed.errors
    ]

    valid_events = []
    for event in parsed.events:
        missing_fields = validate_cloudtrail_event(event)
        if missing_fields:
            errors.append(
                IngestionIssue(
                    position=None,
                    message=(
                        f"{_event_label(event)} is not a valid CloudTrail "
                        "event: missing or invalid "
                        f"{', '.join(missing_fields)}."
                    ),
                )
            )
            continue
        valid_events.append(event)

    parsed_records = len(valid_events)
    failed_records = len(errors)

    if parsed_records == 0:
        raise IngestionValidationError(
            "The uploaded JSON does not contain valid CloudTrail events.",
            errors=errors,
        )

    normalized_events = [normalize_event(event) for event in valid_events]

    event_rows = []
    seen_event_ids = set()
    duplicate_records = 0

    for normalized in normalized_events:
        event_id = normalized["event_id"]
        if event_id is not None and event_id in seen_event_ids:
            duplicate_records += 1
            continue
        if event_id is not None:
            seen_event_ids.add(event_id)
        event_rows.append(_build_event_row(normalized))

    try:
        dataset_id, uploaded_at = database.insert_dataset_with_events(
            connection,
            filename=filename,
            file_size=file_size,
            total_events=parsed.total_records,
            parsed_events=parsed_records,
            failed_events=failed_records,
            events=event_rows,
        )
    except sqlite3.Error as exc:
        raise IngestionPersistenceError(
            "The upload could not be saved to the database. "
            "No data was committed."
        ) from exc

    return IngestionResult(
        dataset_id=dataset_id,
        filename=filename,
        file_size=file_size,
        uploaded_at=uploaded_at,
        total_records=parsed.total_records,
        parsed_records=parsed_records,
        failed_records=failed_records,
        duplicate_records=duplicate_records,
        inserted_records=len(event_rows),
        errors=errors,
    )


def validate_cloudtrail_event(event) -> list[str]:
    """Return required CloudTrail fields that are missing or invalid.

    Only the core record structure is required. Optional CloudTrail fields
    such as ``sourceIPAddress``, ``userAgent``, ``requestParameters``, and
    ``responseElements`` are intentionally not required.
    """
    invalid_fields = []
    for field in REQUIRED_EVENT_FIELDS:
        value = event.get(field)

        if field == "eventVersion":
            if not _is_valid_event_version(value):
                invalid_fields.append(field)
        elif field == "userIdentity":
            if not _is_valid_user_identity(value):
                invalid_fields.append(field)
        elif not isinstance(value, str) or not value.strip():
            invalid_fields.append(field)

    return invalid_fields


def _is_valid_event_version(value) -> bool:
    if not isinstance(value, str):
        return False
    return _EVENT_VERSION_PATTERN.fullmatch(value.strip()) is not None


def _is_valid_user_identity(value) -> bool:
    if not isinstance(value, Mapping):
        return False

    identity_type = value.get("type")
    return (
        isinstance(identity_type, str)
        and identity_type.strip() in SUPPORTED_IDENTITY_TYPES
    )


def _content_size(content) -> int:
    if isinstance(content, bytes):
        return len(content)
    if isinstance(content, str):
        return len(content.encode("utf-8"))
    raise TypeError("content must be a string or bytes")


def _event_label(event) -> str:
    event_id = event.get("eventID") or event.get("eventId")
    if isinstance(event_id, str) and event_id.strip():
        return f"Event {event_id}"

    event_name = event.get("eventName")
    if isinstance(event_name, str) and event_name.strip():
        return f"Event {event_name}"

    return "An event"


def _build_event_row(normalized: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": normalized["event_id"],
        "event_time": normalized["event_time"],
        "event_name": normalized["event_name"],
        "event_source": normalized["event_source"],
        "aws_region": normalized["aws_region"],
        "account_id": normalized["account_id"],
        "username": normalized["username"],
        "principal_id": normalized["principal_id"],
        "principal_arn": normalized["principal_arn"],
        "identity_type": normalized["identity_type"],
        "identity_key": build_identity_key(
            normalized["principal_arn"],
            normalized["principal_id"],
            normalized["username"],
        ),
        "access_key_id": normalized["access_key_id"],
        "source_ip": normalized["source_ip"],
        "user_agent": normalized["user_agent"],
        "raw_event_json": json.dumps(
            normalized["raw_event"], ensure_ascii=False
        ),
        "normalized_event_json": json.dumps(
            normalized, ensure_ascii=False
        ),
    }
