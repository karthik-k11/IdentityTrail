"""Safe parsing for AWS CloudTrail JSON payloads."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


class CloudTrailParseError(ValueError):
    """Raised when content cannot be parsed as a CloudTrail JSON payload."""


@dataclass(frozen=True)
class ParseError:
    """A record-level parsing failure.

    Positions are one-based so they match how records are presented to users.
    """

    position: int | None
    message: str


@dataclass(frozen=True)
class ParseResult:
    """Structured result of parsing a CloudTrail payload."""

    events: list[dict[str, Any]]
    errors: list[ParseError]
    total_records: int
    parsed_records: int
    failed_records: int

    @property
    def ok(self) -> bool:
        """Return True when no record-level errors were encountered."""
        return self.failed_records == 0


def parse_cloudtrail(content: str | bytes) -> ParseResult:
    """Parse CloudTrail content into original event dictionaries.

    Supported top-level shapes are a standard ``{"Records": [...]}`` object,
    a single event object, or a list of event objects. Fatal structural issues
    raise :class:`CloudTrailParseError`; invalid individual records are reported
    in the result without discarding valid events.

    Record positions in :class:`ParseResult` are one-based.
    """
    text = _decode_content(content)
    if not text.strip():
        raise CloudTrailParseError("CloudTrail content is empty")

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CloudTrailParseError(
            f"Malformed JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc

    records = _extract_records(payload)
    events: list[dict[str, Any]] = []
    errors: list[ParseError] = []

    for position, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            errors.append(
                ParseError(
                    position=position,
                    message=f"Record at position {position} is not a JSON object",
                )
            )
            continue
        events.append(record)

    return ParseResult(
        events=events,
        errors=errors,
        total_records=len(records),
        parsed_records=len(events),
        failed_records=len(errors),
    )


def _decode_content(content: str | bytes) -> str:
    if isinstance(content, bytes):
        try:
            return content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise CloudTrailParseError(
                "CloudTrail content is not valid UTF-8"
            ) from exc

    if isinstance(content, str):
        return content.lstrip("\ufeff")

    raise TypeError("content must be a string or bytes")


def _extract_records(payload: Any) -> list[Any]:
    if isinstance(payload, dict):
        if "Records" in payload:
            records = payload["Records"]
            if not isinstance(records, list):
                raise CloudTrailParseError(
                    "The 'Records' field must be a JSON array"
                )
            return records
        return [payload]

    if isinstance(payload, list):
        return payload

    raise CloudTrailParseError(
        f"Unsupported CloudTrail top-level structure: {type(payload).__name__}"
    )
