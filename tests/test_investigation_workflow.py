"""Integration tests for investigation, detection, reports, and Flask routes."""

import csv
import io
import json
import re
import sqlite3
from pathlib import Path

import database
import pytest
from services.detection_engine import analyze_dataset
from services.report_generator import (
    build_report,
    csv_safe,
    report_to_csv,
    report_to_json,
)
from services.risk_scorer import score_findings
from services.timeline_builder import build_timeline
from services.identity_keys import encode_identity_key
from services.query_filters import normalize_time_bound
from tests.support import connect, ingest, make_app, make_event, upload


SAMPLE_PATH = (
    Path(__file__).resolve().parents[1]
    / "sample_data"
    / "cloudtrail_sample.json"
)


def _event(
    event_id,
    name,
    time,
    *,
    source="iam.amazonaws.com",
    ip="192.0.2.10",
    access_key="AKIAIOSFODNN7EXAMPLE",
    **kwargs,
):
    return make_event(
        event_id=event_id,
        event_name=name,
        event_source=source,
        event_time=time,
        source_ip=ip,
        access_key_id=access_key,
        **kwargs,
    )


def _csrf_token(response):
    match = re.search(rb'name="_csrf_token" value="([^"]+)"', response.data)
    if match is None:
        raise AssertionError("Page did not render a CSRF token")
    return match.group(1).decode("ascii")


def test_detection_rules_keep_evidence_and_ignore_failed_mutations(tmp_path):
    connection = connect(tmp_path)
    try:
        events = [
            _event(
                "login-fail-1",
                "ConsoleLogin",
                "2026-11-05T10:00:00Z",
                source="signin.amazonaws.com",
                response_elements={"ConsoleLogin": "Failure"},
                error_code="Failed authentication",
            ),
            _event(
                "login-fail-2",
                "ConsoleLogin",
                "2026-11-05T10:01:00Z",
                source="signin.amazonaws.com",
                response_elements={"ConsoleLogin": "Failure"},
                error_code="Failed authentication",
            ),
            _event(
                "login-fail-3",
                "ConsoleLogin",
                "2026-11-05T10:02:00Z",
                source="signin.amazonaws.com",
                response_elements={"ConsoleLogin": "Failure"},
                error_code="Failed authentication",
            ),
            _event(
                "login-success",
                "ConsoleLogin",
                "2026-11-05T10:10:00Z",
                source="signin.amazonaws.com",
                ip="203.0.113.11",
                response_elements={"ConsoleLogin": "Success"},
            ),
            _event(
                "assume-denied",
                "AssumeRole",
                "2026-11-05T10:12:00Z",
                source="sts.amazonaws.com",
                error_code="AccessDenied",
            ),
            _event(
                "key-created",
                "CreateAccessKey",
                "2026-11-05T10:20:00Z",
                response_elements={
                    "accessKey": {
                        "accessKeyId": "AKIANEWKEY0000000001",
                        "userName": "alice",
                    }
                },
            ),
            _event(
                "key-used",
                "DescribeInstances",
                "2026-11-05T10:25:00Z",
                source="ec2.amazonaws.com",
                access_key="AKIANEWKEY0000000001",
            ),
            _event(
                "key-deleted",
                "DeleteAccessKey",
                "2026-11-05T10:30:00Z",
            ),
            _event(
                "key-updated",
                "UpdateAccessKey",
                "2026-11-05T10:35:00Z",
            ),
            _event(
                "policy-attached",
                "AttachUserPolicy",
                "2026-11-05T10:40:00Z",
            ),
            _event(
                "policy-version",
                "CreatePolicyVersion",
                "2026-11-05T10:45:00Z",
            ),
            _event(
                "trust-updated",
                "UpdateAssumeRolePolicy",
                "2026-11-05T10:50:00Z",
            ),
            _event(
                "group-added",
                "AddUserToGroup",
                "2026-11-05T10:55:00Z",
            ),
            _event(
                "logging-stopped",
                "StopLogging",
                "2026-11-05T11:00:00Z",
                source="cloudtrail.amazonaws.com",
            ),
            _event(
                "trail-updated",
                "UpdateTrail",
                "2026-11-05T11:05:00Z",
                source="cloudtrail.amazonaws.com",
            ),
            _event(
                "bucket-deleted",
                "DeleteBucket",
                "2026-11-05T11:10:00Z",
                source="s3.amazonaws.com",
            ),
            _event(
                "user-created",
                "CreateUser",
                "2026-11-05T11:15:00Z",
            ),
            _event(
                "secret-read",
                "GetSecretValue",
                "2026-11-05T11:20:00Z",
                source="secretsmanager.amazonaws.com",
            ),
            _event(
                "logging-denied",
                "StopLogging",
                "2026-11-05T11:25:00Z",
                source="cloudtrail.amazonaws.com",
                error_code="AccessDenied",
            ),
            _event(
                "policy-denied",
                "AttachUserPolicy",
                "2026-11-05T11:26:00Z",
                error_code="AccessDenied",
            ),
            _event(
                "bucket-denied",
                "DeleteBucket",
                "2026-11-05T11:27:00Z",
                source="s3.amazonaws.com",
                error_code="AccessDenied",
            ),
            _event(
                "secret-denied",
                "GetSecretValue",
                "2026-11-05T11:28:00Z",
                source="secretsmanager.amazonaws.com",
                error_code="AccessDenied",
            ),
            _event(
                "key-create-denied",
                "CreateAccessKey",
                "2026-11-05T11:29:00Z",
                error_code="AccessDenied",
            ),
        ]
        result = ingest(connection, events)
        first = analyze_dataset(connection, result.dataset_id, {})
        rows = database.list_findings(
            connection, dataset_id=result.dataset_id, limit=100
        )
        rule_ids = {row["rule_id"] for row in rows}

        assert {
            "auth.repeated_console_login_failures",
            "auth.console_login_failure_then_success",
            "auth.authentication_error",
            "access_key.createaccesskey",
            "access_key.deleteaccesskey",
            "access_key.updateaccesskey",
            "access_key.use_after_creation",
            "privilege.policy_change",
            "privilege.policy_version_change",
            "privilege.trust_policy_change",
            "privilege.group_membership_change",
            "logging.trail_disabled_or_deleted",
            "logging.trail_configuration_change",
            "sensitive.resource_deletion",
            "sensitive.high_impact_admin",
            "sensitive.secrets_access",
        } <= rule_ids
        assert sum(
            row["rule_id"] == "access_key.createaccesskey" for row in rows
        ) == 1
        assert first["finding_count"] == len(rows)

        finding_by_rule = {row["rule_id"]: row for row in rows}
        assert "3 failed ConsoleLogin attempts" in finding_by_rule[
            "auth.repeated_console_login_failures"
        ]["trigger_reason"]
        assert finding_by_rule[
            "auth.console_login_failure_then_success"
        ]["source_ip"] == "192.0.2.10"

        evidence = json.loads(
            finding_by_rule["logging.trail_disabled_or_deleted"]["evidence_json"]
        )
        assert evidence["events"][0]["event_id"] == "logging-stopped"

        second = analyze_dataset(connection, result.dataset_id, {})
        assert second["finding_count"] == first["finding_count"]
        assert len(
            database.get_analysis_runs(connection, result.dataset_id)
        ) == 2
        assert database.count_findings(
            connection, dataset_id=result.dataset_id
        ) == first["finding_count"]
    finally:
        connection.close()


def test_analysis_replacement_rolls_back_if_finding_persistence_fails(tmp_path):
    connection = connect(tmp_path)
    try:
        result = ingest(
            connection,
            [
                make_event(
                    event_id="user-created",
                    event_name="CreateUser",
                    event_source="iam.amazonaws.com",
                )
            ],
        )
        analyze_dataset(connection, result.dataset_id, {})
        original_count = database.count_findings(
            connection, dataset_id=result.dataset_id
        )
        connection.execute(
            """
            CREATE TRIGGER reject_finding_insert
            BEFORE INSERT ON findings
            BEGIN
                SELECT RAISE(ABORT, 'simulated persistence failure');
            END;
            """
        )
        connection.commit()

        with pytest.raises(sqlite3.IntegrityError):
            analyze_dataset(connection, result.dataset_id, {})

        assert database.count_findings(
            connection, dataset_id=result.dataset_id
        ) == original_count
        assert len(
            database.get_analysis_runs(connection, result.dataset_id)
        ) == 1
    finally:
        connection.close()


def test_assumed_role_is_not_attributed_to_session_issuer_as_human(tmp_path):
    connection = connect(tmp_path)
    try:
        event = make_event(
            event_id="assumed-session",
            identity_type="AssumedRole",
            username=None,
            principal_id="AROAEXAMPLE:session-001",
            principal_arn=(
                "arn:aws:sts::111122223333:"
                "assumed-role/IncidentResponse/session-001"
            ),
        )
        result = ingest(connection, [event])
        rows = database.list_identities(connection, limit=10)

        assert result.inserted_records == 1
        assert len(rows) == 1
        assert rows[0]["identity_key"].startswith("arn|arn:aws:sts:")
        assert rows[0]["username"] is None
    finally:
        connection.close()


def test_timeline_orders_offsets_and_filters_by_actual_time(tmp_path):
    connection = connect(tmp_path)
    try:
        events = [
            make_event(
                event_id="later-utc",
                event_name="DescribeInstances",
                event_time="2026-11-05T10:30:00Z",
            ),
            make_event(
                event_id="earlier-offset",
                event_name="DescribeVolumes",
                event_time="2026-11-05T15:00:00+05:00",
            ),
        ]
        result = ingest(connection, events)
        timeline = build_timeline(
            connection,
            {"dataset_id": result.dataset_id},
            per_page=20,
        )

        assert [event["event_id"] for event in timeline["events"]] == [
            "earlier-offset",
            "later-utc",
        ]
        assert database.count_events(
            connection,
            dataset_id=result.dataset_id,
            start="2026-11-05T10:15:00Z",
        ) == 1
    finally:
        connection.close()


def test_date_end_filter_includes_fractional_seconds_on_the_selected_day(
    tmp_path,
):
    connection = connect(tmp_path)
    try:
        result = ingest(
            connection,
            [
                make_event(
                    event_id="last-second",
                    event_time="2026-11-05T23:59:59.500Z",
                ),
                make_event(
                    event_id="next-day",
                    event_time="2026-11-06T00:00:00Z",
                ),
            ],
        )

        assert database.count_events(
            connection,
            dataset_id=result.dataset_id,
            end=normalize_time_bound("2026-11-05", end=True),
        ) == 1
    finally:
        connection.close()


def test_risk_score_is_bounded_explainable_and_deduplicated():
    findings = [
        {
            "id": 1,
            "rule_id": "logging.stop",
            "dedupe_key": "stop:1",
            "severity": "critical",
        },
        {
            "id": 2,
            "rule_id": "logging.stop",
            "dedupe_key": "stop:1",
            "severity": "critical",
        },
    ] + [
        {
            "id": index,
            "rule_id": "admin.change",
            "dedupe_key": f"change:{index}",
            "severity": "high",
        }
        for index in range(3, 20)
    ]

    score = score_findings(findings)

    assert 0 <= score["score"] <= score["max_score"] == 100
    assert score["score"] == 100
    assert score["unique_findings"] == 18
    assert score["duplicate_findings_ignored"] == 1
    assert "not a probability" in score["disclaimer"]


def test_reports_redact_secrets_and_escape_csv_formulas(tmp_path):
    connection = connect(tmp_path)
    try:
        event = make_event(
            event_id="sensitive-event",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            request_parameters={
                "secretId": "prod/db",
                "clientSecret": "do-not-export",
            },
        )
        result = ingest(
            connection,
            [
                event,
                make_event(
                    event_id="trail-stop",
                    event_name="StopLogging",
                    event_source="cloudtrail.amazonaws.com",
                    event_time="2026-11-05T10:01:00Z",
                ),
            ],
            filename='=HYPERLINK("https://example.invalid").json',
        )
        analyze_dataset(connection, result.dataset_id, {})
        report = build_report(
            connection,
            dataset_id=result.dataset_id,
            analysis_time="2026-11-05T12:00:00Z",
            event_limit=1,
            finding_limit=10,
        )

        assert "do-not-export" not in report_to_json(report)
        assert report["summary"]["event_count"] == 2
        assert report["summary"]["finding_count"] == 2
        assert report["coverage"]["events_omitted"] == 1
        assert report["coverage"]["findings_omitted"] == 0
        limited_report = build_report(
            connection,
            dataset_id=result.dataset_id,
            analysis_time="2026-11-05T12:00:00Z",
            event_limit=1,
            finding_limit=1,
        )
        assert limited_report["coverage"]["findings_omitted"] == 1
        secret_finding = next(
            finding for finding in report["findings"]
            if finding["rule_id"] == "sensitive.secrets_access"
        )
        assert secret_finding["evidence"]["events"][0][
            "request_parameters"
        ]["clientSecret"] == "[REDACTED]"
        rows = list(csv.DictReader(io.StringIO(report_to_csv(report))))
        dataset_row = next(row for row in rows if row["record_type"] == "dataset")
        assert dataset_row["dataset_filename"].startswith("'=")
    finally:
        connection.close()


def test_csv_safe_neutralizes_control_and_bom_prefixes():
    for value in ("=1+1", "  =1+1", "\ufeff=1+1", "\x01=1+1", "\t=1+1"):
        assert csv_safe(value).startswith("'")


def test_flask_sample_dataset_investigation_workflow(tmp_path):
    app = make_app(tmp_path)
    client = app.test_client()
    sample = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    sample["Records"][2]["requestParameters"] = {
        "roleArn": "arn:aws:iam::111122223333:role/IncidentResponse",
        "sessionToken": "sensitive-session-token",
    }

    empty_dashboard = client.get("/dashboard")
    assert empty_dashboard.status_code == 200
    assert b"No evidence stored yet" in empty_dashboard.data

    response = upload(client, sample["Records"], filename="sample.json")
    assert response.status_code == 200
    with app.app_context():
        connection = database.get_db()
        dataset_id = connection.execute(
            "SELECT id FROM datasets WHERE filename = ?", ("sample.json",)
        ).fetchone()["id"]

    survivor = upload(
        client,
        [make_event(event_id="survivor-event")],
        filename="survivor.json",
    )
    assert survivor.status_code == 200

    assert b"Events analyzed" in client.get("/dashboard").data
    assert b"sample.json" in client.get("/datasets").data
    identity_page = client.get("/identities?search=alice")
    assert identity_page.status_code == 200
    assert b"alice" in identity_page.data
    events_page = client.get("/events?search=alice")
    assert events_page.status_code == 200
    assert b"ConsoleLogin" in events_page.data

    with app.app_context():
        connection = database.get_db()
        event = database.list_events(
            connection, dataset_id=dataset_id, event_name="AssumeRole"
        )[0]
        identity = database.list_identities(
            connection, search="alice", limit=1
        )[0]
        token = encode_identity_key(identity["identity_key"])
    detail = client.get(f"/events/{event['id']}")
    assert detail.status_code == 200
    assert b"sensitive-session-token" not in detail.data
    assert b"[REDACTED]" in detail.data
    assert client.get(f"/identities/{token}").status_code == 200

    findings_page = client.get("/findings")
    run = client.post(
        "/analysis/run",
        data={
            "_csrf_token": _csrf_token(findings_page),
            "dataset_id": str(dataset_id),
        },
        follow_redirects=True,
    )
    assert run.status_code == 200
    assert b"Analysis complete" in run.data
    assert b"access_key.createaccesskey" in run.data

    with app.app_context():
        connection = database.get_db()
        finding = database.list_findings(
            connection, dataset_id=dataset_id, limit=1
        )[0]
    assert client.get(f"/findings/{finding['id']}").status_code == 200
    timeline = client.get(f"/timeline?dataset_id={dataset_id}")
    assert timeline.status_code == 200
    assert b"ConsoleLogin" in timeline.data
    assert b"CreateAccessKey" in timeline.data

    report_page = client.get(f"/reports?dataset_id={dataset_id}")
    assert report_page.status_code == 200
    json_report = client.get(f"/reports/json?dataset_id={dataset_id}")
    csv_report = client.get(f"/reports/csv?dataset_id={dataset_id}")
    assert json_report.status_code == csv_report.status_code == 200
    assert json.loads(json_report.data)["summary"]["event_count"] == 6
    assert b"finding" in csv_report.data

    delete_page = client.get(f"/datasets/{dataset_id}/delete")
    delete = client.post(
        f"/datasets/{dataset_id}/delete",
        data={
            "_csrf_token": _csrf_token(delete_page),
            "confirm": "yes",
        },
        follow_redirects=True,
    )
    assert delete.status_code == 200
    assert b"Dataset history" in delete.data
    assert b"Events analyzed" in client.get("/dashboard").data
    with app.app_context():
        connection = database.get_db()
        metrics = database.get_dashboard_metrics(connection)
        datasets = database.list_datasets(connection)
        assert metrics["dataset_count"] == 1
        assert metrics["event_count"] == 1
        assert metrics["finding_count"] == 0
        assert [row["filename"] for row in datasets] == ["survivor.json"]
        assert connection.execute(
            "SELECT event_id FROM events"
        ).fetchone()["event_id"] == "survivor-event"
        assert connection.execute(
            "SELECT COUNT(*) FROM analysis_runs"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM finding_events"
        ).fetchone()[0] == 0
