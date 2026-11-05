"""SQLite database foundation and data-access functions for IdentityTrail.

This module owns connection management, idempotent schema initialization, and
the parameterized SQL used by the application. Flask route handlers should call
these functions rather than constructing SQL directly.
"""

import json
import sqlite3
from pathlib import Path

from flask import current_app, g

from services.identity_keys import build_identity_key


SEVERITY_ORDER = ("critical", "high", "medium", "low")

_TABLE_SQL = """
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
    principal_id TEXT,
    principal_arn TEXT,
    identity_type TEXT,
    identity_key TEXT,
    access_key_id TEXT,
    source_ip TEXT,
    user_agent TEXT,
    raw_event_json TEXT,
    normalized_event_json TEXT,
    FOREIGN KEY (dataset_id) REFERENCES datasets (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    description TEXT NOT NULL,
    identity TEXT,
    identity_key TEXT,
    principal_arn TEXT,
    source_ip TEXT,
    event_time TEXT,
    detection_timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    trigger_reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    recommended_steps_json TEXT NOT NULL DEFAULT '[]',
    dedupe_key TEXT NOT NULL,
    FOREIGN KEY (dataset_id) REFERENCES datasets (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS finding_events (
    finding_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    PRIMARY KEY (finding_id, event_id),
    FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS analysis_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id INTEGER NOT NULL,
    analyzed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finding_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (dataset_id) REFERENCES datasets (id) ON DELETE CASCADE
);
"""

_INDEX_SQL = """
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

CREATE INDEX IF NOT EXISTS idx_events_identity_key
    ON events (identity_key);

CREATE INDEX IF NOT EXISTS idx_events_source_ip
    ON events (source_ip);

CREATE INDEX IF NOT EXISTS idx_events_event_source
    ON events (event_source);

CREATE INDEX IF NOT EXISTS idx_events_dataset_event_time
    ON events (dataset_id, event_time);

CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_dataset_dedupe
    ON findings (dataset_id, dedupe_key);

CREATE INDEX IF NOT EXISTS idx_findings_dataset_id
    ON findings (dataset_id);

CREATE INDEX IF NOT EXISTS idx_findings_severity
    ON findings (severity);

CREATE INDEX IF NOT EXISTS idx_findings_category
    ON findings (category);

CREATE INDEX IF NOT EXISTS idx_findings_rule_id
    ON findings (rule_id);

CREATE INDEX IF NOT EXISTS idx_findings_identity_key
    ON findings (identity_key);

CREATE INDEX IF NOT EXISTS idx_findings_detection_timestamp
    ON findings (detection_timestamp);

CREATE INDEX IF NOT EXISTS idx_finding_events_event_id
    ON finding_events (event_id);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_dataset_id
    ON analysis_runs (dataset_id);
"""

_EVENT_MIGRATION_COLUMNS = (
    ("principal_id", "TEXT"),
    ("identity_type", "TEXT"),
    ("identity_key", "TEXT"),
)

SEVERITY_SORT_SQL = """
CASE severity
    WHEN 'critical' THEN 0
    WHEN 'high' THEN 1
    WHEN 'medium' THEN 2
    WHEN 'low' THEN 3
    ELSE 4
END
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
    """Create or safely upgrade the IdentityTrail schema."""
    connection = get_connection(database_path)
    try:
        connection.executescript(_TABLE_SQL)
        _migrate_events_table(connection)
        _backfill_event_identity(connection)
        connection.executescript(_INDEX_SQL)
        connection.commit()
    finally:
        connection.close()


def _migrate_events_table(connection):
    """Add optional identity columns without touching existing rows."""
    columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(events)")
    }
    for name, column_type in _EVENT_MIGRATION_COLUMNS:
        if name not in columns:
            connection.execute(
                f"ALTER TABLE events ADD COLUMN {name} {column_type}"
            )


def _backfill_event_identity(connection):
    """Populate identity columns for events created before this schema."""
    rows = connection.execute(
        """
        SELECT id, username, principal_arn, normalized_event_json,
               principal_id, identity_type, identity_key
        FROM events
        WHERE identity_key IS NULL
           OR principal_id IS NULL
           OR identity_type IS NULL
        """
    ).fetchall()

    for row in rows:
        normalized = {}
        if row["normalized_event_json"]:
            try:
                loaded = json.loads(row["normalized_event_json"])
                if isinstance(loaded, dict):
                    normalized = loaded
            except (ValueError, TypeError):
                normalized = {}

        principal_id = row["principal_id"] or normalized.get("principal_id")
        identity_type = row["identity_type"] or normalized.get("identity_type")
        principal_arn = row["principal_arn"] or normalized.get("principal_arn")
        username = row["username"] or normalized.get("username")
        identity_key = row["identity_key"] or build_identity_key(
            principal_arn, principal_id, username
        )

        if any(
            value is not None
            for value in (principal_id, identity_type, identity_key)
        ):
            connection.execute(
                """
                UPDATE events
                SET principal_id = COALESCE(principal_id, ?),
                    identity_type = COALESCE(identity_type, ?),
                    identity_key = COALESCE(identity_key, ?)
                WHERE id = ?
                """,
                (principal_id, identity_type, identity_key, row["id"]),
            )


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
    principal_id=None,
    principal_arn=None,
    identity_type=None,
    identity_key=None,
    access_key_id=None,
    source_ip=None,
    user_agent=None,
    raw_event_json=None,
    normalized_event_json=None,
):
    """Insert a CloudTrail event and return the new event ID.

    Optional CloudTrail attributes are stored as NULL when not supplied.
    """
    if identity_key is None:
        identity_key = build_identity_key(
            principal_arn, principal_id, username
        )

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
                principal_id,
                principal_arn,
                identity_type,
                identity_key,
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
                :principal_id,
                :principal_arn,
                :identity_type,
                :identity_key,
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
                "principal_id": principal_id,
                "principal_arn": principal_arn,
                "identity_type": identity_type,
                "identity_key": identity_key,
                "access_key_id": access_key_id,
                "source_ip": source_ip,
                "user_agent": user_agent,
                "raw_event_json": raw_event_json,
                "normalized_event_json": normalized_event_json,
            },
        )
    return cursor.lastrowid


def insert_dataset_with_events(
    connection,
    *,
    filename,
    file_size,
    total_events,
    parsed_events,
    failed_events,
    events,
):
    """Insert a dataset and its events in a single transaction.

    Event rows are mappings containing the event columns excluding ``id`` and
    ``dataset_id``. Returns ``(dataset_id, uploaded_at)``.
    """
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
        dataset_id = cursor.lastrowid

        for event in events:
            parameters = dict(event)
            parameters["dataset_id"] = dataset_id
            parameters.setdefault("principal_id", None)
            parameters.setdefault("identity_type", None)
            parameters.setdefault("identity_key", None)
            connection.execute(
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
                    principal_id,
                    principal_arn,
                    identity_type,
                    identity_key,
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
                    :principal_id,
                    :principal_arn,
                    :identity_type,
                    :identity_key,
                    :access_key_id,
                    :source_ip,
                    :user_agent,
                    :raw_event_json,
                    :normalized_event_json
                )
                """,
                parameters,
            )

        dataset = connection.execute(
            "SELECT uploaded_at FROM datasets WHERE id = ?",
            (dataset_id,),
        ).fetchone()

    return dataset_id, dataset["uploaded_at"]


def list_datasets(connection):
    """Return datasets with stored event counts and analysis metadata."""
    return connection.execute(
        """
        SELECT
            d.id,
            d.filename,
            d.uploaded_at,
            d.file_size,
            d.total_events,
            d.parsed_events,
            d.failed_events,
            (
                SELECT COUNT(*)
                FROM events AS e
                WHERE e.dataset_id = d.id
            ) AS stored_events,
            (
                SELECT COUNT(*)
                FROM findings AS f
                WHERE f.dataset_id = d.id
            ) AS finding_count,
            (
                SELECT MAX(a.analyzed_at)
                FROM analysis_runs AS a
                WHERE a.dataset_id = d.id
            ) AS last_analyzed_at
        FROM datasets AS d
        ORDER BY d.uploaded_at DESC, d.id DESC
        """
    ).fetchall()


def get_dataset(connection, dataset_id):
    """Return one dataset row or ``None``."""
    return connection.execute(
        "SELECT * FROM datasets WHERE id = ?", (dataset_id,)
    ).fetchone()


def delete_dataset(connection, dataset_id):
    """Delete a dataset and everything that depends on it.

    Foreign-key cascades remove its events, findings, finding links, and
    analysis runs in the same transaction. Returns ``True`` when a row existed.
    """
    with connection:
        cursor = connection.execute(
            "DELETE FROM datasets WHERE id = ?", (dataset_id,)
        )
    return cursor.rowcount > 0


def get_dataset_events_for_analysis(connection, dataset_id):
    """Return all events for a dataset in chronological order."""
    return connection.execute(
        """
        SELECT *
        FROM events
        WHERE dataset_id = ?
        ORDER BY (julianday(event_time) IS NULL), julianday(event_time), id
        """,
        (dataset_id,),
    ).fetchall()


def replace_findings(connection, dataset_id, findings):
    """Replace a dataset's findings atomically.

    Re-analysis deletes prior findings for the dataset and inserts the current
    set, preventing duplicate findings from repeated runs. Returns the number of
    findings inserted.
    """
    with connection:
        connection.execute(
            "DELETE FROM findings WHERE dataset_id = ?", (dataset_id,)
        )

        inserted = 0
        for finding in findings:
            event_ids = sorted({
                int(event_id)
                for event_id in getattr(finding, "event_ids", ())
                if event_id is not None
            })
            cursor = connection.execute(
                """
                INSERT INTO findings (
                    dataset_id,
                    rule_id,
                    rule_name,
                    category,
                    severity,
                    description,
                    identity,
                    identity_key,
                    principal_arn,
                    source_ip,
                    event_time,
                    trigger_reason,
                    evidence_json,
                    recommended_steps_json,
                    dedupe_key
                )
                VALUES (
                    :dataset_id,
                    :rule_id,
                    :rule_name,
                    :category,
                    :severity,
                    :description,
                    :identity,
                    :identity_key,
                    :principal_arn,
                    :source_ip,
                    :event_time,
                    :trigger_reason,
                    :evidence_json,
                    :recommended_steps_json,
                    :dedupe_key
                )
                """,
                {
                    "dataset_id": dataset_id,
                    "rule_id": finding.rule_id,
                    "rule_name": finding.rule_name,
                    "category": finding.category,
                    "severity": finding.severity,
                    "description": finding.description,
                    "identity": finding.identity,
                    "identity_key": finding.identity_key,
                    "principal_arn": finding.principal_arn,
                    "source_ip": finding.source_ip,
                    "event_time": finding.event_time,
                    "trigger_reason": finding.trigger_reason,
                    "evidence_json": json.dumps(
                        finding.evidence, ensure_ascii=False, default=str
                    ),
                    "recommended_steps_json": json.dumps(
                        list(finding.recommended_steps),
                        ensure_ascii=False,
                    ),
                    "dedupe_key": finding.dedupe_key,
                },
            )
            finding_id = cursor.lastrowid

            for event_id in event_ids:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO finding_events (finding_id, event_id)
                    VALUES (?, ?)
                    """,
                    (finding_id, event_id),
                )
            inserted += 1

        connection.execute(
            """
            INSERT INTO analysis_runs (dataset_id, finding_count)
            VALUES (?, ?)
            """,
            (dataset_id, inserted),
        )

    return inserted


def _finding_filters(
    *,
    dataset_id=None,
    severity=None,
    category=None,
    rule_id=None,
    identity_key=None,
    identity_search=None,
    start=None,
    end=None,
):
    clauses = []
    parameters = []

    if dataset_id is not None:
        clauses.append("f.dataset_id = ?")
        parameters.append(dataset_id)
    if severity:
        clauses.append("f.severity = ?")
        parameters.append(severity)
    if category:
        clauses.append("f.category = ?")
        parameters.append(category)
    if rule_id:
        clauses.append("f.rule_id = ?")
        parameters.append(rule_id)
    if identity_key:
        clauses.append("f.identity_key = ?")
        parameters.append(identity_key)
    if identity_search:
        pattern = f"%{identity_search}%"
        clauses.append(
            "(f.identity LIKE ? OR f.principal_arn LIKE ? "
            "OR f.identity_key LIKE ?)"
        )
        parameters.extend([pattern, pattern, pattern])
    if start:
        clauses.append(
            """
            EXISTS (
                SELECT 1 FROM finding_events AS fe2
                JOIN events AS e2 ON e2.id = fe2.event_id
                WHERE fe2.finding_id = f.id
                  AND julianday(e2.event_time) >= julianday(?)
            )
            """
        )
        parameters.append(start)
    if end:
        clauses.append(
            """
            EXISTS (
                SELECT 1 FROM finding_events AS fe2
                JOIN events AS e2 ON e2.id = fe2.event_id
                WHERE fe2.finding_id = f.id
                  AND julianday(e2.event_time) <= julianday(?)
            )
            """
        )
        parameters.append(end)

    where = " AND ".join(clauses) if clauses else "1 = 1"
    return where, parameters


def list_findings(
    connection,
    *,
    dataset_id=None,
    severity=None,
    category=None,
    rule_id=None,
    identity_key=None,
    identity_search=None,
    start=None,
    end=None,
    limit=200,
    offset=0,
):
    """Return findings with linked event IDs, newest and most severe first."""
    where, parameters = _finding_filters(
        dataset_id=dataset_id,
        severity=severity,
        category=category,
        rule_id=rule_id,
        identity_key=identity_key,
        identity_search=identity_search,
        start=start,
        end=end,
    )
    parameters.extend([limit, offset])
    return connection.execute(
        f"""
        SELECT
            f.*,
            d.filename,
            (
                SELECT GROUP_CONCAT(fe.event_id)
                FROM finding_events AS fe
                WHERE fe.finding_id = f.id
            ) AS linked_event_ids
        FROM findings AS f
        JOIN datasets AS d ON d.id = f.dataset_id
        WHERE {where}
        ORDER BY {SEVERITY_SORT_SQL}, f.detection_timestamp DESC, f.id DESC
        LIMIT ? OFFSET ?
        """,
        parameters,
    ).fetchall()


def count_findings(
    connection,
    *,
    dataset_id=None,
    severity=None,
    category=None,
    rule_id=None,
    identity_key=None,
    identity_search=None,
    start=None,
    end=None,
):
    """Return the number of findings matching the supplied filters."""
    where, parameters = _finding_filters(
        dataset_id=dataset_id,
        severity=severity,
        category=category,
        rule_id=rule_id,
        identity_key=identity_key,
        identity_search=identity_search,
        start=start,
        end=end,
    )
    return connection.execute(
        f"SELECT COUNT(*) FROM findings AS f WHERE {where}",
        parameters,
    ).fetchone()[0]


def get_finding(connection, finding_id):
    """Return ``(finding, related_events)`` or ``(None, [])``."""
    finding = connection.execute(
        """
        SELECT
            f.*,
            d.filename,
            (
                SELECT GROUP_CONCAT(fe.event_id)
                FROM finding_events AS fe
                WHERE fe.finding_id = f.id
            ) AS linked_event_ids
        FROM findings AS f
        JOIN datasets AS d ON d.id = f.dataset_id
        WHERE f.id = ?
        """,
        (finding_id,),
    ).fetchone()
    if finding is None:
        return None, []

    events = connection.execute(
        """
        SELECT e.*
        FROM finding_events AS fe
        JOIN events AS e ON e.id = fe.event_id
        WHERE fe.finding_id = ?
        ORDER BY (julianday(e.event_time) IS NULL), julianday(e.event_time), e.id
        """,
        (finding_id,),
    ).fetchall()
    return finding, events


def get_findings_for_event(connection, event_id):
    """Return findings linked to one event, most severe first."""
    return connection.execute(
        f"""
        SELECT f.*
        FROM findings AS f
        JOIN finding_events AS fe ON fe.finding_id = f.id
        WHERE fe.event_id = ?
        ORDER BY {SEVERITY_SORT_SQL}, f.detection_timestamp DESC, f.id DESC
        """,
        (event_id,),
    ).fetchall()


def get_findings_for_events(connection, event_ids):
    """Return a mapping of event ID to findings for a collection of events."""
    if not event_ids:
        return {}
    placeholders = ",".join("?" for _ in event_ids)
    rows = connection.execute(
        f"""
        SELECT fe.event_id, f.*
        FROM finding_events AS fe
        JOIN findings AS f ON f.id = fe.finding_id
        WHERE fe.event_id IN ({placeholders})
        ORDER BY {SEVERITY_SORT_SQL}, f.detection_timestamp DESC, f.id DESC
        """,
        list(event_ids),
    ).fetchall()

    grouped = {}
    for row in rows:
        grouped.setdefault(row["event_id"], []).append(row)
    return grouped


def get_analysis_runs(connection, dataset_id=None, limit=20):
    """Return recent analysis runs, optionally limited to one dataset."""
    if dataset_id is None:
        return connection.execute(
            """
            SELECT a.*, d.filename
            FROM analysis_runs AS a
            JOIN datasets AS d ON d.id = a.dataset_id
            ORDER BY a.analyzed_at DESC, a.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return connection.execute(
        """
        SELECT a.*, d.filename
        FROM analysis_runs AS a
        JOIN datasets AS d ON d.id = a.dataset_id
        WHERE a.dataset_id = ?
        ORDER BY a.analyzed_at DESC, a.id DESC
        LIMIT ?
        """,
        (dataset_id, limit),
    ).fetchall()


def get_dashboard_metrics(connection):
    """Return aggregate dashboard counters from the database."""
    row = connection.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM datasets) AS dataset_count,
            (SELECT COUNT(*) FROM events) AS event_count,
            (
                SELECT COUNT(DISTINCT identity_key)
                FROM events
                WHERE identity_key IS NOT NULL
            ) AS identity_count,
            (
                SELECT COUNT(DISTINCT source_ip)
                FROM events
                WHERE source_ip IS NOT NULL AND TRIM(source_ip) <> ''
            ) AS source_ip_count,
            (SELECT COUNT(*) FROM findings) AS finding_count,
            (
                SELECT COUNT(*) FROM findings WHERE severity = 'critical'
            ) AS critical_count,
            (
                SELECT COUNT(*) FROM findings WHERE severity = 'high'
            ) AS high_count,
            (
                SELECT COUNT(*) FROM findings WHERE severity = 'medium'
            ) AS medium_count,
            (
                SELECT COUNT(*) FROM findings WHERE severity = 'low'
            ) AS low_count
        """
    ).fetchone()
    return dict(row)


def get_severity_counts(connection):
    """Return finding counts keyed by severity, including zero values."""
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    rows = connection.execute(
        "SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity"
    ).fetchall()
    for row in rows:
        counts[row["severity"]] = row["count"]
    return counts


def get_rule_counts(connection, limit=10):
    """Return the most frequently triggered detection rules."""
    return connection.execute(
        """
        SELECT
            rule_id,
            rule_name,
            category,
            COUNT(*) AS count,
            MAX(severity) AS sample_severity
        FROM findings
        GROUP BY rule_id, rule_name, category
        ORDER BY count DESC, rule_name ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def get_recent_findings(connection, limit=8):
    """Return the newest findings for the dashboard."""
    return connection.execute(
        """
        SELECT
            f.*,
            d.filename,
            (
                SELECT GROUP_CONCAT(fe.event_id)
                FROM finding_events AS fe
                WHERE fe.finding_id = f.id
            ) AS linked_event_ids
        FROM findings AS f
        JOIN datasets AS d ON d.id = f.dataset_id
        ORDER BY f.detection_timestamp DESC, f.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def get_event_distribution(connection, limit=30):
    """Return event counts grouped by calendar day."""
    return connection.execute(
        """
        SELECT substr(event_time, 1, 10) AS day, COUNT(*) AS count
        FROM events
        WHERE event_time IS NOT NULL AND length(event_time) >= 10
        GROUP BY day
        ORDER BY day DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def _event_filters(
    *,
    dataset_id=None,
    identity_key=None,
    event_name=None,
    source_ip=None,
    aws_region=None,
    event_source=None,
    start=None,
    end=None,
    search=None,
):
    clauses = []
    parameters = []

    if dataset_id is not None:
        clauses.append("dataset_id = ?")
        parameters.append(dataset_id)
    if identity_key:
        clauses.append("identity_key = ?")
        parameters.append(identity_key)
    if event_name:
        clauses.append("event_name = ?")
        parameters.append(event_name)
    if source_ip:
        clauses.append("source_ip = ?")
        parameters.append(source_ip)
    if aws_region:
        clauses.append("aws_region = ?")
        parameters.append(aws_region)
    if event_source:
        clauses.append("event_source = ?")
        parameters.append(event_source)
    if start:
        clauses.append("julianday(event_time) >= julianday(?)")
        parameters.append(start)
    if end:
        clauses.append("julianday(event_time) <= julianday(?)")
        parameters.append(end)
    if search:
        pattern = f"%{search}%"
        clauses.append(
            "(event_name LIKE ? OR username LIKE ? OR principal_arn LIKE ? "
            "OR source_ip LIKE ? OR event_id LIKE ?)"
        )
        parameters.extend([pattern] * 5)

    where = " AND ".join(clauses) if clauses else "1 = 1"
    return where, parameters


def list_events(
    connection,
    *,
    dataset_id=None,
    identity_key=None,
    event_name=None,
    source_ip=None,
    aws_region=None,
    event_source=None,
    start=None,
    end=None,
    search=None,
    limit=100,
    offset=0,
):
    """Return events matching the supplied filters, newest first."""
    where, parameters = _event_filters(
        dataset_id=dataset_id,
        identity_key=identity_key,
        event_name=event_name,
        source_ip=source_ip,
        aws_region=aws_region,
        event_source=event_source,
        start=start,
        end=end,
        search=search,
    )
    parameters.extend([limit, offset])
    return connection.execute(
        f"""
        SELECT *
        FROM events
        WHERE {where}
        ORDER BY (julianday(event_time) IS NULL), julianday(event_time) DESC,
                 id DESC
        LIMIT ? OFFSET ?
        """,
        parameters,
    ).fetchall()


def count_events(
    connection,
    *,
    dataset_id=None,
    identity_key=None,
    event_name=None,
    source_ip=None,
    aws_region=None,
    event_source=None,
    start=None,
    end=None,
    search=None,
):
    """Return the number of events matching the supplied filters."""
    where, parameters = _event_filters(
        dataset_id=dataset_id,
        identity_key=identity_key,
        event_name=event_name,
        source_ip=source_ip,
        aws_region=aws_region,
        event_source=event_source,
        start=start,
        end=end,
        search=search,
    )
    return connection.execute(
        f"SELECT COUNT(*) FROM events WHERE {where}", parameters
    ).fetchone()[0]


def get_event(connection, event_id):
    """Return one event row or ``None``."""
    return connection.execute(
        "SELECT * FROM events WHERE id = ?", (event_id,)
    ).fetchone()


def get_events_by_ids(connection, event_ids):
    """Return event rows for internal event IDs in chronological order."""
    if not event_ids:
        return []
    placeholders = ",".join("?" for _ in event_ids)
    return connection.execute(
        f"""
        SELECT *
        FROM events
        WHERE id IN ({placeholders})
        ORDER BY (julianday(event_time) IS NULL), julianday(event_time), id
        """,
        list(event_ids),
    ).fetchall()


def get_filter_options(connection):
    """Return distinct values used by explorer and timeline filter controls."""
    return {
        "datasets": list_datasets(connection),
        "event_names": _distinct_values(connection, "event_name"),
        "source_ips": _distinct_values(connection, "source_ip"),
        "regions": _distinct_values(connection, "aws_region"),
        "event_sources": _distinct_values(connection, "event_source"),
        "categories": _distinct_values(connection, "category", "findings"),
        "rule_ids": _distinct_values(connection, "rule_id", "findings"),
    }


def _distinct_values(connection, column, table="events", limit=200):
    allowed_columns = {
        "event_name",
        "source_ip",
        "aws_region",
        "event_source",
        "category",
        "rule_id",
    }
    if column not in allowed_columns or table not in {"events", "findings"}:
        raise ValueError("Unsupported distinct-value query")
    return connection.execute(
        f"""
        SELECT DISTINCT {column} AS value
        FROM {table}
        WHERE {column} IS NOT NULL AND TRIM({column}) <> ''
        ORDER BY value
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def list_identities(connection, search=None, limit=100, offset=0):
    """Return aggregated identity rows with a stable identity key."""
    search_clause = ""
    parameters = []
    if search:
        pattern = f"%{search}%"
        search_clause = """
            WHERE (
                identity_key LIKE ?
                OR username LIKE ?
                OR principal_arn LIKE ?
                OR principal_id LIKE ?
            )
        """
        parameters.extend([pattern] * 4)

    parameters.extend([limit, offset])
    return connection.execute(
        f"""
        SELECT
            identity_key,
            MAX(NULLIF(username, '')) AS username,
            MAX(NULLIF(principal_arn, '')) AS principal_arn,
            MAX(NULLIF(principal_id, '')) AS principal_id,
            MAX(NULLIF(identity_type, '')) AS identity_type,
            GROUP_CONCAT(DISTINCT NULLIF(access_key_id, ''))
                AS access_keys,
            GROUP_CONCAT(DISTINCT NULLIF(source_ip, '')) AS source_ips,
            GROUP_CONCAT(DISTINCT NULLIF(aws_region, '')) AS regions,
            GROUP_CONCAT(DISTINCT NULLIF(event_source, '')) AS event_sources,
            COUNT(*) AS event_count,
            (
                SELECT e2.event_time FROM events AS e2
                WHERE e2.identity_key = events.identity_key
                ORDER BY (julianday(e2.event_time) IS NULL),
                         julianday(e2.event_time), e2.id
                LIMIT 1
            ) AS first_seen,
            (
                SELECT e2.event_time FROM events AS e2
                WHERE e2.identity_key = events.identity_key
                ORDER BY (julianday(e2.event_time) IS NULL),
                         julianday(e2.event_time) DESC, e2.id DESC
                LIMIT 1
            ) AS last_seen,
            (
                SELECT COUNT(*)
                FROM findings AS f
                WHERE f.identity_key = events.identity_key
            ) AS finding_count
        FROM events
        {search_clause}
        {"AND" if search_clause else "WHERE"} identity_key IS NOT NULL
        GROUP BY identity_key
        ORDER BY event_count DESC, identity_key ASC
        LIMIT ? OFFSET ?
        """,
        parameters,
    ).fetchall()


def count_identities(connection, search=None):
    """Return the number of unique stored identities."""
    if search:
        pattern = f"%{search}%"
        return connection.execute(
            """
            SELECT COUNT(DISTINCT identity_key)
            FROM events
            WHERE identity_key IS NOT NULL
              AND (
                  identity_key LIKE ?
                  OR username LIKE ?
                  OR principal_arn LIKE ?
                  OR principal_id LIKE ?
              )
            """,
            [pattern] * 4,
        ).fetchone()[0]
    return connection.execute(
        """
        SELECT COUNT(DISTINCT identity_key)
        FROM events
        WHERE identity_key IS NOT NULL
        """
    ).fetchone()[0]


def get_identity_profile(connection, identity_key):
    """Return aggregate profile data for one identity key."""
    return connection.execute(
        """
        SELECT
            identity_key,
            MAX(NULLIF(username, '')) AS username,
            MAX(NULLIF(principal_arn, '')) AS principal_arn,
            MAX(NULLIF(principal_id, '')) AS principal_id,
            MAX(NULLIF(identity_type, '')) AS identity_type,
            GROUP_CONCAT(DISTINCT NULLIF(access_key_id, ''))
                AS access_keys,
            GROUP_CONCAT(DISTINCT NULLIF(source_ip, '')) AS source_ips,
            GROUP_CONCAT(DISTINCT NULLIF(aws_region, '')) AS regions,
            GROUP_CONCAT(DISTINCT NULLIF(event_source, '')) AS event_sources,
            GROUP_CONCAT(DISTINCT NULLIF(event_name, '')) AS event_names,
            COUNT(*) AS event_count,
            MIN(event_time) AS first_seen,
            MAX(event_time) AS last_seen,
            (
                SELECT COUNT(*)
                FROM findings AS f
                WHERE f.identity_key = events.identity_key
            ) AS finding_count
        FROM events
        WHERE identity_key = ?
        GROUP BY identity_key
        """,
        (identity_key,),
    ).fetchone()


def get_identity_event_counts(connection, identity_key):
    """Return event-name counts for one identity."""
    return connection.execute(
        """
        SELECT event_name, COUNT(*) AS count
        FROM events
        WHERE identity_key = ?
        GROUP BY event_name
        ORDER BY count DESC, event_name ASC
        """,
        (identity_key,),
    ).fetchall()


def list_identity_events(
    connection,
    identity_key,
    *,
    event_name=None,
    source_ip=None,
    aws_region=None,
    start=None,
    end=None,
    limit=100,
    offset=0,
):
    """Return activity for one identity."""
    return list_events(
        connection,
        identity_key=identity_key,
        event_name=event_name,
        source_ip=source_ip,
        aws_region=aws_region,
        start=start,
        end=end,
        limit=limit,
        offset=offset,
    )


def count_identity_events(
    connection,
    identity_key,
    *,
    event_name=None,
    source_ip=None,
    aws_region=None,
    start=None,
    end=None,
):
    """Count filtered activity for one identity."""
    return count_events(
        connection,
        identity_key=identity_key,
        event_name=event_name,
        source_ip=source_ip,
        aws_region=aws_region,
        start=start,
        end=end,
    )


def get_identity_findings(connection, identity_key, limit=200):
    """Return findings associated with one identity."""
    return list_findings(
        connection, identity_key=identity_key, limit=limit
    )


def _timeline_filters(
    *,
    dataset_id=None,
    identity_key=None,
    source_ip=None,
    event_name=None,
    event_source=None,
    severity=None,
    category=None,
    start=None,
    end=None,
):
    clauses = []
    parameters = []

    if dataset_id is not None:
        clauses.append("e.dataset_id = ?")
        parameters.append(dataset_id)
    if identity_key:
        clauses.append("e.identity_key = ?")
        parameters.append(identity_key)
    if source_ip:
        clauses.append("e.source_ip = ?")
        parameters.append(source_ip)
    if event_name:
        clauses.append("e.event_name = ?")
        parameters.append(event_name)
    if event_source:
        clauses.append("e.event_source = ?")
        parameters.append(event_source)
    if start:
        clauses.append("julianday(e.event_time) >= julianday(?)")
        parameters.append(start)
    if end:
        clauses.append("julianday(e.event_time) <= julianday(?)")
        parameters.append(end)
    if severity:
        clauses.append(
            """
            EXISTS (
                SELECT 1 FROM finding_events AS fe
                JOIN findings AS f ON f.id = fe.finding_id
                WHERE fe.event_id = e.id AND f.severity = ?
            )
            """
        )
        parameters.append(severity)
    if category:
        clauses.append(
            """
            EXISTS (
                SELECT 1 FROM finding_events AS fe
                JOIN findings AS f ON f.id = fe.finding_id
                WHERE fe.event_id = e.id AND f.category = ?
            )
            """
        )
        parameters.append(category)

    where = " AND ".join(clauses) if clauses else "1 = 1"
    return where, parameters


def list_timeline_events(
    connection,
    *,
    dataset_id=None,
    identity_key=None,
    source_ip=None,
    event_name=None,
    event_source=None,
    severity=None,
    category=None,
    start=None,
    end=None,
    limit=100,
    offset=0,
):
    """Return filtered events in chronological order."""
    where, parameters = _timeline_filters(
        dataset_id=dataset_id,
        identity_key=identity_key,
        source_ip=source_ip,
        event_name=event_name,
        event_source=event_source,
        severity=severity,
        category=category,
        start=start,
        end=end,
    )
    parameters.extend([limit, offset])
    return connection.execute(
        f"""
        SELECT e.*
        FROM events AS e
        WHERE {where}
        ORDER BY (julianday(e.event_time) IS NULL),
                 julianday(e.event_time) ASC, e.id ASC
        LIMIT ? OFFSET ?
        """,
        parameters,
    ).fetchall()


def count_timeline_events(
    connection,
    *,
    dataset_id=None,
    identity_key=None,
    source_ip=None,
    event_name=None,
    event_source=None,
    severity=None,
    category=None,
    start=None,
    end=None,
):
    """Count events matching timeline filters."""
    where, parameters = _timeline_filters(
        dataset_id=dataset_id,
        identity_key=identity_key,
        source_ip=source_ip,
        event_name=event_name,
        event_source=event_source,
        severity=severity,
        category=category,
        start=start,
        end=end,
    )
    return connection.execute(
        f"SELECT COUNT(*) FROM events AS e WHERE {where}", parameters
    ).fetchone()[0]


def get_report_event_metrics(
    connection,
    *,
    dataset_id=None,
    identity_key=None,
    start=None,
    end=None,
):
    """Return exact event totals and UTC-orderable time bounds for a scope."""
    where, parameters = _event_filters(
        dataset_id=dataset_id,
        identity_key=identity_key,
        start=start,
        end=end,
    )
    scoped_parameters = parameters * 3
    return connection.execute(
        f"""
        SELECT
            COUNT(*) AS event_count,
            COUNT(DISTINCT NULLIF(identity_key, '')) AS identity_count,
            COUNT(DISTINCT NULLIF(source_ip, '')) AS source_ip_count,
            (
                SELECT event_time FROM events
                WHERE {where} AND julianday(event_time) IS NOT NULL
                ORDER BY julianday(event_time), id LIMIT 1
            ) AS start,
            (
                SELECT event_time FROM events
                WHERE {where} AND julianday(event_time) IS NOT NULL
                ORDER BY julianday(event_time) DESC, id DESC LIMIT 1
            ) AS end
        FROM events
        WHERE {where}
        """,
        scoped_parameters,
    ).fetchone()


def get_report_severity_counts(
    connection,
    *,
    dataset_id=None,
    identity_key=None,
    start=None,
    end=None,
):
    """Return exact finding counts by severity for a report scope."""
    where, parameters = _finding_filters(
        dataset_id=dataset_id,
        identity_key=identity_key,
        start=start,
        end=end,
    )
    rows = connection.execute(
        f"""
        SELECT f.severity, COUNT(*) AS count
        FROM findings AS f
        WHERE {where}
        GROUP BY f.severity
        """,
        parameters,
    ).fetchall()
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for row in rows:
        counts[row["severity"]] = row["count"]
    return counts


def list_report_events(
    connection,
    *,
    dataset_id=None,
    identity_key=None,
    start=None,
    end=None,
    limit=500,
):
    """Return events for report context and timeline extraction."""
    where, parameters = _event_filters(
        dataset_id=dataset_id,
        identity_key=identity_key,
        start=start,
        end=end,
    )
    parameters.append(limit)
    return connection.execute(
        f"""
        SELECT *
        FROM events
        WHERE {where}
        ORDER BY (julianday(event_time) IS NULL), julianday(event_time), id
        LIMIT ?
        """,
        parameters,
    ).fetchall()
