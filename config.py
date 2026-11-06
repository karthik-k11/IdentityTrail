import os
import secrets


class Config:
    SECRET_KEY = os.environ.get(
        "IDENTITYTRAIL_SECRET_KEY",
        secrets.token_hex(32),
    )

    MAX_CONTENT_LENGTH = int(
        os.environ.get("IDENTITYTRAIL_MAX_UPLOAD_BYTES", str(10 * 1024 * 1024))
    )

    MAX_EVENT_COUNT = int(
        os.environ.get("IDENTITYTRAIL_MAX_EVENT_COUNT", "10000")
    )

    # Configurable detection thresholds. These are counts and windows, not
    # claims that an activity is malicious.
    DETECTION_CONSOLE_FAILURE_THRESHOLD = int(
        os.environ.get("IDENTITYTRAIL_CONSOLE_FAILURE_THRESHOLD", "3")
    )
    DETECTION_CONSOLE_FAILURE_WINDOW_MINUTES = int(
        os.environ.get("IDENTITYTRAIL_CONSOLE_FAILURE_WINDOW_MINUTES", "15")
    )
    DETECTION_FAILURE_SUCCESS_WINDOW_MINUTES = int(
        os.environ.get("IDENTITYTRAIL_FAILURE_SUCCESS_WINDOW_MINUTES", "30")
    )
    DETECTION_ACCESS_KEY_ACTIVITY_WINDOW_HOURS = int(
        os.environ.get("IDENTITYTRAIL_ACCESS_KEY_ACTIVITY_WINDOW_HOURS", "24")
    )
    DETECTION_TIMELINE_GAP_MINUTES = int(
        os.environ.get("IDENTITYTRAIL_TIMELINE_GAP_MINUTES", "60")
    )

    PAGE_SIZE = int(os.environ.get("IDENTITYTRAIL_PAGE_SIZE", "50"))
    REPORT_EVENT_LIMIT = int(
        os.environ.get("IDENTITYTRAIL_REPORT_EVENT_LIMIT", "500")
    )

    DATABASE_PATH = os.environ.get(
        "IDENTITYTRAIL_DATABASE_PATH",
        os.path.join(
            os.path.dirname(__file__),
            "instance",
            "identitytrail.db",
        ),
    )