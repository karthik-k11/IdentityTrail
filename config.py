import os


class Config:
    SECRET_KEY = os.environ.get(
        "IDENTITYTRAIL_SECRET_KEY",
        "identitytrail-local-development-key"
    )

    MAX_CONTENT_LENGTH = 10 * 1024 * 1024

    DATABASE_PATH = os.path.join(
        os.path.dirname(__file__),
        "instance",
        "identitytrail.db"
    )