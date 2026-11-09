"""Identity aggregation and activity views."""

from __future__ import annotations

from collections import Counter

import database
from services.identity_keys import (
    encode_identity_key,
    identity_display_name,
)
from services.redaction import mask_access_key


def split_values(value):
    """Split a GROUP_CONCAT result into a clean list."""
    if not value:
        return []
    return sorted({
        item.strip()
        for item in str(value).split(",")
        if item and item.strip()
    })


def categorize_event(event_name, event_source=None):
    """Return a broad, human-readable category for an event."""
    name = (event_name or "").lower()
    source = (event_source or "").lower()

    if name in {
        "consolelogin",
        "assumerole",
        "assumerolewithsaml",
        "assumerolewithwebidentity",
        "getfederationtoken",
        "getsessiontoken",
        "getcalleridentity",
        "changepassword",
    }:
        return "Authentication"
    if "accesskey" in name:
        return "Access Key Management"
    if name.startswith(("attach", "detach", "put")) and "policy" in name:
        return "IAM & Permissions"
    if name in {
        "createpolicy",
        "createpolicyversion",
        "setdefaultpolicyversion",
        "deletepolicy",
        "deletepolicyversion",
        "createuser",
        "deleteuser",
        "createrole",
        "deleterole",
        "creategroup",
        "deletegroup",
        "addusertogroup",
        "removeuserfromgroup",
        "updateassumerolepolicy",
        "createloginprofile",
        "updateloginprofile",
    }:
        return "IAM & Permissions"
    if any(token in name for token in (
        "trail", "logging", "eventselector", "eventdatastore", "loggroup"
    )):
        return "Logging & Monitoring"
    if "secret" in source or source.startswith("kms.") or source.startswith("ssm."):
        return "Secrets & Keys"
    if source.startswith(("s3.", "ebs.", "efs.", "glacier.")):
        return "Storage"
    if source.startswith(("rds.", "dynamodb.", "redshift.", "elasticache.")):
        return "Database"
    if source.startswith(("ec2.", "ecs.", "eks.", "lambda.", "ecr.")):
        return "Compute"
    return "Other"


def _category_counts(event_counts):
    categories = Counter()
    for row in event_counts:
        categories[categorize_event(row["event_name"])] += row["count"]
    return sorted(
        (
            {"category": category, "count": count}
            for category, count in categories.items()
        ),
        key=lambda item: (-item["count"], item["category"]),
    )


def list_identities(connection, search=None, page=1, per_page=50):
    """Return a paginated identity listing with display-safe metadata."""
    page = max(1, int(page))
    per_page = max(1, min(int(per_page), 200))
    offset = (page - 1) * per_page

    total = database.count_identities(connection, search=search)
    rows = database.list_identities(
        connection, search=search, limit=per_page, offset=offset
    )

    items = []
    for row in rows:
        item = dict(row)
        item["display_name"] = identity_display_name(
            item.get("username"),
            item.get("principal_arn"),
            item.get("principal_id"),
        )
        item["access_keys_list"] = [
            mask_access_key(value)
            for value in split_values(item.get("access_keys"))
        ]
        item["source_ip_list"] = split_values(item.get("source_ips"))
        item["region_list"] = split_values(item.get("regions"))
        item["event_source_list"] = split_values(item.get("event_sources"))
        item["encoded_key"] = encode_identity_key(item["identity_key"])
        items.append(item)

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    }


def get_identity_detail(connection, identity_key, finding_limit=200):
    """Return an aggregated identity profile and related findings."""
    row = database.get_identity_profile(connection, identity_key)
    if row is None:
        return None

    profile = dict(row)
    profile["display_name"] = identity_display_name(
        profile.get("username"),
        profile.get("principal_arn"),
        profile.get("principal_id"),
    )
    profile["access_keys_list"] = [
        mask_access_key(value)
        for value in split_values(profile.get("access_keys"))
    ]
    profile["source_ip_list"] = split_values(profile.get("source_ips"))
    profile["region_list"] = split_values(profile.get("regions"))
    profile["event_source_list"] = split_values(profile.get("event_sources"))
    profile["event_name_list"] = split_values(profile.get("event_names"))
    profile["encoded_key"] = encode_identity_key(identity_key)

    event_counts = database.get_identity_event_counts(
        connection, identity_key
    )
    profile["categories"] = _category_counts(event_counts)
    profile["findings"] = [
        dict(finding)
        for finding in database.get_identity_findings(
            connection, identity_key, limit=finding_limit
        )
    ]
    return profile


def get_identity_activity(
    connection,
    identity_key,
    *,
    event_name=None,
    source_ip=None,
    aws_region=None,
    start=None,
    end=None,
    page=1,
    per_page=50,
):
    """Return paginated activity for one identity."""
    page = max(1, int(page))
    per_page = max(1, min(int(per_page), 200))
    offset = (page - 1) * per_page

    total = database.count_identity_events(
        connection,
        identity_key,
        event_name=event_name,
        source_ip=source_ip,
        aws_region=aws_region,
        start=start,
        end=end,
    )
    rows = database.list_identity_events(
        connection,
        identity_key,
        event_name=event_name,
        source_ip=source_ip,
        aws_region=aws_region,
        start=start,
        end=end,
        limit=per_page,
        offset=offset,
    )

    events = []
    for row in rows:
        item = dict(row)
        item["category"] = categorize_event(
            item.get("event_name"), item.get("event_source")
        )
        item["access_key_masked"] = mask_access_key(
            item.get("access_key_id")
        )
        events.append(item)

    return {
        "items": events,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    }
