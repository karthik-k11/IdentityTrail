"""Route helpers shared by the IdentityTrail blueprints."""

from __future__ import annotations

import json

from flask import request, url_for


def load_json(value, fallback):
    """Parse a JSON text value, returning the fallback on any problem."""
    if not value:
        return fallback
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return fallback
    if isinstance(parsed, type(fallback)):
        return parsed
    return fallback


def page_url(endpoint, page, **extra):
    """Build a pagination URL while preserving the active filters."""
    arguments = {
        key: value
        for key, value in request.args.items()
        if key != "page"
    }
    arguments.update(extra)
    return url_for(endpoint, page=page, **arguments)


def pagination_context(result, endpoint, **extra):
    """Return template-ready pagination metadata and links."""
    page = int(result.get("page", 1))
    pages = int(result.get("pages", 1))
    return {
        "pagination": {
            "page": page,
            "pages": pages,
            "per_page": result.get("per_page"),
            "total": result.get("total", 0),
        },
        "prev_url": (
            page_url(endpoint, page - 1, **extra) if page > 1 else None
        ),
        "next_url": (
            page_url(endpoint, page + 1, **extra) if page < pages else None
        ),
    }


def severity_class(severity):
    """Return a CSS-safe severity class name."""
    value = str(severity or "").lower()
    if value in {"critical", "high", "medium", "low"}:
        return value
    return "unknown"


def format_json(value):
    """Pretty-print a Python value for a read-only evidence block."""
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)
