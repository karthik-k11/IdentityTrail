"""Detection rule registry.

Rules are intentionally separated from Flask routes and CloudTrail parsing.
Each module evaluates the same :class:`RuleContext` and returns findings with
evidence references.
"""

from rules.authentication import evaluate as evaluate_authentication
from rules.access_keys import evaluate as evaluate_access_keys
from rules.privilege import evaluate as evaluate_privilege
from rules.security_config import evaluate as evaluate_security_config
from rules.sensitive_admin import evaluate as evaluate_sensitive_admin

RULE_EVALUATORS = (
    evaluate_authentication,
    evaluate_access_keys,
    evaluate_privilege,
    evaluate_security_config,
    evaluate_sensitive_admin,
)

RULE_CATALOG = (
    {
        "category": "Authentication Activity",
        "rules": (
            "auth.repeated_console_login_failures",
            "auth.console_login_failure_then_success",
            "auth.authentication_error",
        ),
    },
    {
        "category": "Access Key Activity",
        "rules": (
            "access_key.createaccesskey",
            "access_key.deleteaccesskey",
            "access_key.updateaccesskey",
            "access_key.use_after_creation",
        ),
    },
    {
        "category": "Privilege & Permission Changes",
        "rules": (
            "privilege.policy_change",
            "privilege.policy_version_change",
            "privilege.trust_policy_change",
            "privilege.group_membership_change",
        ),
    },
    {
        "category": "Security & Logging Configuration",
        "rules": (
            "logging.trail_disabled_or_deleted",
            "logging.trail_configuration_change",
        ),
    },
    {
        "category": "Sensitive Administrative Activity",
        "rules": (
            "sensitive.resource_deletion",
            "sensitive.high_impact_admin",
            "sensitive.secrets_access",
        ),
    },
)


def evaluate_all(context):
    """Run every registered rule and return the combined findings."""
    findings = []
    for evaluator in RULE_EVALUATORS:
        findings.extend(evaluator(context))
    return findings
