"""Shared event-name sets used by detection rules."""

AUTH_ERROR_EVENTS = frozenset({
    "AssumeRole",
    "AssumeRoleWithSAML",
    "AssumeRoleWithWebIdentity",
    "GetFederationToken",
    "GetSessionToken",
    "GetCallerIdentity",
})

ACCESS_KEY_EVENT_SEVERITY = {
    "CreateAccessKey": "medium",
    "DeleteAccessKey": "high",
    "UpdateAccessKey": "medium",
}

PRIVILEGE_POLICY_EVENTS = frozenset({
    "AttachUserPolicy",
    "DetachUserPolicy",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "AttachGroupPolicy",
    "DetachGroupPolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
    "DeleteUserPolicy",
    "DeleteRolePolicy",
    "DeleteGroupPolicy",
})

POLICY_VERSION_EVENTS = frozenset({
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "DeletePolicyVersion",
})

TRUST_POLICY_EVENTS = frozenset({"UpdateAssumeRolePolicy"})

GROUP_MEMBERSHIP_EVENTS = frozenset({
    "AddUserToGroup",
    "RemoveUserFromGroup",
})

LOGGING_CRITICAL_EVENTS = frozenset({
    "StopLogging",
    "DeleteTrail",
})

LOGGING_CONFIG_EVENTS = frozenset({
    "UpdateTrail",
    "PutEventSelectors",
    "DeleteEventDataStore",
    "StopEventDataStore",
})

SENSITIVE_DELETION_EVENTS = frozenset({
    "DeleteUser",
    "DeleteRole",
    "DeletePolicy",
    "DeleteGroup",
    "DeleteBucket",
    "DeleteDBInstance",
    "DeleteDBCluster",
    "DeleteDBSubnetGroup",
    "DeleteTable",
    "DeleteFunction",
    "DeleteAlias",
    "DeleteKey",
    "DeleteSecret",
    "DeleteSecurityGroup",
    "DeleteNetworkAcl",
    "DeleteSubnet",
    "DeleteVpc",
    "DeleteFlowLogs",
    "DeleteLogGroup",
    "DeleteRule",
    "DeleteWebACL",
    "DeleteHostedZone",
})

HIGH_IMPACT_ADMIN_EVENTS = frozenset({
    "CreateUser",
    "CreateRole",
    "CreatePolicy",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "DeactivateMFADevice",
    "DeleteVirtualMFADevice",
    "PutBucketPolicy",
    "PutBucketAcl",
    "PutKeyPolicy",
    "ScheduleKeyDeletion",
    "DisableKey",
    "CreateGrant",
    "CreateSAMLProvider",
    "UpdateSAMLProvider",
    "CreateOpenIDConnectProvider",
    "UpdateOpenIDConnectProviderThumbprint",
})

SECRETS_ACCESS_EVENTS = frozenset({
    "GetSecretValue",
    "BatchGetSecretValue",
    "GetParameter",
    "GetParameters",
    "GetParameterHistory",
    "Decrypt",
})

SENSITIVE_FOLLOW_ON_EVENTS = frozenset().union(
    ACCESS_KEY_EVENT_SEVERITY.keys(),
    PRIVILEGE_POLICY_EVENTS,
    POLICY_VERSION_EVENTS,
    TRUST_POLICY_EVENTS,
    GROUP_MEMBERSHIP_EVENTS,
    LOGGING_CRITICAL_EVENTS,
    LOGGING_CONFIG_EVENTS,
    SENSITIVE_DELETION_EVENTS,
    HIGH_IMPACT_ADMIN_EVENTS,
)
