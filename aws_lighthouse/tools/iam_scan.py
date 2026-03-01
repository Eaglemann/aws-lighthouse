import json
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_aws_client
from ..logger import logger
from ..types import IAMFinding

# AWS-managed policies that are inherently over-permissive — checked by name
# rather than downloading their documents to save API calls.
_DANGEROUS_AWS_MANAGED: Dict[str, str] = {
    "AdministratorAccess": "HIGH",
    "PowerUserAccess": "MEDIUM",
}


def _normalise(value: Any) -> List[str]:
    """Ensure Action / Resource values are always a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def _check_statements(statements: Any) -> Optional[str]:
    """
    Scan a policy's Statement list for over-permissive Allow rules.
    Returns the highest severity found, or None if the policy is clean.
      HIGH   — Action:* with Resource:*  (full administrator)
      MEDIUM — Action:<service>:* with Resource:*  (service-level wildcard)
    Statements with a Condition key are still flagged but noted separately
    by the caller if needed.
    """
    if isinstance(statements, dict):
        statements = [statements]

    highest: Optional[str] = None

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        actions = _normalise(stmt.get("Action", []))
        resources = _normalise(stmt.get("Resource", []))

        has_star_resource = "*" in resources
        if not has_star_resource:
            continue

        if "*" in actions:
            return "HIGH"  # can't get worse — short-circuit

        if any(a.endswith(":*") for a in actions):
            highest = "MEDIUM"

    return highest


def _get_managed_policy_doc(
    iam, policy_arn: str, cache: Dict[str, Any]
) -> Optional[Any]:
    """Fetch and cache a managed policy's default-version document."""
    if policy_arn in cache:
        return cache[policy_arn]
    try:
        version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
        raw = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)[
            "PolicyVersion"
        ]["Document"]
        # boto3 returns the document already parsed for managed policies,
        # but URL-encoded in some SDK versions — handle both.
        if isinstance(raw, str):
            raw = json.loads(unquote(raw))
        cache[policy_arn] = raw
        return raw
    except (ClientError, BotoCoreError, ValueError) as e:
        logger.error(f"Failed to fetch policy {policy_arn}: {e}")
        cache[policy_arn] = None
        return None


def _parse_inline_doc(raw_doc: Any) -> Any:
    """Inline policy documents from get_*_policy are URL-encoded JSON strings."""
    if isinstance(raw_doc, str):
        return json.loads(unquote(raw_doc))
    return raw_doc


def detect_overpermissive_iam() -> List[IAMFinding]:
    """
    Scan IAM users, roles, and groups for policies that grant
    Action:* on Resource:* (HIGH) or Action:<svc>:* on Resource:* (MEDIUM).

    Checks both inline policies and attached managed policies.
    Customer-managed policy documents are fetched once and cached.
    AWS-managed policies are evaluated by name only (no document download).
    """
    iam = get_aws_client("iam")
    findings: List[IAMFinding] = []
    policy_cache: Dict[str, Any] = {}

    def _add(
        severity, principal_type, principal_name, policy_type, policy_name, reason
    ):
        findings.append(
            {
                "severity": severity,
                "principal_type": principal_type,
                "principal_name": principal_name,
                "policy_type": policy_type,
                "policy_name": policy_name,
                "reason": reason,
            }
        )

    # ── helpers ──────────────────────────────────────────────────────────────

    def _check_inline(principal_type, principal_name, get_fn, list_fn, list_key):
        try:
            names = list_fn().get(list_key, [])
        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to list inline policies for {principal_name}: {e}")
            return
        for policy_name in names:
            try:
                raw = get_fn(policy_name)
                doc = _parse_inline_doc(raw)
                severity = _check_statements(doc.get("Statement", []))
                if severity:
                    _add(
                        severity,
                        principal_type,
                        principal_name,
                        "Inline",
                        policy_name,
                        "Action:* on Resource:*"
                        if severity == "HIGH"
                        else "Action:<svc>:* on Resource:*",
                    )
            except (ClientError, BotoCoreError, ValueError) as e:
                logger.error(
                    f"Failed to read inline policy {policy_name} on {principal_name}: {e}"
                )

    def _check_attached(principal_type, principal_name, list_fn):
        try:
            policies = list_fn().get("AttachedPolicies", [])
        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to list attached policies for {principal_name}: {e}")
            return
        for p in policies:
            arn = p["PolicyArn"]
            name = p["PolicyName"]
            # AWS-managed: check by name only
            if arn.startswith("arn:aws:iam::aws:policy/"):
                sev = _DANGEROUS_AWS_MANAGED.get(name)
                if sev:
                    _add(
                        sev,
                        principal_type,
                        principal_name,
                        "AWS Managed",
                        name,
                        f"Known over-permissive AWS policy: {name}",
                    )
                continue
            # Customer-managed: fetch and parse document
            doc = _get_managed_policy_doc(iam, arn, policy_cache)
            if doc is None:
                continue
            severity = _check_statements(doc.get("Statement", []))
            if severity:
                _add(
                    severity,
                    principal_type,
                    principal_name,
                    "Customer Managed",
                    name,
                    "Action:* on Resource:*"
                    if severity == "HIGH"
                    else "Action:<svc>:* on Resource:*",
                )

    # ── Users ─────────────────────────────────────────────────────────────────
    try:
        for user in iam.get_paginator("list_users").paginate().search("Users"):
            uname = user["UserName"]
            _check_inline(
                "User",
                uname,
                lambda pn, u=uname: iam.get_user_policy(UserName=u, PolicyName=pn)[
                    "PolicyDocument"
                ],
                lambda u=uname: iam.list_user_policies(UserName=u),
                "PolicyNames",
            )
            _check_attached(
                "User",
                uname,
                lambda u=uname: iam.list_attached_user_policies(UserName=u),
            )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to enumerate IAM users: {e}")

    # ── Roles ─────────────────────────────────────────────────────────────────
    try:
        for role in iam.get_paginator("list_roles").paginate().search("Roles"):
            rname = role["RoleName"]
            # Skip AWS service-linked roles — they are managed by AWS
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            _check_inline(
                "Role",
                rname,
                lambda pn, r=rname: iam.get_role_policy(RoleName=r, PolicyName=pn)[
                    "PolicyDocument"
                ],
                lambda r=rname: iam.list_role_policies(RoleName=r),
                "PolicyNames",
            )
            _check_attached(
                "Role",
                rname,
                lambda r=rname: iam.list_attached_role_policies(RoleName=r),
            )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to enumerate IAM roles: {e}")

    # ── Groups ────────────────────────────────────────────────────────────────
    try:
        for group in iam.get_paginator("list_groups").paginate().search("Groups"):
            gname = group["GroupName"]
            _check_inline(
                "Group",
                gname,
                lambda pn, g=gname: iam.get_group_policy(GroupName=g, PolicyName=pn)[
                    "PolicyDocument"
                ],
                lambda g=gname: iam.list_group_policies(GroupName=g),
                "PolicyNames",
            )
            _check_attached(
                "Group",
                gname,
                lambda g=gname: iam.list_attached_group_policies(GroupName=g),
            )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to enumerate IAM groups: {e}")

    # Sort: HIGH first, then by principal name
    findings.sort(
        key=lambda f: (0 if f["severity"] == "HIGH" else 1, f["principal_name"])
    )
    return findings
