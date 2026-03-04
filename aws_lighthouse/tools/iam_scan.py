import json
from typing import Any
from urllib.parse import unquote

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger
from ..scan_contract import error_result, scan_error_from_exception
from ..types import IAMFinding

# AWS-managed policies that are inherently over-permissive — checked by name
# rather than downloading their documents to save API calls.
_DANGEROUS_AWS_MANAGED: dict[str, str] = {
    "AdministratorAccess": "HIGH",
    "PowerUserAccess": "MEDIUM",
}


def _normalise(value: Any) -> list[str]:
    """Ensure Action / Resource values are always a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def _check_statements(statements: Any) -> str | None:
    """
    Scan a policy's Statement list for over-permissive Allow rules.
    Returns the highest severity found, or None if the policy is clean.
      HIGH   — Action:* with Resource:*  (full administrator)
      MEDIUM — Action:<service>:* with Resource:*  (service-level wildcard)
    """
    if isinstance(statements, dict):
        statements = [statements]

    highest: str | None = None

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


def _parse_inline_doc(raw_doc: Any) -> Any:
    """Inline policy documents from get_account_authorization_details are URL-encoded JSON strings."""
    if isinstance(raw_doc, str):
        return json.loads(unquote(raw_doc))
    return raw_doc


def detect_overpermissive_iam():
    """
    Scan IAM users, roles, and groups for policies that grant
    Action:* on Resource:* (HIGH) or Action:<svc>:* on Resource:* (MEDIUM).

    Uses a single paginated get_account_authorization_details call instead of
    N+1 per-principal calls, reducing ~640 API calls to a handful of pages.
    """
    iam = get_client("iam")
    findings: list[IAMFinding] = []
    errors = []

    users: list[Any] = []
    roles: list[Any] = []
    groups: list[Any] = []
    policy_docs: dict[str, Any] = {}  # arn -> parsed document

    try:
        paginator = iam.get_paginator("get_account_authorization_details")
        for page in paginator.paginate(
            Filter=["User", "Role", "Group", "LocalManagedPolicy"]
        ):
            users.extend(page.get("UserDetailList", []))
            roles.extend(page.get("RoleDetailList", []))
            groups.extend(page.get("GroupDetailList", []))
            # Build a cache of customer-managed policy documents from the same response
            for policy in page.get("Policies", []):
                arn = policy["Arn"]
                for version in policy.get("PolicyVersionList", []):
                    if version.get("IsDefaultVersion"):
                        raw = version["Document"]
                        if isinstance(raw, str):
                            raw = json.loads(unquote(raw))
                        policy_docs[arn] = raw
                        break
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to fetch account authorization details: {e}")
        return error_result(
            data=[],
            errors=[
                scan_error_from_exception(
                    service="iam",
                    operation="GetAccountAuthorizationDetails",
                    exc=e,
                )
            ],
        )

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

    def _check_inline_list(
        principal_type: str, principal_name: str, policy_list: list[Any]
    ) -> None:
        for p in policy_list:
            try:
                doc = _parse_inline_doc(p["PolicyDocument"])
                severity = _check_statements(doc.get("Statement", []))
                if severity:
                    _add(
                        severity,
                        principal_type,
                        principal_name,
                        "Inline",
                        p["PolicyName"],
                        "Action:* on Resource:*"
                        if severity == "HIGH"
                        else "Action:<svc>:* on Resource:*",
                    )
            except (ValueError, KeyError) as e:
                logger.error(f"Failed to parse inline policy on {principal_name}: {e}")
                errors.append(
                    scan_error_from_exception(
                        service="iam",
                        operation="ParseInlinePolicy",
                        exc=e,
                    )
                )

    def _check_attached_list(
        principal_type: str, principal_name: str, attached: list[Any]
    ) -> None:
        for p in attached:
            arn = p["PolicyArn"]
            name = p["PolicyName"]
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
            doc = policy_docs.get(arn)
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

    for user in users:
        uname = user["UserName"]
        _check_inline_list("User", uname, user.get("UserPolicyList", []))
        _check_attached_list("User", uname, user.get("AttachedManagedPolicies", []))

    for role in roles:
        rname = role["RoleName"]
        if role.get("Path", "").startswith("/aws-service-role/"):
            continue
        _check_inline_list("Role", rname, role.get("RolePolicyList", []))
        _check_attached_list("Role", rname, role.get("AttachedManagedPolicies", []))

    for group in groups:
        gname = group["GroupName"]
        _check_inline_list("Group", gname, group.get("GroupPolicyList", []))
        _check_attached_list("Group", gname, group.get("AttachedManagedPolicies", []))

    findings.sort(
        key=lambda f: (0 if f["severity"] == "HIGH" else 1, f["principal_name"])
    )
    return error_result(data=findings, errors=errors)
