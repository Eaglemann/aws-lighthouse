import json
from unittest.mock import MagicMock, patch
from urllib.parse import quote

from botocore.exceptions import ClientError

from aws_lighthouse.tools.iam_scan import (
    _check_statements,
    _normalise,
    _parse_inline_doc,
    detect_overpermissive_iam,
)

MOD = "aws_lighthouse.tools.iam_scan"


# ── _normalise ────────────────────────────────────────────────────────────────


def test_normalise_string():
    assert _normalise("s3:*") == ["s3:*"]


def test_normalise_list():
    assert _normalise(["s3:*", "ec2:*"]) == ["s3:*", "ec2:*"]


def test_normalise_other():
    assert _normalise(None) == []
    assert _normalise(42) == []


# ── _check_statements ─────────────────────────────────────────────────────────


def test_statements_full_star_is_high():
    stmts = [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    assert _check_statements(stmts) == "HIGH"


def test_statements_service_star_is_medium():
    stmts = [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
    assert _check_statements(stmts) == "MEDIUM"


def test_statements_deny_ignored():
    stmts = [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
    assert _check_statements(stmts) is None


def test_statements_scoped_resource_ignored():
    stmts = [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::my-bucket"}]
    assert _check_statements(stmts) is None


def test_statements_single_dict_accepted():
    stmt = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    assert _check_statements(stmt) == "HIGH"


def test_statements_empty_is_none():
    assert _check_statements([]) is None


# ── _parse_inline_doc ─────────────────────────────────────────────────────────


def test_parse_inline_doc_already_dict():
    doc = {"Statement": []}
    assert _parse_inline_doc(doc) is doc


def test_parse_inline_doc_url_encoded_string():
    raw = quote(json.dumps({"Statement": []}))
    result = _parse_inline_doc(raw)
    assert result == {"Statement": []}


# ── detect_overpermissive_iam ─────────────────────────────────────────────────


def _make_mock_iam(pages: list[dict]) -> MagicMock:
    """Build a mock IAM client whose get_account_authorization_details paginator
    yields the given list of response pages."""
    mock_iam = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = iter(pages)
    mock_iam.get_paginator.return_value = mock_paginator
    return mock_iam


def _empty_page(**kwargs) -> dict:
    base = {
        "UserDetailList": [],
        "RoleDetailList": [],
        "GroupDetailList": [],
        "Policies": [],
    }
    base.update(kwargs)
    return base


def test_no_principals_returns_empty():
    mock_iam = _make_mock_iam([_empty_page()])
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        assert detect_overpermissive_iam() == []


def test_api_error_returns_empty():
    mock_iam = MagicMock()
    mock_iam.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": ""}},
        "GetAccountAuthorizationDetails",
    )
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        assert detect_overpermissive_iam() == []


def test_user_with_admin_managed_policy_flagged():
    page = _empty_page(
        UserDetailList=[
            {
                "UserName": "admin-user",
                "UserPolicyList": [],
                "AttachedManagedPolicies": [
                    {
                        "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "PolicyName": "AdministratorAccess",
                    }
                ],
            }
        ]
    )
    mock_iam = _make_mock_iam([page])
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["principal_name"] == "admin-user"
    assert findings[0]["policy_name"] == "AdministratorAccess"
    assert findings[0]["policy_type"] == "AWS Managed"


def test_user_with_power_user_is_medium():
    page = _empty_page(
        UserDetailList=[
            {
                "UserName": "power-user",
                "UserPolicyList": [],
                "AttachedManagedPolicies": [
                    {
                        "PolicyArn": "arn:aws:iam::aws:policy/PowerUserAccess",
                        "PolicyName": "PowerUserAccess",
                    }
                ],
            }
        ]
    )
    mock_iam = _make_mock_iam([page])
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_service_linked_role_skipped():
    page = _empty_page(
        RoleDetailList=[
            {
                "RoleName": "AWSServiceRoleForEC2",
                "Path": "/aws-service-role/ec2.amazonaws.com/",
                "RolePolicyList": [],
                "AttachedManagedPolicies": [],
            }
        ]
    )
    mock_iam = _make_mock_iam([page])
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        assert detect_overpermissive_iam() == []


def test_role_with_inline_star_policy_flagged():
    doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    page = _empty_page(
        RoleDetailList=[
            {
                "RoleName": "bad-role",
                "Path": "/",
                "RolePolicyList": [
                    {"PolicyName": "StarPolicy", "PolicyDocument": doc}
                ],
                "AttachedManagedPolicies": [],
            }
        ]
    )
    mock_iam = _make_mock_iam([page])
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["principal_name"] == "bad-role"
    assert findings[0]["policy_type"] == "Inline"


def test_group_with_inline_medium_policy_flagged():
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    page = _empty_page(
        GroupDetailList=[
            {
                "GroupName": "devs",
                "GroupPolicyList": [
                    {"PolicyName": "S3Star", "PolicyDocument": doc}
                ],
                "AttachedManagedPolicies": [],
            }
        ]
    )
    mock_iam = _make_mock_iam([page])
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["principal_name"] == "devs"
    assert findings[0]["principal_type"] == "Group"


def test_customer_managed_policy_via_policy_docs():
    """Policy document comes from Policies[] in the same response page."""
    doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    page = _empty_page(
        UserDetailList=[
            {
                "UserName": "dev",
                "UserPolicyList": [],
                "AttachedManagedPolicies": [
                    {
                        "PolicyArn": "arn:aws:iam::123456789012:policy/BroadPolicy",
                        "PolicyName": "BroadPolicy",
                    }
                ],
            }
        ],
        Policies=[
            {
                "Arn": "arn:aws:iam::123456789012:policy/BroadPolicy",
                "PolicyVersionList": [
                    {"IsDefaultVersion": True, "Document": doc}
                ],
            }
        ],
    )
    mock_iam = _make_mock_iam([page])
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["policy_type"] == "Customer Managed"
    assert findings[0]["policy_name"] == "BroadPolicy"


def test_customer_managed_policy_url_encoded_document():
    """Policy document can be a URL-encoded JSON string."""
    doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    page = _empty_page(
        UserDetailList=[
            {
                "UserName": "dev",
                "UserPolicyList": [],
                "AttachedManagedPolicies": [
                    {
                        "PolicyArn": "arn:aws:iam::123456789012:policy/BroadPolicy",
                        "PolicyName": "BroadPolicy",
                    }
                ],
            }
        ],
        Policies=[
            {
                "Arn": "arn:aws:iam::123456789012:policy/BroadPolicy",
                "PolicyVersionList": [
                    {
                        "IsDefaultVersion": True,
                        "Document": quote(json.dumps(doc)),
                    }
                ],
            }
        ],
    )
    mock_iam = _make_mock_iam([page])
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_unknown_customer_managed_policy_skipped():
    """Attached policy with no matching document in Policies[] is skipped silently."""
    page = _empty_page(
        UserDetailList=[
            {
                "UserName": "dev",
                "UserPolicyList": [],
                "AttachedManagedPolicies": [
                    {
                        "PolicyArn": "arn:aws:iam::123456789012:policy/Unknown",
                        "PolicyName": "Unknown",
                    }
                ],
            }
        ]
    )
    mock_iam = _make_mock_iam([page])
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        assert detect_overpermissive_iam() == []


def test_findings_sorted_high_before_medium():
    doc_high = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    doc_medium = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    page = _empty_page(
        UserDetailList=[
            {
                "UserName": "beta",
                "UserPolicyList": [
                    {"PolicyName": "MedPolicy", "PolicyDocument": doc_medium}
                ],
                "AttachedManagedPolicies": [],
            },
            {
                "UserName": "alpha",
                "UserPolicyList": [
                    {"PolicyName": "HighPolicy", "PolicyDocument": doc_high}
                ],
                "AttachedManagedPolicies": [],
            },
        ]
    )
    mock_iam = _make_mock_iam([page])
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()
    assert findings[0]["severity"] == "HIGH"
    assert findings[1]["severity"] == "MEDIUM"


def test_multiple_pages_aggregated():
    """Results from multiple paginator pages are combined."""
    page1 = _empty_page(
        UserDetailList=[
            {
                "UserName": "user-a",
                "UserPolicyList": [],
                "AttachedManagedPolicies": [
                    {
                        "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "PolicyName": "AdministratorAccess",
                    }
                ],
            }
        ]
    )
    page2 = _empty_page(
        UserDetailList=[
            {
                "UserName": "user-b",
                "UserPolicyList": [],
                "AttachedManagedPolicies": [
                    {
                        "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "PolicyName": "AdministratorAccess",
                    }
                ],
            }
        ]
    )
    mock_iam = _make_mock_iam([page1, page2])
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()
    assert len(findings) == 2
    names = {f["principal_name"] for f in findings}
    assert names == {"user-a", "user-b"}


def test_uses_single_paginator_call():
    """Verify only one paginator is created (not one per entity type)."""
    mock_iam = _make_mock_iam([_empty_page()])
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        detect_overpermissive_iam()
    mock_iam.get_paginator.assert_called_once_with("get_account_authorization_details")
