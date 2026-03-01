from unittest.mock import MagicMock, patch
from urllib.parse import quote

from botocore.exceptions import ClientError

from aws_lighthouse.tools.iam_scan import (
    _check_statements,
    _get_managed_policy_doc,
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
    import json

    raw = quote(json.dumps({"Statement": []}))
    result = _parse_inline_doc(raw)
    assert result == {"Statement": []}


# ── _get_managed_policy_doc ───────────────────────────────────────────────────


def test_get_managed_policy_doc_cached():
    iam = MagicMock()
    cache = {"arn:aws:iam::123:policy/MyPolicy": {"Statement": []}}
    doc = _get_managed_policy_doc(iam, "arn:aws:iam::123:policy/MyPolicy", cache)
    assert doc == {"Statement": []}
    iam.get_policy.assert_not_called()


def test_get_managed_policy_doc_fetches_and_caches():
    iam = MagicMock()
    iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Statement": [{"Effect": "Allow"}]}}
    }
    cache = {}
    doc = _get_managed_policy_doc(iam, "arn:aws:iam::123:policy/New", cache)
    assert doc == {"Statement": [{"Effect": "Allow"}]}
    assert "arn:aws:iam::123:policy/New" in cache


def test_get_managed_policy_doc_api_error_returns_none():
    iam = MagicMock()
    iam.get_policy.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": ""}}, "GetPolicy"
    )
    cache = {}
    doc = _get_managed_policy_doc(iam, "arn:aws:iam::123:policy/Bad", cache)
    assert doc is None
    assert cache["arn:aws:iam::123:policy/Bad"] is None


# ── detect_overpermissive_iam ─────────────────────────────────────────────────


def _make_paginator(items):
    pg = MagicMock()
    pg.paginate.return_value.search.return_value = iter(items)
    return pg


def _build_mock_iam(users=None, roles=None, groups=None):
    """Build a mock IAM client with no inline policies and empty attached policies."""
    mock_iam = MagicMock()

    users = users or []
    roles = roles or []
    groups = groups or []

    def paginator(name):
        if name == "list_users":
            return _make_paginator(users)
        if name == "list_roles":
            return _make_paginator(roles)
        if name == "list_groups":
            return _make_paginator(groups)
        return _make_paginator([])

    mock_iam.get_paginator.side_effect = paginator
    mock_iam.list_user_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
    mock_iam.list_group_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_group_policies.return_value = {"AttachedPolicies": []}
    return mock_iam


def test_no_principals_returns_empty():
    mock_iam = _build_mock_iam()
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()
    assert findings == []


def test_user_with_admin_managed_policy_flagged():
    mock_iam = _build_mock_iam(users=[{"UserName": "admin-user"}])
    mock_iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [
            {
                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "PolicyName": "AdministratorAccess",
            }
        ]
    }
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["principal_name"] == "admin-user"
    assert findings[0]["policy_name"] == "AdministratorAccess"


def test_user_with_power_user_is_medium():
    mock_iam = _build_mock_iam(users=[{"UserName": "power-user"}])
    mock_iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [
            {
                "PolicyArn": "arn:aws:iam::aws:policy/PowerUserAccess",
                "PolicyName": "PowerUserAccess",
            }
        ]
    }
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_service_linked_role_skipped():
    role = {
        "RoleName": "AWSServiceRoleForEC2",
        "Path": "/aws-service-role/ec2.amazonaws.com/",
    }
    mock_iam = _build_mock_iam(roles=[role])
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()
    assert findings == []


def test_role_with_inline_star_policy_flagged():
    role = {"RoleName": "bad-role", "Path": "/"}
    mock_iam = _build_mock_iam(roles=[role])
    mock_iam.list_role_policies.return_value = {"PolicyNames": ["StarPolicy"]}
    doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    mock_iam.get_role_policy.return_value = {"PolicyDocument": doc}

    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["principal_name"] == "bad-role"


def test_findings_sorted_high_before_medium():
    mock_iam = _build_mock_iam(users=[{"UserName": "beta"}, {"UserName": "alpha"}])

    def attached_policies(UserName):
        if UserName == "beta":
            return {
                "AttachedPolicies": [
                    {
                        "PolicyArn": "arn:aws:iam::aws:policy/PowerUserAccess",
                        "PolicyName": "PowerUserAccess",
                    }
                ]
            }
        return {
            "AttachedPolicies": [
                {
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "PolicyName": "AdministratorAccess",
                }
            ]
        }

    mock_iam.list_attached_user_policies.side_effect = attached_policies

    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = detect_overpermissive_iam()

    assert findings[0]["severity"] == "HIGH"
    assert findings[1]["severity"] == "MEDIUM"
