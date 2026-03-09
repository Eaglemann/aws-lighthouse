"""Unit tests for aws_lighthouse/tools/sg_blast_radius.py."""

import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import BotoCoreError, ClientError

pytestmark = [pytest.mark.unit]

# Patch target
_PATCH = "aws_lighthouse.tools.sg_blast_radius.get_client"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ec2(enis=None, sg_data=None, igw_data=None):
    """Return a mock EC2 client pre-configured for the given ENI / SG / IGW responses."""
    ec2 = MagicMock()

    # describe_network_interfaces paginator
    paginator = MagicMock()
    page = {"NetworkInterfaces": enis or []}
    paginator.paginate.return_value = [page]
    ec2.get_paginator.return_value = paginator

    # describe_security_groups
    sg_data = sg_data or [
        {"GroupId": "sg-001", "GroupName": "test-sg", "VpcId": "vpc-abc"}
    ]
    ec2.describe_security_groups.return_value = {"SecurityGroups": sg_data}

    # describe_internet_gateways
    igw_data = igw_data or []
    ec2.describe_internet_gateways.return_value = {"InternetGateways": igw_data}

    return ec2


def _make_ct(events=None):
    """Return a mock CloudTrail client that returns the given events."""
    ct = MagicMock()
    ct.lookup_events.return_value = {"Events": events or []}
    return ct


def _client_factory(ec2=None, ct=None):
    """Return a get_client mock that dispatches by service name."""
    ec2 = ec2 or _make_ec2()
    ct = ct or _make_ct()

    def _get(service, region=None):
        if service == "ec2":
            return ec2
        return ct

    return _get


# ---------------------------------------------------------------------------
# _get_attached_resources
# ---------------------------------------------------------------------------


class TestGetAttachedResources:
    def test_ec2_instance_classified_correctly(self):
        from aws_lighthouse.tools.sg_blast_radius import _get_attached_resources

        eni = {
            "NetworkInterfaceId": "eni-001",
            "InterfaceType": "interface",
            "Description": "Primary",
            "Attachment": {"InstanceId": "i-0abc"},
            "Association": {"PublicIp": "1.2.3.4"},
            "PrivateIpAddress": "10.0.0.1",
        }
        ec2 = _make_ec2(enis=[eni])
        resources = _get_attached_resources(ec2, "sg-001")

        assert len(resources) == 1
        r = resources[0]
        assert r["resource_type"] == "EC2"
        assert r["resource_id"] == "i-0abc"
        assert r["public_ip"] == "1.2.3.4"
        assert r["private_ip"] == "10.0.0.1"

    def test_lambda_eni_classified_correctly(self):
        from aws_lighthouse.tools.sg_blast_radius import _get_attached_resources

        eni = {
            "NetworkInterfaceId": "eni-002",
            "InterfaceType": "lambda_function",
            "Description": "Lambda function",
            "Attachment": {},
            "Association": {},
            "PrivateIpAddress": "10.0.0.2",
        }
        ec2 = _make_ec2(enis=[eni])
        resources = _get_attached_resources(ec2, "sg-001")

        assert len(resources) == 1
        assert resources[0]["resource_type"] == "Lambda"
        assert resources[0]["resource_id"] == "eni-002"
        assert resources[0]["public_ip"] is None

    def test_rds_eni_classified_correctly(self):
        from aws_lighthouse.tools.sg_blast_radius import _get_attached_resources

        eni = {
            "NetworkInterfaceId": "eni-003",
            "InterfaceType": "interface",
            "Description": "RDSNetworkInterface",
            "Attachment": {},
            "Association": {},
            "PrivateIpAddress": "10.0.0.3",
        }
        ec2 = _make_ec2(enis=[eni])
        resources = _get_attached_resources(ec2, "sg-001")

        assert len(resources) == 1
        assert resources[0]["resource_type"] == "RDS"

    def test_other_eni_no_instance_no_lambda_no_rds(self):
        from aws_lighthouse.tools.sg_blast_radius import _get_attached_resources

        eni = {
            "NetworkInterfaceId": "eni-004",
            "InterfaceType": "interface",
            "Description": "ELB listener",
            "Attachment": {},
            "Association": {},
            "PrivateIpAddress": "10.0.0.4",
        }
        ec2 = _make_ec2(enis=[eni])
        resources = _get_attached_resources(ec2, "sg-001")

        assert len(resources) == 1
        assert resources[0]["resource_type"] == "Other"
        assert resources[0]["resource_id"] == "eni-004"

    def test_deduplicates_by_resource_id(self):
        from aws_lighthouse.tools.sg_blast_radius import _get_attached_resources

        eni_a = {
            "NetworkInterfaceId": "eni-001",
            "InterfaceType": "interface",
            "Description": "",
            "Attachment": {"InstanceId": "i-same"},
            "Association": {},
            "PrivateIpAddress": "10.0.0.1",
        }
        eni_b = {
            "NetworkInterfaceId": "eni-002",
            "InterfaceType": "interface",
            "Description": "",
            "Attachment": {"InstanceId": "i-same"},
            "Association": {},
            "PrivateIpAddress": "10.0.0.2",
        }
        ec2 = _make_ec2(enis=[eni_a, eni_b])
        resources = _get_attached_resources(ec2, "sg-001")

        # Both ENIs map to the same instance — only the first should be kept
        assert len(resources) == 1
        assert resources[0]["resource_id"] == "i-same"

    def test_api_error_returns_empty_list(self):
        from aws_lighthouse.tools.sg_blast_radius import _get_attached_resources

        ec2 = MagicMock()
        ec2.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "DescribeNetworkInterfaces",
        )
        resources = _get_attached_resources(ec2, "sg-001")
        assert resources == []


# ---------------------------------------------------------------------------
# _check_igw
# ---------------------------------------------------------------------------


class TestCheckIgw:
    def test_igw_present_returns_true(self):
        from aws_lighthouse.tools.sg_blast_radius import _check_igw

        ec2 = _make_ec2(igw_data=[{"InternetGatewayId": "igw-001"}])
        assert _check_igw(ec2, "vpc-abc") is True

    def test_igw_absent_returns_false(self):
        from aws_lighthouse.tools.sg_blast_radius import _check_igw

        ec2 = _make_ec2(igw_data=[])
        assert _check_igw(ec2, "vpc-abc") is False

    def test_api_error_returns_false(self):
        from aws_lighthouse.tools.sg_blast_radius import _check_igw

        ec2 = MagicMock()
        ec2.describe_internet_gateways.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "DescribeInternetGateways",
        )
        assert _check_igw(ec2, "vpc-abc") is False

    def test_botocore_error_returns_false(self):
        from aws_lighthouse.tools.sg_blast_radius import _check_igw

        ec2 = MagicMock()
        ec2.describe_internet_gateways.side_effect = BotoCoreError()
        assert _check_igw(ec2, "vpc-abc") is False


# ---------------------------------------------------------------------------
# Exposure verdict logic (via get_sg_blast_radius)
# ---------------------------------------------------------------------------


class TestExposureVerdict:
    def _run(self, has_public_ip: bool, has_igw: bool) -> str:
        """Helper: build a minimal blast-radius call and extract the exposure field."""
        from aws_lighthouse.tools.sg_blast_radius import get_sg_blast_radius

        eni_association = {"PublicIp": "1.2.3.4"} if has_public_ip else {}
        eni = {
            "NetworkInterfaceId": "eni-001",
            "InterfaceType": "interface",
            "Description": "test",
            "Attachment": {"InstanceId": "i-001"},
            "Association": eni_association,
            "PrivateIpAddress": "10.0.0.1",
        }
        igw_data = [{"InternetGatewayId": "igw-1"}] if has_igw else []
        ec2 = _make_ec2(enis=[eni], igw_data=igw_data)
        ct = _make_ct()

        with patch(_PATCH, side_effect=_client_factory(ec2=ec2, ct=ct)):
            result = get_sg_blast_radius(["sg-001"])

        assert result["ok"] is True
        return result["data"][0]["exposure"]

    def test_internet_exposed_when_public_ip_and_igw(self):
        assert self._run(has_public_ip=True, has_igw=True) == "INTERNET_EXPOSED"

    def test_private_when_no_public_ip(self):
        assert self._run(has_public_ip=False, has_igw=True) == "PRIVATE"

    def test_unknown_when_public_ip_but_no_igw(self):
        assert self._run(has_public_ip=True, has_igw=False) == "UNKNOWN"


# ---------------------------------------------------------------------------
# get_sg_blast_radius
# ---------------------------------------------------------------------------


class TestGetSgBlastRadius:
    def test_empty_sg_list_returns_ok_empty_data(self):
        from aws_lighthouse.tools.sg_blast_radius import get_sg_blast_radius

        result = get_sg_blast_radius([])
        assert result["ok"] is True
        assert result["data"] == []
        assert result["errors"] == []

    def test_api_error_on_client_init_returns_error_result(self):
        from aws_lighthouse.tools.sg_blast_radius import get_sg_blast_radius

        with patch(
            _PATCH,
            side_effect=ClientError(
                {"Error": {"Code": "InvalidClientTokenId", "Message": "bad"}},
                "CreateClient",
            ),
        ):
            result = get_sg_blast_radius(["sg-001"])

        assert result["ok"] is False
        assert result["data"] == []
        assert len(result["errors"]) == 1

    def test_deduplicates_duplicate_sg_ids(self):
        from aws_lighthouse.tools.sg_blast_radius import get_sg_blast_radius

        ec2 = _make_ec2(
            enis=[],
            sg_data=[{"GroupId": "sg-001", "GroupName": "test-sg", "VpcId": "vpc-abc"}],
        )
        ct = _make_ct()

        with patch(_PATCH, side_effect=_client_factory(ec2=ec2, ct=ct)):
            result = get_sg_blast_radius(["sg-001", "sg-001", "sg-001"])

        assert result["ok"] is True
        # Only one result despite three identical IDs
        assert len(result["data"]) == 1
        assert result["data"][0]["sg_id"] == "sg-001"

    def test_cloudtrail_returns_count_and_ips(self):
        from aws_lighthouse.tools.sg_blast_radius import get_sg_blast_radius

        ec2 = _make_ec2(enis=[])

        ct_event_json = json.dumps(
            {
                "sourceIPAddress": "203.0.113.45",
                "requestParameters": {"groupId": "sg-001"},
            }
        )
        ct_events = [
            {
                "EventName": "AuthorizeSecurityGroupIngress",
                "CloudTrailEvent": ct_event_json,
            },
        ]
        # The CloudTrail helper iterates two event names
        # (AuthorizeSecurityGroupIngress, RevokeSecurityGroupIngress).
        # Each lookup_events call returns one matching event → 2 total.
        ct = _make_ct(events=ct_events)

        with patch(_PATCH, side_effect=_client_factory(ec2=ec2, ct=ct)):
            result = get_sg_blast_radius(["sg-001"])

        assert result["ok"] is True
        br = result["data"][0]
        # 2 event_names × 1 event each = 2
        assert br["recent_connection_count"] == 2
        assert "203.0.113.45" in br["top_source_ips"]

    def test_no_sg_findings_returns_empty(self):
        from aws_lighthouse.tools.sg_blast_radius import get_sg_blast_radius

        result = get_sg_blast_radius([])
        assert result["data"] == []

    def test_result_has_all_required_fields(self):
        from aws_lighthouse.tools.sg_blast_radius import get_sg_blast_radius

        ec2 = _make_ec2(enis=[])
        ct = _make_ct()

        with patch(_PATCH, side_effect=_client_factory(ec2=ec2, ct=ct)):
            result = get_sg_blast_radius(["sg-001"])

        assert result["ok"] is True
        br = result["data"][0]
        for key in (
            "sg_id",
            "sg_name",
            "region",
            "attached_resources",
            "has_public_ip",
            "has_igw",
            "exposure",
            "recent_connection_count",
            "top_source_ips",
        ):
            assert key in br, f"Missing key: {key}"

    def test_sg_name_populated_from_describe_security_groups(self):
        from aws_lighthouse.tools.sg_blast_radius import get_sg_blast_radius

        ec2 = _make_ec2(
            enis=[],
            sg_data=[
                {"GroupId": "sg-001", "GroupName": "my-web-sg", "VpcId": "vpc-abc"}
            ],
        )
        ct = _make_ct()

        with patch(_PATCH, side_effect=_client_factory(ec2=ec2, ct=ct)):
            result = get_sg_blast_radius(["sg-001"])

        assert result["data"][0]["sg_name"] == "my-web-sg"

    def test_multiple_sgs_all_analysed(self):
        from aws_lighthouse.tools.sg_blast_radius import get_sg_blast_radius

        def _sg_data_for(sg_id):
            return [{"GroupId": sg_id, "GroupName": sg_id, "VpcId": "vpc-abc"}]

        ec2 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"NetworkInterfaces": []}]
        ec2.get_paginator.return_value = paginator
        ec2.describe_security_groups.side_effect = lambda GroupIds: {
            "SecurityGroups": _sg_data_for(GroupIds[0])
        }
        ec2.describe_internet_gateways.return_value = {"InternetGateways": []}
        ct = _make_ct()

        with patch(_PATCH, side_effect=_client_factory(ec2=ec2, ct=ct)):
            result = get_sg_blast_radius(["sg-001", "sg-002"])

        assert result["ok"] is True
        sg_ids = {r["sg_id"] for r in result["data"]}
        assert sg_ids == {"sg-001", "sg-002"}
