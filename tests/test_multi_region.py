from unittest.mock import MagicMock, patch

from aws_lighthouse.tools.multi_region import get_enabled_regions

MOD = "aws_lighthouse.tools.multi_region"


def test_returns_sorted_region_names():
    mock_ec2 = MagicMock()
    mock_ec2.describe_regions.return_value = {
        "Regions": [
            {"RegionName": "us-west-2"},
            {"RegionName": "eu-west-1"},
            {"RegionName": "ap-southeast-1"},
        ]
    }
    with patch(f"{MOD}.get_aws_client", return_value=mock_ec2):
        regions = get_enabled_regions()
    assert regions == ["ap-southeast-1", "eu-west-1", "us-west-2"]


def test_passes_correct_opt_in_filter():
    mock_ec2 = MagicMock()
    mock_ec2.describe_regions.return_value = {"Regions": []}
    with patch(f"{MOD}.get_aws_client", return_value=mock_ec2):
        get_enabled_regions()
    call_kwargs = mock_ec2.describe_regions.call_args[1]
    filters = call_kwargs["Filters"]
    assert any(
        f["Name"] == "opt-in-status"
        and "opt-in-not-required" in f["Values"]
        and "opted-in" in f["Values"]
        for f in filters
    )


def test_empty_regions():
    mock_ec2 = MagicMock()
    mock_ec2.describe_regions.return_value = {"Regions": []}
    with patch(f"{MOD}.get_aws_client", return_value=mock_ec2):
        regions = get_enabled_regions()
    assert regions == []


def test_api_error_returns_empty():
    mock_ec2 = MagicMock()
    mock_ec2.describe_regions.side_effect = Exception("denied")
    with patch(f"{MOD}.get_aws_client", return_value=mock_ec2):
        regions = get_enabled_regions()
    assert regions == []
