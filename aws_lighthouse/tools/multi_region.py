from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger
from ..scan_contract import error_result, ok_result, scan_error_from_exception
from ..types import ScanResult


def get_enabled_regions() -> ScanResult:
    """Return all AWS regions that are enabled (opt-in-not-required or opted-in)."""
    try:
        ec2 = get_client("ec2")
        response = ec2.describe_regions(
            Filters=[
                {
                    "Name": "opt-in-status",
                    "Values": ["opt-in-not-required", "opted-in"],
                }
            ]
        )
        return ok_result(sorted(r["RegionName"] for r in response.get("Regions", [])))
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to list enabled regions: {e}")
        return error_result(
            data=[],
            errors=[
                scan_error_from_exception(
                    service="ec2",
                    operation="DescribeRegions",
                    exc=e,
                )
            ],
        )
